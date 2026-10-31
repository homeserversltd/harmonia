//! Harmonia's keyed application state. No receipt or envelope is stored here.
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

pub(crate) const DATABASE: &str = "/var/lib/harmonia/harmonia.sqlite3";
const ENTRY: &str = "harmonia.ledger.entry.v1";
const PAGE: &str = "caduceus.receipts.ledger.v1";
const PROPOSAL_IDENTITY_MIGRATION: &str = "proposal-product-identity-v1";
const PROPOSAL_DOCUMENT_MIGRATION: &str = "proposal-documents-v1";
const PROPOSAL_FEED: &str = "harmonia";
const PROPOSALS_TABLE: &str = "CREATE TABLE IF NOT EXISTS proposals (
    feed_id TEXT NOT NULL, id TEXT NOT NULL, module_id TEXT NOT NULL,
    kind TEXT NOT NULL, target_path TEXT, reference_source_path TEXT,
    live_sha TEXT, reference_sha TEXT, silenced INTEGER NOT NULL,
    has_run INTEGER NOT NULL, PRIMARY KEY(feed_id,id));";
const CONFIG_PROPOSALS_TABLE: &str = "CREATE TABLE IF NOT EXISTS proposal_config (
    feed_id TEXT NOT NULL, id TEXT NOT NULL, config_state TEXT NOT NULL,
    source BLOB NOT NULL, PRIMARY KEY(feed_id,id));";

pub(crate) struct ConfigProposal {
    pub(crate) id: String,
    pub(crate) state: Value,
    pub(crate) source: Vec<u8>,
}

fn database_error(error: rusqlite::Error) -> String {
    format!("harmonia-state-database-failed: {error}")
}

pub(crate) fn database_path() -> PathBuf {
    std::env::var_os("HARMONIA_STATE_DATABASE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DATABASE))
}

pub(crate) fn reader() -> Result<Option<Connection>, String> {
    let database = database_path();
    match std::fs::symlink_metadata(&database) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("harmonia-state-observe-failed: {error}")),
        Ok(metadata) if !metadata.file_type().is_file() => return Err("harmonia-state-not-regular".into()),
        Ok(_) => {}
    }
    let connection = Connection::open_with_flags(
        &database, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ).map_err(database_error)?;
    connection.busy_timeout(Duration::from_secs(5)).map_err(database_error)?;
    // An incomplete store is absence, not a failed convergence run.
    for query in [
        "SELECT ledger_sequence,run_id,module_id,profile_id,module_version,ok,changed,operation_count,first_missing_signal,recorded_at,receipt_ref,profile_identity,step,error FROM ledger LIMIT 0",
        "SELECT feed_id,id,module_id,kind,target_path,reference_source_path,live_sha,reference_sha,silenced,has_run FROM proposals LIMIT 0",
        "SELECT id FROM migrations LIMIT 0", "SELECT id,count FROM deed_outbox LIMIT 0",
    ] {
        if connection.prepare(query).is_err() { return Ok(None); }
    }
    Ok(Some(connection))
}

fn public_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "harmonia-state-mode-observe-failed")?;
    if metadata.file_type().is_symlink() { return Err("harmonia-state-symlink-refused".into()); }
    if metadata.permissions().mode() & 0o7777 != mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|_| "harmonia-state-public-mode-failed")?;
    }
    Ok(())
}

pub(crate) fn writer() -> Result<Connection, String> {
    let database = database_path();
    let parent = database.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| format!("harmonia-state-parent-failed: {error}"))?;
    public_mode(parent, 0o755)?;
    match std::fs::symlink_metadata(&database) {
        Ok(metadata) if !metadata.file_type().is_file() => return Err("harmonia-state-not-regular".into()),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(format!("harmonia-state-observe-failed: {error}")),
        _ => {}
    }
    let mut connection = Connection::open(&database).map_err(database_error)?;
    connection.pragma_update(None, "secure_delete", "ON").map_err(database_error)?;
    public_mode(&database, 0o644)?;
    connection.busy_timeout(Duration::from_secs(5)).map_err(database_error)?;
    // The entire schema becomes visible in one transaction.
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(database_error)?;
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS ledger (
            ledger_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL, module_id TEXT NOT NULL, profile_id TEXT,
            module_version TEXT, ok INTEGER, changed INTEGER, operation_count INTEGER,
            first_missing_signal TEXT, recorded_at TEXT,
            receipt_ref TEXT NOT NULL, profile_identity TEXT NOT NULL, step TEXT, error TEXT,
            UNIQUE (run_id, module_id)
         );
         CREATE INDEX IF NOT EXISTS ledger_module ON ledger(module_id, recorded_at DESC);
         CREATE INDEX IF NOT EXISTS ledger_receipt ON ledger(receipt_ref);
         CREATE TABLE IF NOT EXISTS migrations (id TEXT PRIMARY KEY);
         CREATE TABLE IF NOT EXISTS deed_outbox (id TEXT PRIMARY KEY, count INTEGER NOT NULL);"
    ).map_err(database_error)?;
    transaction.execute_batch(PROPOSALS_TABLE).map_err(database_error)?;
    transaction.execute_batch(CONFIG_PROPOSALS_TABLE).map_err(database_error)?;
    let migrated = migrate_proposal_identity(&transaction)?;
    migrate_proposal_documents(&transaction, &database)?;
    transaction.commit().map_err(database_error)?;
    if migrated {
        // Erase bytes freed before secure deletion was enabled too. Record the
        // migration only after scrubbing succeeds, so interruption is retryable.
        connection.execute_batch("VACUUM").map_err(database_error)?;
        let busy: i64 = connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .map_err(database_error)?;
        if busy != 0 { return Err("harmonia-state-checkpoint-busy".into()); }
        connection.execute("INSERT OR IGNORE INTO migrations(id) VALUES(?1)", [PROPOSAL_IDENTITY_MIGRATION])
            .map_err(database_error)?;
    }
    Ok(connection)
}

fn migrate_proposal_documents(connection: &Connection, database: &Path) -> Result<(), String> {
    let complete: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM migrations WHERE id=?1)",
        [PROPOSAL_DOCUMENT_MIGRATION], |row| row.get(0),
    ).map_err(database_error)?;
    if complete { return Ok(()); }
    let has_document: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('proposals') WHERE name='document')",
        [], |row| row.get(0),
    ).map_err(database_error)?;
    if !has_document {
        connection.execute("ALTER TABLE proposals ADD COLUMN document TEXT", []).map_err(database_error)?;
    }
    let has_position: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('proposals') WHERE name='position')",
        [], |row| row.get(0),
    ).map_err(database_error)?;
    if !has_position {
        connection.execute("ALTER TABLE proposals ADD COLUMN position INTEGER", []).map_err(database_error)?;
    }
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS appearance_adoption (
             module_id TEXT NOT NULL, home TEXT NOT NULL, PRIMARY KEY(module_id,home));
         CREATE TABLE IF NOT EXISTS appearance_completion (
             module_id TEXT PRIMARY KEY, id TEXT NOT NULL, ok INTEGER NOT NULL);"
    ).map_err(database_error)?;
    // Different legacy feeds may hold different state for the same id. Never
    // silently pick a winner when collapsing their keys into the single feed.
    for (table, sql) in [
        ("proposals", "SELECT id FROM proposals GROUP BY id HAVING COUNT(*)>1 LIMIT 1"),
        ("proposal_config", "SELECT id FROM proposal_config GROUP BY id HAVING COUNT(*)>1 LIMIT 1"),
    ] {
        let conflict: Option<String> = connection.query_row(sql, [], |row| row.get(0))
            .optional().map_err(database_error)?;
        if let Some(id) = conflict {
            return Err(format!("legacy-proposal-feed-id-collision table={table} id={id}"));
        }
    }
    connection.execute("UPDATE proposals SET feed_id=?1 WHERE feed_id<>?1", [PROPOSAL_FEED]).map_err(database_error)?;
    connection.execute("UPDATE proposal_config SET feed_id=?1 WHERE feed_id<>?1", [PROPOSAL_FEED]).map_err(database_error)?;
    // Only this migration reads the old projection; an absent or malformed file
    // leaves old indexed rows without documents until observation re-mints them.
    const LEGACY_FILE: &str = "interactables.json";
    let legacy = database.parent().unwrap_or_else(|| Path::new(".")).join(LEGACY_FILE);
    let imported = {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
        match options.open(&legacy) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ELOOP) => None,
            Err(error) => return Err(format!("legacy-feed-open-failed: {error}")),
            Ok(mut file) => {
                if !file.metadata().map_err(|error| format!("legacy-feed-metadata-failed: {error}"))?.is_file() {
                    None
                } else {
                    let mut bytes = Vec::new();
                    file.read_to_end(&mut bytes).map_err(|error| format!("legacy-feed-read-failed: {error}"))?;
                    match serde_json::from_slice::<crate::interactables::InteractablesFeed>(&bytes) {
                        Err(_) => None, // A2: an unparseable feed imports nothing, never a refusal.
                        Ok(feed) if feed.schema == crate::interactables::FEED_SCHEMA
                            || feed.schema == crate::interactables::LEGACY_FEED_SCHEMA => Some(feed),
                        Ok(feed) => return Err(format!("legacy-feed-schema-unsupported {}", feed.schema)),
                    }
                }
            }
        }
    };
    if let Some(feed) = imported {
        let mut seen = std::collections::BTreeSet::new();
        for item in &feed.interactables {
            if !seen.insert(&item.id) {
                return Err(format!("legacy-feed-document-id-collision id={}", item.id));
            }
        }
        for (position, mut item) in feed.interactables.into_iter().enumerate() {
            let flags: Option<(bool, bool)> = connection.query_row(
                "SELECT silenced,has_run FROM proposals WHERE feed_id=?1 AND id=?2",
                params![PROPOSAL_FEED,item.id], |row| Ok((row.get(0)?,row.get(1)?)),
            ).optional().map_err(database_error)?;
            if let Some((silenced, has_run)) = flags {
                item.silenced = silenced;
                item.has_run = has_run;
            }
            upsert_proposal_row(connection, PROPOSAL_FEED, &item)?;
            set_proposal_position(connection, PROPOSAL_FEED, &item.id, position)?;
        }
        for receipt in &feed.receipts {
            record_appearance_facts(connection, receipt)?;
        }
        if let Some(seat) = crate::atoms::ask::mint_seats::feed_if_present()? {
            let visible = load_proposals_on(connection)?;
            seat.validate_ruyi(&serde_json::to_value(&visible).map_err(|error| error.to_string())?)?;
        }
    }
    connection.execute("INSERT INTO migrations(id) VALUES(?1)", [PROPOSAL_DOCUMENT_MIGRATION]).map_err(database_error)?;
    Ok(())
}

pub(crate) fn record_appearance_facts(connection: &Connection, receipt: &Value) -> Result<(), String> {
    if receipt.get("schema").and_then(Value::as_str) != Some("harmonia.interactables.hermes_appearance.receipt.v1") {
        return Ok(());
    }
    let Some(module) = receipt.get("module_id").and_then(Value::as_str) else { return Ok(()); };
    let id = receipt.get("id").and_then(Value::as_str).unwrap_or_default();
    let homes = receipt.get("homes").and_then(Value::as_array);
    if let Some(homes) = homes {
        for home in homes.iter().filter(|home| home.get("ok").and_then(Value::as_bool) == Some(true)) {
            if let Some(path) = home.get("home").and_then(Value::as_str) {
                connection.execute("INSERT OR IGNORE INTO appearance_adoption(module_id,home) VALUES(?1,?2)", params![module,path])
                    .map_err(database_error)?;
            }
        }
    }
    let success = receipt.get("ok").and_then(Value::as_bool) == Some(true)
        && receipt.get("kind").and_then(Value::as_str) == Some("hermes-appearance")
        && homes.is_some_and(|homes| !homes.is_empty() && homes.iter().all(|home| home.get("ok").and_then(Value::as_bool) == Some(true)));
    connection.execute(
        "INSERT INTO appearance_completion(module_id,id,ok) VALUES(?1,?2,?3)
         ON CONFLICT(module_id) DO UPDATE SET id=excluded.id,ok=excluded.ok
         WHERE (id,ok) IS NOT (excluded.id,excluded.ok)",
        params![module,id,success],
    ).map_err(database_error)?;
    Ok(())
}

fn proposal_feed_id(path: &Path) -> String {
    format!("harmonia-feed-{:x}", Sha256::digest(path.as_os_str().as_bytes()))
}

fn stored_reference(item: &crate::interactables::Interactable) -> Option<String> {
    item.reference_source_path.as_ref().map(|path| path.to_string_lossy().into_owned())
}

/// Move caller locations to opaque product keys once. Both halves of each
/// pending proposal move in one transaction; source bytes stay available.
fn migrate_proposal_identity(connection: &Connection) -> Result<bool, String> {
    let complete: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM migrations WHERE id=?1)", [PROPOSAL_IDENTITY_MIGRATION], |row| row.get(0),
    ).map_err(database_error)?;
    if complete { return Ok(false); }
    let mut after: Option<String> = None;
    loop {
        let next: Option<String> = connection.query_row(
            "SELECT feed_id FROM (SELECT feed_id FROM proposals UNION SELECT feed_id FROM proposal_config)
             WHERE (?1 IS NULL OR feed_id>?1) ORDER BY feed_id LIMIT 1",
            [&after], |row| row.get(0),
        ).optional().map_err(database_error)?;
        let Some(old) = next else { break; };
        if old != PROPOSAL_FEED && !old.starts_with("harmonia-feed-") {
            let new = proposal_feed_id(Path::new(&old));
            connection.execute(
                "INSERT INTO proposals(feed_id,id,module_id,kind,target_path,reference_source_path,live_sha,reference_sha,silenced,has_run) SELECT ?1,id,module_id,kind,target_path,reference_source_path,live_sha,reference_sha,silenced,has_run FROM proposals WHERE feed_id=?2",
                params![new,old],
            ).map_err(database_error)?;
            connection.execute(
                "INSERT INTO proposal_config SELECT ?1,id,config_state,source FROM proposal_config WHERE feed_id=?2",
                params![new,old],
            ).map_err(database_error)?;
            connection.execute("DELETE FROM proposal_config WHERE feed_id=?1", [&old]).map_err(database_error)?;
            connection.execute("DELETE FROM proposals WHERE feed_id=?1", [&old]).map_err(database_error)?;
        }
        after = Some(old);
    }
    connection.execute(
        "UPDATE proposals SET reference_source_path='/var/lib/harmonia/proposal-sources/' || id || '.source' WHERE reference_source_path IS NOT NULL",
        [],
    ).map_err(database_error)?;
    connection.execute(
        "UPDATE proposal_config SET config_state=json_remove(json_set(config_state,
         '$.reference','/var/lib/harmonia/proposal-sources/' || id || '.source',
         '$.reference_id','/var/lib/harmonia/proposal-sources/' || id || '.source'),'$.run_id')",
        [],
    ).map_err(database_error)?;
    Ok(true)
}

struct LedgerSeats {
    entry: Option<crate::atoms::ask::mint_seats::Seat>,
    page: Option<crate::atoms::ask::mint_seats::Seat>,
}

fn seats() -> Result<&'static LedgerSeats, String> {
    static SEATS: OnceLock<Result<LedgerSeats, String>> = OnceLock::new();
    SEATS.get_or_init(|| {
        let base = crate::atoms::ask::caduceus_door::base_url().ok();
        Ok(LedgerSeats {
            entry: match base { Some(base) => crate::atoms::ask::mint_seats::Seat::load_if_present(ENTRY, base)?, None => None },
            page: match base { Some(base) => crate::atoms::ask::mint_seats::Seat::load_if_present(PAGE, base)?, None => None },
        })
    }).as_ref().map_err(Clone::clone)
}

fn unreported_absences(seats: &LedgerSeats, observed: Option<&Connection>) -> Result<Vec<&'static str>, String> {
    let mut absent = Vec::new();
    for (id, loaded) in [(ENTRY, &seats.entry), (PAGE, &seats.page)] {
        if loaded.is_some() { continue; }
        let reported = match observed {
            Some(connection) => connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM migrations WHERE id=?1)",
                [format!("schema-seat-absent:{id}")], |row| row.get::<_, bool>(0),
            ).map_err(database_error)?,
            None => false,
        };
        if !reported { absent.push(id); }
    }
    Ok(absent)
}

/// Failure state is not a transcript. Scrub a credential-bearing suffix rather
/// than guessing where its value ends, then truncate only at a UTF-8 boundary.
fn redacted_failure_text(value: &str) -> String {
    bounded_redacted(value, 4096)
}

fn bounded_redacted(value: &str, limit: usize) -> String {
    let lower = value.to_ascii_lowercase();
    let sensitive = ["password", "passwd", "secret", "token", "authorization", "bearer ",
        "credential", "api_key", "apikey", "access_key", "private_key", "private key",
        "connection_string", "pin=", "pin:", "\"pin\"", "://", "-----begin", "sk-", "ghp_", "glpat-", "eyj",
        "stderr=", "stdout=", "\n", "\r"]
        .iter().filter_map(|marker| lower.find(marker)).min();
    let mut redacted = match sensitive {
        Some(index) => format!("{}[REDACTED]", &value[..index]),
        None => value.to_owned(),
    };
    let mut end = redacted.len().min(limit);
    while !redacted.is_char_boundary(end) { end -= 1; }
    redacted.truncate(end);
    redacted
}

/// Keep only the newest material outcome for each module. A quiet success keeps
/// that outcome, not a new run-id/timestamp row; repeated identical failures do too.
pub(crate) fn record(
    profile: &crate::Profile, run_id: &str, entries: &[crate::receipts::ProfileLedgerEntry<'_>],
) -> Result<(), String> {
    if entries.is_empty() { return Ok(()); }
    let mut connection = writer()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(database_error)?;
    let mut changes = Vec::new();
    let profile_identity = bounded_redacted(&profile.identity, 96);
    for entry in entries {
        let first_missing_signal = redacted_failure_text(entry.first_missing_signal);
        let error = (!entry.ok).then(|| redacted_failure_text(entry.error.unwrap_or(entry.first_missing_signal)));
        let failed_step = (!entry.ok).then_some(entry.step).flatten().map(|value| bounded_redacted(value, 128));
        let module_version = entry.module_version.map(|value| bounded_redacted(value, 96));
        let prior: Option<(Option<String>, Option<String>, Option<bool>, Option<i64>, Option<String>, Option<String>, Option<String>, Option<String>)> =
            transaction.query_row(
                    "SELECT profile_id,module_version,ok,operation_count,first_missing_signal,profile_identity,step,error
                     FROM ledger WHERE module_id=?1 ORDER BY ledger_sequence DESC LIMIT 1",
                    [entry.module_id],
                    |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)),
                ).optional().map_err(database_error)?;
        let same_state = prior.as_ref().is_some_and(|prior| {
            prior.0.as_deref() == Some(profile.id.as_str())
                && prior.1 == module_version
                && prior.2 == Some(entry.ok)
                && prior.3 == i64::try_from(entry.operation_count).ok()
                && prior.4.as_deref() == Some(first_missing_signal.as_str())
                && prior.5.as_deref() == Some(profile_identity.as_str())
                && prior.6 == failed_step
                && prior.7 == error
        });
        // A first all-current observation is not a deed. Recovery from a failed
        // outcome is a state transition, even when no software bytes moved.
        if !entry.changed && (same_state || (entry.ok && prior.is_none())) { continue; }
        let receipt_ref = std::fs::canonicalize(entry.receipt_dir)
            .map_err(|error| format!("ledger-receipt-reference-observe-failed: {error}"))?;
        let receipt_ref = receipt_ref.to_str().ok_or("ledger-receipt-reference-not-utf8")?;
        let row = json!({
            "schema": ENTRY, "run_id": run_id, "module_id": entry.module_id,
            "profile_id": profile.id, "module_version": module_version,
            "ok": entry.ok, "changed": entry.changed, "operation_count": entry.operation_count,
            "first_missing_signal": first_missing_signal,
            "recorded_at": crate::bands::propose_edits::iso8601_now(),
            "receipt_ref": receipt_ref, "profile_identity": profile_identity,
            "step": failed_step, "error": error,
        });
        changes.push(row);
    }
    // Equality and timestamps above are serialized; quiet presses ask no door.
    if changes.is_empty() { return Ok(()); }
    let seats = seats()?;
    let absent = unreported_absences(seats, Some(&transaction))?;
    let mut newly_absent = Vec::new();
    let mut outcome_deeds = Vec::new();
    for id in absent {
        if transaction.execute("INSERT OR IGNORE INTO migrations(id) VALUES(?1)",
            [format!("schema-seat-absent:{id}")]).map_err(database_error)? > 0 {
            newly_absent.push(id);
        }
    }
    for mut row in changes {
        transaction.execute("DELETE FROM ledger WHERE module_id=?1 AND run_id<>?2",
            params![row["module_id"].as_str(),row["run_id"].as_str()]).map_err(database_error)?;
        let sequence: i64 = transaction.query_row(
            "INSERT INTO ledger(run_id,module_id,profile_id,module_version,ok,changed,operation_count,first_missing_signal,recorded_at,receipt_ref,profile_identity,step,error)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
             ON CONFLICT(run_id,module_id) DO UPDATE SET profile_id=excluded.profile_id,
               module_version=excluded.module_version,ok=excluded.ok,changed=excluded.changed,
               operation_count=excluded.operation_count,first_missing_signal=excluded.first_missing_signal,
               recorded_at=excluded.recorded_at,receipt_ref=excluded.receipt_ref,
               profile_identity=excluded.profile_identity,step=excluded.step,error=excluded.error
             RETURNING ledger_sequence",
            params![row["run_id"].as_str(),row["module_id"].as_str(),row["profile_id"].as_str(),
                row["module_version"].as_str(),row["ok"].as_bool(),row["changed"].as_bool(),
                row["operation_count"].as_i64(),row["first_missing_signal"].as_str(),row["recorded_at"].as_str(),
                row["receipt_ref"].as_str(),row["profile_identity"].as_str(),row["step"].as_str(),row["error"].as_str()],
            |row| row.get(0),
        ).map_err(database_error)?;
        row["ledger_sequence"] = json!(sequence);
        if let Some(seat) = &seats.entry { seat.validate_ruyi(&row)?; }
        if row["ok"] == false || row["changed"] == false {
            outcome_deeds.push((row["module_id"].as_str().unwrap_or_default().to_owned(),
                row["ok"].as_bool().unwrap_or(false), row["first_missing_signal"].as_str().unwrap_or("module-failed").to_owned()));
        }
    }
    transaction.commit().map_err(database_error)?;
    for (module, ok, signal) in outcome_deeds {
        let _ = crate::deeds::record("module-outcome", &module, ok, true, None,
            Some(run_id), Some(&module), Some(&signal), None);
    }
    if !newly_absent.is_empty() {
        let _ = crate::deeds::record("schema-seat-absent", &newly_absent.join(":"), true, true,
            None, Some(run_id), None, Some("primitive-field-presence"), Some(newly_absent.len() as u64));
    }
    Ok(())
}

pub(crate) fn command(args: &[String]) -> Result<(), String> {
    let mut module = None;
    let mut page = 1_u64;
    let mut per_page = 25_u64;
    let mut json_requested = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--json" if !json_requested => { json_requested = true; index += 1; }
            "--module" if module.is_none() => {
                module = Some(args.get(index+1).filter(|value| !value.is_empty() && !value.starts_with("--"))
                    .ok_or("ledger-module-missing")?.as_str());
                index += 2;
            }
            "--page" | "--per-page" => {
                let flag = args[index].as_str();
                let number = args.get(index+1).ok_or("ledger-page-value-missing")?
                    .parse::<u64>().map_err(|_| "ledger-page-value-invalid")?;
                if number == 0 { return Err("ledger-page-value-invalid".into()); }
                if flag == "--page" { page = number; } else { per_page = number.min(25); }
                index += 2;
            }
            _ => return Err("ledger accepts [--module <id>] [--page N] [--per-page M] --json".into()),
        }
    }
    if !json_requested { return Err("ledger-json-required".into()); }
    let seats = seats()?;
    let connection = reader()?;
    let total: u64 = match connection.as_ref() {
        Some(connection) => connection.query_row(
            "SELECT count(*) FROM ledger WHERE (?1 IS NULL OR module_id=?1)", [module], |row| row.get(0),
        ).map_err(database_error)?,
        None => 0,
    };
    let total_pages = total.div_ceil(per_page).max(1);
    page = page.min(total_pages);
    let offset = (page-1)*per_page;
    let mut entries = Vec::new();
    if let Some(connection) = connection.as_ref() {
        let mut query = connection.prepare(
            "SELECT run_id,module_id,profile_id,module_version,ok,changed,operation_count,first_missing_signal,recorded_at,receipt_ref,ledger_sequence,profile_identity,step,error
             FROM ledger WHERE (?1 IS NULL OR module_id=?1)
             ORDER BY recorded_at DESC,run_id DESC,module_id ASC LIMIT ?2 OFFSET ?3",
        ).map_err(database_error)?;
        let mut rows = query.query(params![module,per_page,offset]).map_err(database_error)?;
        while let Some(row) = rows.next().map_err(database_error)? {
            let entry = json!({
                "schema": ENTRY, "run_id": row.get::<_,Option<String>>(0).map_err(database_error)?,
                "module_id": row.get::<_,Option<String>>(1).map_err(database_error)?,
                "profile_id": row.get::<_,Option<String>>(2).map_err(database_error)?,
                "module_version": row.get::<_,Option<String>>(3).map_err(database_error)?,
                "ok": row.get::<_,Option<bool>>(4).map_err(database_error)?,
                "changed": row.get::<_,Option<bool>>(5).map_err(database_error)?,
                "operation_count": row.get::<_,Option<i64>>(6).map_err(database_error)?,
                "first_missing_signal": row.get::<_,Option<String>>(7).map_err(database_error)?,
                "recorded_at": row.get::<_,Option<String>>(8).map_err(database_error)?,
                "receipt_ref": row.get::<_,Option<String>>(9).map_err(database_error)?,
                "ledger_sequence": row.get::<_,Option<i64>>(10).map_err(database_error)?,
                "profile_identity": row.get::<_,Option<String>>(11).map_err(database_error)?,
                "step": row.get::<_,Option<String>>(12).map_err(database_error)?,
                "error": row.get::<_,Option<String>>(13).map_err(database_error)?,
            });
            if let Some(seat) = &seats.entry { seat.validate_ruyi(&entry)?; }
            entries.push(json!({"ordinal": total-offset-entries.len() as u64,"entry": entry}));
        }
    }
    let page = json!({"schema":PAGE,"ledgerPath":Value::Null,"module":module,
        "page":page,"perPage":per_page,"totalEntries":total,"totalPages":total_pages,
        "entries":entries,"ok":true,
        "firstMissingSignal":if total==0 {"caduceus-ledger-empty"} else {"none"}});
    if let Some(seat) = &seats.page { seat.validate_ruyi(&page)?; }
    println!("{}", serde_json::to_string(&page).map_err(|error| error.to_string())?);
    Ok(())
}

fn config_reader() -> Result<Option<Connection>, String> {
    let Some(connection) = reader()? else { return Ok(None); };
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='proposal_config')",
        [], |row| row.get(0),
    ).map_err(database_error)?;
    Ok(present.then_some(connection))
}

/// Reads can consume a pending proposal before its producer next writes and
/// migrates the store. They never create or repair persistent state.
pub(crate) fn config_state(path: &Path, id: &str) -> Result<Option<Value>, String> {
    let Some(connection) = config_reader()? else { return Ok(None); };
    let state: Option<String> = connection.query_row(
        "SELECT config_state FROM proposal_config WHERE (feed_id=?1 OR feed_id=?3) AND id=?2 ORDER BY feed_id=?1 DESC LIMIT 1",
        params![PROPOSAL_FEED.to_owned(),id,path.to_string_lossy()], |row| row.get(0),
    ).optional().map_err(database_error)?;
    state.map(|state| serde_json::from_str(&state).map_err(|error| error.to_string())).transpose()
}

pub(crate) fn proposal_source(path: &Path, id: &str) -> Result<Option<Vec<u8>>, String> {
    let Some(connection) = config_reader()? else { return Ok(None); };
    connection.query_row(
        "SELECT source FROM proposal_config WHERE (feed_id=?1 OR feed_id=?3) AND id=?2 ORDER BY feed_id=?1 DESC LIMIT 1",
        params![PROPOSAL_FEED.to_owned(),id,path.to_string_lossy()], |row| row.get(0),
    ).optional().map_err(database_error)
}

pub(crate) fn has_proposal_source_on(connection: &Connection, id: &str) -> Result<bool, String> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM proposal_config WHERE feed_id=?1 AND id=?2)",
        params![PROPOSAL_FEED,id], |row| row.get(0),
    ).map_err(database_error)
}

fn upsert_config_row(connection: &Connection, feed_id: &str, proposal: &ConfigProposal) -> Result<(), String> {
    connection.execute(
        "INSERT INTO proposal_config(feed_id,id,config_state,source) VALUES(?1,?2,?3,?4)
         ON CONFLICT(feed_id,id) DO UPDATE SET config_state=excluded.config_state,source=excluded.source
         WHERE (config_state,source) IS NOT (excluded.config_state,excluded.source)",
        params![feed_id,proposal.id,proposal.state.to_string(),proposal.source],
    ).map_err(database_error)?;
    Ok(())
}

fn project_proposal_rows(connection: &Connection, feed_id: &str, feed: &crate::interactables::InteractablesFeed) -> Result<(), String> {
    for (position, item) in feed.interactables.iter().enumerate() {
        upsert_proposal_row(connection, feed_id, item)?;
        set_proposal_position(connection, feed_id, &item.id, position)?;
    }
    // Keyset walk: no whole-store load or body replay, even during repair.
    let mut after: Option<String> = None;
    loop {
        let next: Option<String> = connection.query_row(
            "SELECT id FROM proposals WHERE feed_id=?1 AND document IS NOT NULL AND (?2 IS NULL OR id>?2) ORDER BY id LIMIT 1",
            params![feed_id,after], |row| row.get(0)).optional().map_err(database_error)?;
        let Some(id) = next else { break; };
        if !feed.interactables.iter().any(|item| item.id==id) {
            // Both parts of the proposal resolve with its identity, under the
            // caller's single transaction; a crash cannot leave either behind.
            connection.execute("DELETE FROM proposal_config WHERE feed_id=?1 AND id=?2", params![feed_id,id]).map_err(database_error)?;
            connection.execute("DELETE FROM proposals WHERE feed_id=?1 AND id=?2", params![feed_id,id]).map_err(database_error)?;
        }
        after = Some(id);
    }
    Ok(())
}

fn set_proposal_position(connection: &Connection, feed_id: &str, id: &str, position: usize) -> Result<(), String> {
    connection.execute(
        "UPDATE proposals SET position=?1 WHERE feed_id=?2 AND id=?3 AND position IS NOT ?1",
        params![position as i64,feed_id,id],
    ).map_err(database_error)?;
    Ok(())
}

fn upsert_proposal_row(connection: &Connection, feed_id: &str, item: &crate::interactables::Interactable) -> Result<(), String> {
    connection.execute(
        "INSERT INTO proposals(feed_id,id,module_id,kind,target_path,reference_source_path,live_sha,reference_sha,silenced,has_run,document)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
         ON CONFLICT(feed_id,id) DO UPDATE SET module_id=excluded.module_id,kind=excluded.kind,
          target_path=excluded.target_path,reference_source_path=excluded.reference_source_path,
          live_sha=excluded.live_sha,reference_sha=excluded.reference_sha,silenced=excluded.silenced,has_run=excluded.has_run,document=excluded.document
         WHERE (module_id,kind,target_path,reference_source_path,live_sha,reference_sha,silenced,has_run,document)
           IS NOT (excluded.module_id,excluded.kind,excluded.target_path,excluded.reference_source_path,
                   excluded.live_sha,excluded.reference_sha,excluded.silenced,excluded.has_run,excluded.document)",
        params![feed_id,item.id,item.module_id,item.kind,item.target_path.as_ref().map(|p|p.to_string_lossy()),
            stored_reference(item),item.live_sha,item.reference_sha,item.silenced,item.has_run,
            serde_json::to_string(item).map_err(|error| error.to_string())?],
    ).map_err(database_error)?;
    Ok(())
}

pub(crate) fn load_proposals_on(connection: &Connection) -> Result<crate::interactables::InteractablesFeed, String> {
    let has_document: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('proposals') WHERE name='document')",
        [], |row| row.get(0),
    ).map_err(database_error)?;
    if !has_document { return Ok(crate::interactables::make_feed(Vec::new())); }
    let mut query = connection.prepare(
        "SELECT document,silenced,has_run FROM proposals WHERE feed_id=?1 AND document IS NOT NULL ORDER BY position IS NULL,position,rowid"
    ).map_err(database_error)?;
    let mut rows = query.query([PROPOSAL_FEED]).map_err(database_error)?;
    let mut items = Vec::new();
    while let Some(row) = rows.next().map_err(database_error)? {
        let document: String = row.get(0).map_err(database_error)?;
        let mut item: crate::interactables::Interactable = serde_json::from_str(&document)
            .map_err(|error| format!("interactable-document-invalid: {error}"))?;
        item.silenced = row.get(1).map_err(database_error)?;
        item.has_run = row.get(2).map_err(database_error)?;
        items.push(item);
    }
    Ok(crate::interactables::make_feed(items))
}

pub(crate) fn load_proposal_on(connection: &Connection, id: &str) -> Result<Option<crate::interactables::Interactable>, String> {
    let has_document: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('proposals') WHERE name='document')",
        [], |row| row.get(0),
    ).map_err(database_error)?;
    if !has_document { return Ok(None); }
    let row: Option<(String, bool, bool)> = connection.query_row(
        "SELECT document,silenced,has_run FROM proposals WHERE feed_id=?1 AND id=?2 AND document IS NOT NULL AND kind!='engine-replacement'",
        params![PROPOSAL_FEED,id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).optional().map_err(database_error)?;
    row.map(|(document, silenced, has_run)| {
        let mut item: crate::interactables::Interactable = serde_json::from_str(&document)
            .map_err(|error| format!("interactable-document-invalid: {error}"))?;
        item.silenced = silenced;
        item.has_run = has_run;
        Ok(item)
    }).transpose()
}

pub(crate) fn load_proposal(id: &str) -> Result<Option<crate::interactables::Interactable>, String> {
    match reader()? {
        Some(connection) => load_proposal_on(&connection, id),
        None => Ok(None),
    }
}

pub(crate) fn set_proposal_silence_on(connection: &Connection, item: &crate::interactables::Interactable) -> Result<(), String> {
    let document = serde_json::to_string(item).map_err(|error| error.to_string())?;
    connection.execute("UPDATE proposals SET silenced=?1, document=?2 WHERE feed_id=?3 AND id=?4 AND document IS NOT NULL",
        params![item.silenced,document,PROPOSAL_FEED,item.id]).map_err(database_error)?;
    // A declared feed seat validates the composed full feed before commit.
    if let Some(seat) = crate::atoms::ask::mint_seats::feed_if_present()? {
        let feed = load_proposals_on(connection)?;
        seat.validate_ruyi(&serde_json::to_value(feed).map_err(|error| error.to_string())?)?;
    }
    Ok(())
}

pub(crate) fn remove_proposal_on(connection: &Connection, id: &str) -> Result<bool, String> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM proposals WHERE feed_id=?1 AND id=?2 AND document IS NOT NULL)",
        params![PROPOSAL_FEED,id], |row| row.get(0),
    ).map_err(database_error)?;
    if exists {
        connection.execute("DELETE FROM proposal_config WHERE feed_id=?1 AND id=?2", params![PROPOSAL_FEED,id]).map_err(database_error)?;
        connection.execute("DELETE FROM proposals WHERE feed_id=?1 AND id=?2", params![PROPOSAL_FEED,id]).map_err(database_error)?;
    }
    Ok(exists)
}

pub(crate) fn validate_proposals_on(connection: &Connection) -> Result<(), String> {
    if let Some(seat) = crate::atoms::ask::mint_seats::feed_if_present()? {
        let feed = load_proposals_on(connection)?;
        seat.validate_ruyi(&serde_json::to_value(feed).map_err(|error| error.to_string())?)?;
    }
    Ok(())
}

pub(crate) fn has_proposal_kind(kind: &str) -> Result<bool, String> {
    let Some(connection) = reader()? else { return Ok(false); };
    let has_document: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('proposals') WHERE name='document')",
        [], |row| row.get(0),
    ).map_err(database_error)?;
    if !has_document { return Ok(false); }
    connection.query_row("SELECT EXISTS(SELECT 1 FROM proposals WHERE feed_id=?1 AND kind=?2 AND document IS NOT NULL)",
        params![PROPOSAL_FEED,kind], |row| row.get(0)).map_err(database_error)
}

pub(crate) fn load_proposals() -> Result<crate::interactables::InteractablesFeed, String> {
    match reader()? {
        Some(connection) => load_proposals_on(&connection),
        None => Ok(crate::interactables::make_feed(Vec::new())),
    }
}

pub(crate) fn has_unmatched_proposals() -> Result<bool, String> {
    let Some(connection) = reader()? else { return Ok(false); };
    let has_document: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('proposals') WHERE name='document')",
        [], |row| row.get(0),
    ).map_err(database_error)?;
    let sql = if has_document {
        "SELECT EXISTS(SELECT 1 FROM proposals WHERE document IS NULL)"
    } else {
        "SELECT EXISTS(SELECT 1 FROM proposals)"
    };
    connection.query_row(sql, [], |row| row.get(0)).map_err(database_error)
}

pub(crate) fn with_proposal_transaction<T>(operation: impl FnOnce(&Connection) -> Result<T, String>) -> Result<T, String> {
    let mut connection = writer()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(database_error)?;
    let result = operation(&transaction)?;
    transaction.commit().map_err(database_error)?;
    Ok(result)
}

pub(crate) fn save_proposals_on(
    connection: &Connection, feed: &crate::interactables::InteractablesFeed, config: &[ConfigProposal],
) -> Result<(), String> {
    let mut visible = feed.clone();
    visible.receipts.clear();
    visible.extra.clear();
    for item in &mut visible.interactables {
        let flags: Option<(bool, bool)> = connection.query_row(
            "SELECT silenced,has_run FROM proposals WHERE feed_id=?1 AND id=?2 AND document IS NULL",
            params![PROPOSAL_FEED,item.id], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional().map_err(database_error)?;
        if let Some((silenced, has_run)) = flags {
            item.silenced = silenced;
            item.has_run = has_run;
        }
    }
    if let Some(seat) = crate::atoms::ask::mint_seats::feed_if_present()? {
        seat.validate_ruyi(&serde_json::to_value(&visible).map_err(|error| error.to_string())?)?;
    }
    project_proposal_rows(connection, PROPOSAL_FEED, &visible)?;
    for proposal in config.iter().filter(|proposal| visible.interactables.iter().any(|item| item.id == proposal.id && !item.has_run)) {
        upsert_config_row(connection, PROPOSAL_FEED, proposal)?;
    }
    for receipt in &feed.receipts { record_appearance_facts(connection, receipt)?; }
    Ok(())
}

pub(crate) fn retire_unmatched_ruyi_on(connection: &Connection) -> Result<(), String> {
    connection.execute(
        "DELETE FROM proposal_config WHERE feed_id=?1 AND id IN \
         (SELECT id FROM proposals WHERE feed_id=?1 AND document IS NULL AND \
          kind IN ('ruyi-bump','dns-record','toolchain-ratchet','household-trust-renew'))",
        [PROPOSAL_FEED],
    ).map_err(database_error)?;
    connection.execute(
        "DELETE FROM proposals WHERE feed_id=?1 AND document IS NULL AND \
         kind IN ('ruyi-bump','dns-record','toolchain-ratchet','household-trust-renew')",
        [PROPOSAL_FEED],
    ).map_err(database_error)?;
    Ok(())
}

pub(crate) fn retire_unseen_documents_on(
    connection: &Connection, active: &std::collections::BTreeSet<String>,
    observed: &std::collections::BTreeSet<String>,
    recognized: &std::collections::BTreeSet<String>,
) -> Result<(), String> {
    let mut after: Option<String> = None;
    loop {
        let next: Option<(String,String,String)> = connection.query_row(
            "SELECT id,module_id,kind FROM proposals WHERE feed_id=?1 AND document IS NULL AND (?2 IS NULL OR id>?2) \
             ORDER BY id LIMIT 1", params![PROPOSAL_FEED,after], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional().map_err(database_error)?;
        let Some((id, module, kind)) = next else { break; };
        let independently_observed = matches!(kind.as_str(), "ruyi-bump" | "dns-record" | "toolchain-ratchet" | "household-trust-renew");
        if !active.contains(&module) || kind == "engine-replacement"
            || (!independently_observed && observed.contains(&module) && !recognized.contains(&id)) {
            connection.execute("DELETE FROM proposal_config WHERE feed_id=?1 AND id=?2", params![PROPOSAL_FEED,id]).map_err(database_error)?;
            connection.execute("DELETE FROM proposals WHERE feed_id=?1 AND id=?2 AND document IS NULL", params![PROPOSAL_FEED,id]).map_err(database_error)?;
        }
        after = Some(id);
    }
    Ok(())
}

pub(crate) fn adopted_homes_on(connection: &Connection, module: &str) -> Result<std::collections::BTreeSet<String>, String> {
    let mut query = connection.prepare("SELECT home FROM appearance_adoption WHERE module_id=?1").map_err(database_error)?;
    let homes = query.query_map([module], |row| row.get(0)).map_err(database_error)?
        .collect::<Result<_,_>>().map_err(database_error)?;
    Ok(homes)
}

pub(crate) fn adopted_homes(module: &str) -> Result<std::collections::BTreeSet<String>, String> {
    let Some(connection) = reader()? else { return Ok(Default::default()); };
    if connection.prepare("SELECT home FROM appearance_adoption LIMIT 0").is_err() { return Ok(Default::default()); }
    adopted_homes_on(&connection, module)
}

pub(crate) fn appearance_completed(module: &str, id: &str) -> Result<bool, String> {
    let Some(connection) = reader()? else { return Ok(false); };
    if connection.prepare("SELECT id FROM appearance_completion LIMIT 0").is_err() { return Ok(false); }
    connection.query_row("SELECT EXISTS(SELECT 1 FROM appearance_completion WHERE module_id=?1 AND id=?2 AND ok=1)",
        params![module,id], |row| row.get(0)).map_err(database_error)
}
