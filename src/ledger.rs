//! Harmonia's keyed application state. No receipt or envelope is stored here.
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

pub(crate) const DATABASE: &str = "/var/lib/harmonia/harmonia.sqlite3";
const ENTRY: &str = "harmonia.ledger.entry.v1";
const PAGE: &str = "caduceus.receipts.ledger.v1";
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

pub(crate) fn reader() -> Result<Option<Connection>, String> {
    match std::fs::symlink_metadata(DATABASE) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("harmonia-state-observe-failed: {error}")),
        Ok(metadata) if !metadata.file_type().is_file() => return Err("harmonia-state-not-regular".into()),
        Ok(_) => {}
    }
    let connection = Connection::open_with_flags(
        DATABASE, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
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
    let parent = Path::new(DATABASE).parent().unwrap();
    std::fs::create_dir_all(parent).map_err(|error| format!("harmonia-state-parent-failed: {error}"))?;
    public_mode(parent, 0o755)?;
    match std::fs::symlink_metadata(DATABASE) {
        Ok(metadata) if !metadata.file_type().is_file() => return Err("harmonia-state-not-regular".into()),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(format!("harmonia-state-observe-failed: {error}")),
        _ => {}
    }
    let mut connection = Connection::open(DATABASE).map_err(database_error)?;
    public_mode(Path::new(DATABASE), 0o644)?;
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
    transaction.commit().map_err(database_error)?;
    Ok(connection)
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

/// Old stores and absent keys are null. Queries never create or repair state.
pub(crate) fn config_state(path: &Path, id: &str) -> Result<Option<Value>, String> {
    let Some(connection) = config_reader()? else { return Ok(None); };
    let state: Option<String> = connection.query_row(
        "SELECT config_state FROM proposal_config WHERE feed_id=?1 AND id=?2",
        params![path.to_string_lossy(),id], |row| row.get(0),
    ).optional().map_err(database_error)?;
    state.map(|state| serde_json::from_str(&state).map_err(|error| error.to_string())).transpose()
}

pub(crate) fn proposal_source(path: &Path, id: &str) -> Result<Option<Vec<u8>>, String> {
    let Some(connection) = config_reader()? else { return Ok(None); };
    connection.query_row(
        "SELECT source FROM proposal_config WHERE feed_id=?1 AND id=?2",
        params![path.to_string_lossy(),id], |row| row.get(0),
    ).optional().map_err(database_error)
}

pub(crate) fn has_proposal_source(path: &Path, id: &str) -> Result<bool, String> {
    let Some(connection) = config_reader()? else { return Ok(false); };
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM proposal_config WHERE feed_id=?1 AND id=?2)",
        params![path.to_string_lossy(),id], |row| row.get(0),
    ).map_err(database_error)
}

/// Make new sources durable before exposing their reference strings. Do not
/// resolve any prior identity here: the old feed may still be visible until
/// its projection succeeds. Final synchronization resolves retired rows.
pub(crate) fn prepare_config_proposals(
    path: &Path, feed: &crate::interactables::InteractablesFeed, config: &[ConfigProposal],
) -> Result<(), String> {
    if config.is_empty() { return Ok(()); }
    if let Some(connection) = reader()? {
        if proposal_rows_match(&connection, &path.to_string_lossy(), feed)?
            && config_rows_match(&connection, &path.to_string_lossy(), feed, config)?
        { return Ok(()); }
    }
    if let Some(seat) = crate::atoms::ask::mint_seats::feed_if_present()? {
        seat.validate_ruyi(&serde_json::to_value(feed).map_err(|error| error.to_string())?)?;
    }
    let mut connection = writer()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(database_error)?;
    let feed_id = path.to_string_lossy();
    for proposal in config {
        if let Some(item) = feed.interactables.iter().find(|item| item.id==proposal.id && !item.has_run) {
            upsert_proposal_row(&transaction, &feed_id, item)?;
            upsert_config_row(&transaction, &feed_id, proposal)?;
        }
    }
    transaction.commit().map_err(database_error)
}

/// The public feed remains the presentation surface. Its proposal identities
/// and their config state/source snapshots change together, by key; no run
/// receipt, diff or command payload is copied into the database.
pub(crate) fn sync_proposals(
    path: &Path, feed: &crate::interactables::InteractablesFeed, config: &[ConfigProposal],
) -> Result<(), String> {
    let feed_id = path.to_string_lossy();
    let observed = reader()?;
    if observed.is_none() && feed.interactables.is_empty() { return Ok(()); }
    if let Some(connection) = observed.as_ref() {
        if proposal_rows_match(connection, &feed_id, feed)? && config_rows_match(connection, &feed_id, feed, config)? {
            return Ok(());
        }
    }
    drop(observed);
    if let Some(seat) = crate::atoms::ask::mint_seats::feed_if_present()? {
        seat.validate_ruyi(&serde_json::to_value(feed).map_err(|error| error.to_string())?)?;
    }
    let mut connection = writer()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(database_error)?;
    project_proposal_rows(&transaction, &feed_id, feed)?;
    for proposal in config.iter().filter(|proposal| feed.interactables.iter().any(|item| item.id==proposal.id && !item.has_run)) {
        upsert_config_row(&transaction, &feed_id, proposal)?;
    }
    transaction.commit().map_err(database_error)
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

fn config_rows_match(
    connection: &Connection, feed_id: &str, feed: &crate::interactables::InteractablesFeed,
    config: &[ConfigProposal],
) -> Result<bool, String> {
    if config.is_empty() { return Ok(true); }
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='proposal_config')",
        [], |row| row.get(0),
    ).map_err(database_error)?;
    if !present { return Ok(false); }
    for proposal in config.iter().filter(|proposal| feed.interactables.iter().any(|item| item.id==proposal.id && !item.has_run)) {
        let same: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM proposal_config WHERE feed_id=?1 AND id=?2 AND config_state=?3 AND source=?4)",
            params![feed_id,proposal.id,proposal.state.to_string(),proposal.source], |row| row.get(0),
        ).map_err(database_error)?;
        if !same { return Ok(false); }
    }
    Ok(true)
}

fn project_proposal_rows(connection: &Connection, feed_id: &str, feed: &crate::interactables::InteractablesFeed) -> Result<(), String> {
    for item in &feed.interactables {
        upsert_proposal_row(connection, feed_id, item)?;
    }
    // Keyset walk: no whole-store load or body replay, even during repair.
    let mut after: Option<String> = None;
    loop {
        let next: Option<String> = connection.query_row(
            "SELECT id FROM proposals WHERE feed_id=?1 AND (?2 IS NULL OR id>?2) ORDER BY id LIMIT 1",
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

fn upsert_proposal_row(connection: &Connection, feed_id: &str, item: &crate::interactables::Interactable) -> Result<(), String> {
    connection.execute(
        "INSERT INTO proposals(feed_id,id,module_id,kind,target_path,reference_source_path,live_sha,reference_sha,silenced,has_run)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
         ON CONFLICT(feed_id,id) DO UPDATE SET module_id=excluded.module_id,kind=excluded.kind,
          target_path=excluded.target_path,reference_source_path=excluded.reference_source_path,
          live_sha=excluded.live_sha,reference_sha=excluded.reference_sha,silenced=excluded.silenced,has_run=excluded.has_run
         WHERE (module_id,kind,target_path,reference_source_path,live_sha,reference_sha,silenced,has_run)
           IS NOT (excluded.module_id,excluded.kind,excluded.target_path,excluded.reference_source_path,
                   excluded.live_sha,excluded.reference_sha,excluded.silenced,excluded.has_run)",
        params![feed_id,item.id,item.module_id,item.kind,item.target_path.as_ref().map(|p|p.to_string_lossy()),
            item.reference_source_path.as_ref().map(|p|p.to_string_lossy()),item.live_sha,item.reference_sha,item.silenced,item.has_run],
    ).map_err(database_error)?;
    Ok(())
}

fn proposal_rows_match(connection: &Connection, feed_id: &str, feed: &crate::interactables::InteractablesFeed) -> Result<bool, String> {
    let count: u64 = connection.query_row("SELECT count(*) FROM proposals WHERE feed_id=?1", [feed_id], |row| row.get(0)).map_err(database_error)?;
    if count != feed.interactables.len() as u64 { return Ok(false); }
    for item in &feed.interactables {
        let same: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM proposals WHERE feed_id=?1 AND id=?2
             AND (module_id,kind,target_path,reference_source_path,live_sha,reference_sha,silenced,has_run) IS (?3,?4,?5,?6,?7,?8,?9,?10))",
            params![feed_id,item.id,item.module_id,item.kind,item.target_path.as_ref().map(|p|p.to_string_lossy()),
                item.reference_source_path.as_ref().map(|p|p.to_string_lossy()),item.live_sha,item.reference_sha,item.silenced,item.has_run],
            |row| row.get(0)).map_err(database_error)?;
        if !same { return Ok(false); }
    }
    Ok(true)
}

pub(crate) fn filter_open_proposals(path: &Path, feed: &mut crate::interactables::InteractablesFeed) -> Result<(), String> {
    if let Some(seat) = crate::atoms::ask::mint_seats::feed_if_present()? {
        seat.validate_ruyi(&serde_json::to_value(&*feed).map_err(|error| error.to_string())?)?;
    }
    let feed_id = path.to_string_lossy();
    let observed = reader().ok().flatten();
    let connection = match observed {
        Some(connection) if proposal_rows_match(&connection, &feed_id, feed).unwrap_or(false) => connection,
        _ => {
            // A read must not repair disk or log itself. Rebuild the keyed reply
            // view from the feed; the next producer repairs the persistent rows.
            let connection = Connection::open_in_memory().map_err(database_error)?;
            connection.execute_batch(PROPOSALS_TABLE).map_err(database_error)?;
            connection.execute_batch(CONFIG_PROPOSALS_TABLE).map_err(database_error)?;
            project_proposal_rows(&connection, &feed_id, feed)?;
            connection
        }
    };
    for item in &mut feed.interactables {
        let (silenced, has_run) = connection.query_row(
            "SELECT silenced,has_run FROM proposals WHERE feed_id=?1 AND id=?2",
            params![feed_id,item.id], |row| Ok((row.get::<_,bool>(0)?,row.get::<_,bool>(1)?))).map_err(database_error)?;
        item.silenced = silenced;
        item.has_run = has_run;
    }
    Ok(())
}
