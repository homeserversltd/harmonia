//! Harmonia's keyed application state. No receipt or envelope is stored here.
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

pub(crate) const DATABASE: &str = "/var/lib/harmonia/harmonia.sqlite3";
const ENTRY: &str = "harmonia.ledger.entry.v1";
const PAGE: &str = "caduceus.receipts.ledger.v1";

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
    Ok(Some(connection))
}

pub(crate) fn writer() -> Result<Connection, String> {
    let parent = Path::new(DATABASE).parent().unwrap();
    std::fs::create_dir_all(parent).map_err(|error| format!("harmonia-state-parent-failed: {error}"))?;
    match std::fs::symlink_metadata(DATABASE) {
        Ok(metadata) if !metadata.file_type().is_file() => return Err("harmonia-state-not-regular".into()),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(format!("harmonia-state-observe-failed: {error}")),
        _ => {}
    }
    let connection = Connection::open(DATABASE).map_err(database_error)?;
    connection.busy_timeout(Duration::from_secs(5)).map_err(database_error)?;
    // SQLite owns its DELETE journal. IF NOT EXISTS does not dirty an existing schema.
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS ledger (
            run_id TEXT NOT NULL, module_id TEXT NOT NULL, profile_id TEXT,
            module_version TEXT, ok INTEGER, changed INTEGER, operation_count INTEGER,
            first_missing_signal TEXT, recorded_at TEXT,
            PRIMARY KEY (run_id, module_id)
         );
         CREATE INDEX IF NOT EXISTS ledger_module ON ledger(module_id, recorded_at DESC);
         CREATE TABLE IF NOT EXISTS proposals (
            feed_id TEXT NOT NULL, id TEXT NOT NULL, module_id TEXT NOT NULL,
            kind TEXT NOT NULL, target_path TEXT, reference_source_path TEXT,
            live_sha TEXT, reference_sha TEXT, silenced INTEGER NOT NULL,
            has_run INTEGER NOT NULL, PRIMARY KEY(feed_id, id)
         );
         CREATE TABLE IF NOT EXISTS migrations (id TEXT PRIMARY KEY);"
    ).map_err(database_error)?;
    Ok(connection)
}

struct LedgerSeats {
    entry: Option<crate::atoms::ask::mint_seats::Seat>,
    page: Option<crate::atoms::ask::mint_seats::Seat>,
}

fn seats() -> Result<&'static LedgerSeats, String> {
    static SEATS: OnceLock<Result<LedgerSeats, String>> = OnceLock::new();
    SEATS.get_or_init(|| {
        let base = crate::atoms::ask::caduceus_door::base_url()?;
        Ok(LedgerSeats {
            entry: crate::atoms::ask::mint_seats::Seat::load_if_present(ENTRY, base)?,
            page: crate::atoms::ask::mint_seats::Seat::load_if_present(PAGE, base)?,
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

/// Keep only the newest material outcome for each module. A quiet success keeps
/// that outcome, not a new run-id/timestamp row; repeated identical failures do too.
pub(crate) fn record(
    profile: &crate::Profile, run_id: &str, entries: &[crate::receipts::ProfileLedgerEntry<'_>],
) -> Result<(), String> {
    let seats = seats()?;
    let observed = reader()?;
    let absent = unreported_absences(seats, observed.as_ref())?;
    let mut changes = Vec::new();
    for entry in entries {
        let prior: Option<(Option<String>, Option<String>, Option<bool>, Option<i64>, Option<String>)> =
            match observed.as_ref() {
                Some(connection) => connection.query_row(
                    "SELECT profile_id,module_version,ok,operation_count,first_missing_signal
                     FROM ledger WHERE module_id=?1 ORDER BY recorded_at DESC,run_id DESC LIMIT 1",
                    [entry.module_id],
                    |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
                ).optional().map_err(database_error)?,
                None => None,
            };
        let same_state = prior.as_ref().is_some_and(|prior| {
            prior.0.as_deref() == Some(profile.id.as_str())
                && prior.1.as_deref() == entry.module_version
                && prior.2 == Some(entry.ok)
                && prior.3 == i64::try_from(entry.operation_count).ok()
                && prior.4.as_deref() == Some(entry.first_missing_signal)
        });
        // A first all-current observation is not a deed. Recovery from a failed
        // outcome is a state transition, even when no software bytes moved.
        if !entry.changed && (same_state || (entry.ok && prior.is_none())) { continue; }
        let row = json!({
            "schema": ENTRY, "run_id": run_id, "module_id": entry.module_id,
            "profile_id": profile.id, "module_version": entry.module_version,
            "ok": entry.ok, "changed": entry.changed, "operation_count": entry.operation_count,
            "first_missing_signal": entry.first_missing_signal,
            "recorded_at": crate::bands::propose_edits::iso8601_now(),
        });
        if let Some(seat) = &seats.entry { seat.validate(&row)?; }
        changes.push(row);
    }
    drop(observed);
    if changes.is_empty() && absent.is_empty() { return Ok(()); }
    let mut connection = writer()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(database_error)?;
    let mut newly_absent = Vec::new();
    for id in absent {
        if transaction.execute("INSERT OR IGNORE INTO migrations(id) VALUES(?1)",
            [format!("schema-seat-absent:{id}")]).map_err(database_error)? > 0 {
            newly_absent.push(id);
        }
    }
    for row in changes {
        transaction.execute("DELETE FROM ledger WHERE module_id=?1 AND run_id<>?2",
            params![row["module_id"].as_str(),row["run_id"].as_str()]).map_err(database_error)?;
        transaction.execute(
            "INSERT INTO ledger(run_id,module_id,profile_id,module_version,ok,changed,operation_count,first_missing_signal,recorded_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
             ON CONFLICT(run_id,module_id) DO UPDATE SET profile_id=excluded.profile_id,
               module_version=excluded.module_version,ok=excluded.ok,changed=excluded.changed,
               operation_count=excluded.operation_count,first_missing_signal=excluded.first_missing_signal,
               recorded_at=excluded.recorded_at",
            params![row["run_id"].as_str(),row["module_id"].as_str(),row["profile_id"].as_str(),
                row["module_version"].as_str(),row["ok"].as_bool(),row["changed"].as_bool(),
                row["operation_count"].as_i64(),row["first_missing_signal"].as_str(),row["recorded_at"].as_str()],
        ).map_err(database_error)?;
    }
    transaction.commit().map_err(database_error)?;
    if !newly_absent.is_empty() {
        crate::deeds::record("schema-seat-absent", &newly_absent.join(":"), true, true,
            0, Some(run_id), None, Some("primitive-field-presence"), Some(newly_absent.len() as u64))?;
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
            "SELECT run_id,module_id,profile_id,module_version,ok,changed,operation_count,first_missing_signal,recorded_at
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
            });
            if let Some(seat) = &seats.entry { seat.validate(&entry)?; }
            entries.push(json!({"ordinal": total-offset-entries.len() as u64,"entry": entry}));
        }
    }
    let page = json!({"schema":PAGE,"ledgerPath":Value::Null,"module":module,
        "page":page,"perPage":per_page,"totalEntries":total,"totalPages":total_pages,
        "entries":entries,"ok":true,
        "firstMissingSignal":if total==0 {"caduceus-ledger-empty"} else {"none"}});
    if let Some(seat) = &seats.page { seat.validate(&page)?; }
    println!("{}", serde_json::to_string(&page).map_err(|error| error.to_string())?);
    Ok(())
}

/// The existing public feed remains the declaration/presentation surface. Rows
/// track only open identities and state; no diff, command payload or receipt is
/// copied into the database. Its loaded public feed seat governs this projection.
pub(crate) fn sync_proposals(path: &Path, feed: &crate::interactables::InteractablesFeed) -> Result<(), String> {
    let public_seat = crate::atoms::ask::mint_seats::interactables_at_start().feed.as_ref()
        .map_err(Clone::clone)?;
    public_seat.validate(&serde_json::to_value(feed).map_err(|error| error.to_string())?)?;
    let feed_id = path.to_string_lossy();
    let observed = reader()?;
    if observed.is_none() && feed.interactables.is_empty() { return Ok(()); }
    let mut connection = writer()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(database_error)?;
    for item in feed.interactables.iter().filter(|item| !item.has_run) {
        transaction.execute(
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
    }
    // Stream stale keys; never replay the store or save the public feed as a blob.
    let stale = {
        let mut query = transaction.prepare("SELECT id FROM proposals WHERE feed_id=?1").map_err(database_error)?;
        let rows = query.query_map([feed_id.as_ref()], |row|row.get::<_,String>(0)).map_err(database_error)?;
        let mut stale = Vec::new();
        for id in rows {
            let id = id.map_err(database_error)?;
            if !feed.interactables.iter().any(|item|item.id==id && !item.has_run) { stale.push(id); }
        }
        stale
    };
    for id in stale {
        transaction.execute("DELETE FROM proposals WHERE feed_id=?1 AND id=?2", params![feed_id,id]).map_err(database_error)?;
    }
    transaction.execute("INSERT OR IGNORE INTO migrations(id) VALUES(?1)",
        [format!("proposals-enrolled:{feed_id}")]).map_err(database_error)?;
    transaction.commit().map_err(database_error)
}

pub(crate) fn filter_open_proposals(path: &Path, feed: &mut crate::interactables::InteractablesFeed) -> Result<(), String> {
    let Some(connection) = reader()? else { return Ok(()); };
    let feed_id = path.to_string_lossy();
    // Until a legacy feed first changes, its declarations remain readable.
    let enrolled: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM migrations WHERE id=?1) OR EXISTS(SELECT 1 FROM proposals WHERE feed_id=?2)",
        params![format!("proposals-enrolled:{feed_id}"),feed_id.as_ref()], |row|row.get(0)).map_err(database_error)?;
    if !enrolled { return Ok(()); }
    let mut query = connection.prepare("SELECT EXISTS(SELECT 1 FROM proposals WHERE feed_id=?1 AND id=?2)").map_err(database_error)?;
    let mut kept = Vec::new();
    for item in feed.interactables.drain(..) {
        if item.has_run { continue; }
        let open: bool = query.query_row(params![feed_id,item.id],|row|row.get(0)).map_err(database_error)?;
        if !open {
            return Err(format!("harmonia-proposals-state-desync {}: retry the owning proposal write", item.id));
        }
        kept.push(item);
    }
    feed.interactables = kept;
    Ok(())
}
