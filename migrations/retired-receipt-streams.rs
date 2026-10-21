//! The retired format's confined, apply-only compatibility boundary.
use rusqlite::OptionalExtension;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

const MIGRATION: &str = "retired-receipt-streams-v2-confined";
const ROOT: &str = "/var/lib/harmonia/receipts";
const OLD_MIGRATION: &str = "retired-receipt-streams-v1";

fn remove(path: &Path, removed: &mut u64) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => { *removed += 1; Ok(()) }
        Err(error) if error.kind()==std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("receipt-sweep-remove-failed".into()),
    }
}

fn sweep(directory: &Path, device: u64, mounts: &[PathBuf], removed: &mut u64) -> Result<(), String> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind()==std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("receipt-sweep-list-failed".into()),
    };
    for item in entries {
        let item = match item {
            Ok(item) => item,
            Err(error) if error.kind()==std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err("receipt-sweep-entry-failed".into()),
        };
        let path = item.path();
        if mounts.iter().any(|mount| mount==&path) { continue; }
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind()==std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err("receipt-sweep-kind-failed".into()),
        };
        if metadata.dev()!=device { continue; }
        if metadata.is_dir() {
            sweep(&path, device, mounts, removed)?;
        } else if metadata.is_file() || metadata.file_type().is_symlink() {
            let name = item.file_name();
            let name = name.to_string_lossy();
            let lock = directory==Path::new(ROOT) && name.strip_prefix('.')
                .and_then(|name| name.strip_suffix("-ledger.jsonl.lock"))
                .is_some_and(|profile| !profile.is_empty());
            if name.ends_with(".jsonl") || lock { remove(&path, removed)?; }
        }
    }
    Ok(())
}

fn walk(removed: &mut u64) -> Result<(), String> {
    match std::fs::symlink_metadata(ROOT) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            let mounts = crate::atoms::attest::convergence_receipts::mountpoints_beneath(Path::new(ROOT))?;
            sweep(Path::new(ROOT), metadata.dev(), &mounts, removed)?;
        }
        Ok(_) => return Err("receipt-sweep-root-not-directory".into()),
        Err(error) if error.kind()==std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("receipt-sweep-observe-failed".into()),
    }
    let extra = Path::new("/var/lib/harmonia/proposals.attest.jsonl");
    match std::fs::symlink_metadata(extra) {
        Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
            let mounts = crate::atoms::attest::convergence_receipts::mountpoints_beneath(extra)?;
            if !mounts.iter().any(|mount| mount==extra) { remove(extra, removed)?; }
        }
        Ok(_) => return Err("receipt-sweep-extra-not-file".into()),
        Err(error) if error.kind()==std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("receipt-sweep-extra-observe-failed".into()),
    }
    Ok(())
}

pub(crate) fn run() -> Result<(), String> {
    let observed = crate::ledger::reader()?;
    let done = match observed.as_ref() {
        Some(connection) => connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM migrations WHERE id=?1)", [MIGRATION], |row| row.get::<_,bool>(0))
            .map_err(|_| "receipt-sweep-state-read-failed")?,
        None => false,
    };
    if done { return Ok(()); }
    drop(observed);
    let start = Instant::now();
    let mut removed = 0;
    // No SQLite write lock is held during filesystem observation/removal.
    let result = walk(&mut removed);
    let mut connection = crate::ledger::writer()?;
    let transaction = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| "receipt-sweep-state-lock-failed")?;
    if removed>0 {
        transaction.execute("INSERT INTO deed_outbox(id,count) VALUES(?1,?2)
            ON CONFLICT(id) DO UPDATE SET count=count+excluded.count", rusqlite::params![MIGRATION,removed])
            .map_err(|_| "receipt-sweep-state-count-failed")?;
    }
    // Carry an unacknowledged old handoff forward, but never repeat its sweep.
    transaction.execute("INSERT INTO deed_outbox(id,count) SELECT ?1,count FROM deed_outbox WHERE id=?2
        ON CONFLICT(id) DO UPDATE SET count=count+excluded.count", rusqlite::params![MIGRATION,OLD_MIGRATION])
        .map_err(|_| "receipt-sweep-state-count-failed")?;
    transaction.execute("DELETE FROM deed_outbox WHERE id=?1", [OLD_MIGRATION])
        .map_err(|_| "receipt-sweep-state-count-failed")?;
    transaction.commit().map_err(|_| "receipt-sweep-state-commit-failed")?;
    result?;

    // Recheck/ack under the lock; competing walkers count only actual unlinks.
    let transaction = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| "receipt-sweep-state-lock-failed")?;
    let pending: Option<u64> = transaction.query_row("SELECT count FROM deed_outbox WHERE id=?1", [MIGRATION], |row| row.get(0))
        .optional().map_err(|_| "receipt-sweep-state-read-failed")?;
    let delivered = pending.is_none_or(|count| crate::deeds::record_delivery("sweep-retired-receipts", ROOT,
        true, true, Some(start.elapsed().as_millis()), None, None, None, Some(count)));
    if delivered {
        transaction.execute("INSERT OR IGNORE INTO migrations(id) VALUES(?1)", [MIGRATION])
            .map_err(|_| "receipt-sweep-state-marker-failed")?;
        transaction.execute("DELETE FROM deed_outbox WHERE id=?1", [MIGRATION])
            .map_err(|_| "receipt-sweep-state-ack-failed")?;
    }
    transaction.commit().map_err(|_| "receipt-sweep-state-commit-failed".into())
}
