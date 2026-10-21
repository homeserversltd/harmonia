//! The only knowledge of the retired receipt-stream format. Never follows links.
//! Kept at the migration boundary, outside the active writers and readers.
use rusqlite::OptionalExtension;
use std::path::Path;
use std::time::Instant;

const MIGRATION: &str = "retired-receipt-streams-v1";
const ROOT: &str = "/var/lib/harmonia/receipts";

fn sweep(directory: &Path) -> Result<u64, String> {
    let mut removed = 0;
    match std::fs::symlink_metadata(directory) {
        Err(error) if error.kind()==std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(format!("receipt-sweep-observe-failed: {error}")),
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => return Err("receipt-sweep-root-not-directory".into()),
        Ok(_) => {}
    }
    for item in std::fs::read_dir(directory).map_err(|error|format!("receipt-sweep-list-failed: {error}"))? {
        let item = item.map_err(|error|format!("receipt-sweep-entry-failed: {error}"))?;
        let kind = item.file_type().map_err(|error|format!("receipt-sweep-kind-failed: {error}"))?;
        let path = item.path();
        if kind.is_dir() { removed += sweep(&path)?; }
        else if (kind.is_file() || kind.is_symlink()) && path.extension().is_some_and(|extension|extension=="jsonl") {
            std::fs::remove_file(&path).map_err(|error|format!("receipt-sweep-remove-failed: {error}"))?;
            removed += 1;
        }
    }
    Ok(removed)
}

pub(crate) fn run() -> Result<(), String> {
    let observed = crate::ledger::reader()?;
    if let Some(connection) = observed.as_ref() {
        if connection.query_row("SELECT id FROM migrations WHERE id=?1",[MIGRATION],|row|row.get::<_,String>(0))
            .optional().map_err(|error|error.to_string())?.is_some() { return Ok(()); }
    }
    drop(observed);
    // Serialize first-run migration with every other Harmonia writer.
    let mut connection = crate::ledger::writer()?;
    let transaction = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error|error.to_string())?;
    let done: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM migrations WHERE id=?1)",[MIGRATION],|row|row.get(0))
        .map_err(|error|error.to_string())?;
    if done { return Ok(()); }
    let start = Instant::now();
    let removed = sweep(Path::new(ROOT))?;
    if removed>0 {
        crate::deeds::record("sweep-retired-receipts",ROOT,true,true,start.elapsed().as_millis(),None,None,None,Some(removed))?;
    }
    transaction.execute("INSERT INTO migrations(id) VALUES(?1)",[MIGRATION]).map_err(|error|error.to_string())?;
    transaction.commit().map_err(|error|error.to_string())
}
