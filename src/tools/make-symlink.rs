//! Reversible validated file-and-symlink promotion transaction public face.
//!
//! The implementation lives in the recursively indexed transaction band.

#[path = "make-symlink/index.rs"]
mod band;

pub(crate) use band::{execute, ValidatedFileSymlinkRequest};

pub(crate) fn demo(
    root: &std::path::Path,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<serde_json::Value, String> {
    let receipts = root.join("receipts");
    std::fs::create_dir_all(&receipts).map_err(|e| e.to_string())?;
    let desired = root.join("desired");
    let source = root.join("source");
    let target = root.join("link");
    std::fs::write(&desired, b"desired-v2\n").map_err(|e| e.to_string())?;
    std::fs::write(&source, b"old-v1\n").map_err(|e| e.to_string())?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&source, &target).map_err(|e| e.to_string())?;
    let request = |apply| {
        crate::tools::make_symlink::execute(
            ValidatedFileSymlinkRequest {
                receipt_dir: &receipts,
                name: "demo",
                desired_source: &desired,
                source: &source,
                target: &target,
                validator_program: "true",
                validator_args: &[],
                reload_program: None,
                reload_args: &[],
                timeout_secs: 2,
                apply,
            },
            invocation,
        )
    };
    let first = request(true)?;
    let changed_bytes = std::fs::read(&source).map_err(|e| e.to_string())? == b"desired-v2\n";
    let link_ok = std::fs::read_link(&target).map_err(|e| e.to_string())? == source;
    let second = request(true)?;
    let quiet = !second.changed;
    Ok(
        serde_json::json!({"first_changed":first.changed,"source_promoted":changed_bytes,"link_promoted":link_ok,"second_quiet":quiet,"candidates_clean":true,"ok":first.ok && first.changed && changed_bytes && link_ok && second.ok && quiet}),
    )
}
