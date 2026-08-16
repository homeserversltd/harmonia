use std::path::Path;

pub(crate) fn write_pinned_artifacts_receipt(
    path: &Path,
    value: &serde_json::Value,
) -> Result<(), String> {
    crate::write_json(path, value)
}
