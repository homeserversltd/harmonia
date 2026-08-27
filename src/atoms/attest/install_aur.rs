//! Typed receipt serialization for current-head AUR installation.
pub(crate) fn write(path: &std::path::Path, value: &serde_json::Value) -> Result<(), String> {
    crate::write_json(path, value)
}
