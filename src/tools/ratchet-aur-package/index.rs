pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("ratchet-aur-package")
}
