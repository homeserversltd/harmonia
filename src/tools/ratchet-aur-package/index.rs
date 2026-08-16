pub(crate) use crate::atoms::r#do::ratchet_aur::*;

pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("ratchet-aur-package")
}
