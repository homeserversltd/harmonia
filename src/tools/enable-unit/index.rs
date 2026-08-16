pub(crate) use crate::atoms::r#do::enable_unit::*;

pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("enable-unit")
}
