pub(crate) use crate::atoms::r#do::remove_unit::*;

pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("remove-unit")
}
