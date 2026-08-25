//! Declaration and compatibility adapter for the set-clock atom.

pub(crate) use crate::atoms::r#do::set_clock::{run, Request};

pub fn declaration() -> Result<Option<&'static crate::tools::declaration::Declaration>, String> {
    crate::tools::declaration::get("set-clock")
}
