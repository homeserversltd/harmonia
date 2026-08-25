//! Declaration/ritual adapter for the backfill-file atom.
#![allow(dead_code)]
pub(crate) use crate::atoms::r#do::backfill_file::{
    execute, observe_predicate, resolve_ownership, BackfillFileRequest, BackupPolicy,
    DeclaredOwnership,
};
