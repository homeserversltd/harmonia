//! Reversible validated file-and-symlink promotion transaction public face.
//!
//! The implementation lives in the recursively indexed transaction band.

#[path = "validated_file_symlink/index.rs"]
mod band;

pub(crate) use band::{execute, ValidatedFileSymlinkRequest};
