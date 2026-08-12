//! Indexed implementation spine for validated file-and-symlink promotion.
//!
//! The source remains one Rust privacy scope through `include!`, while each
//! independently named transaction boundary owns an indexed directory.

use crate::tools::files::{atomic_write_bytes, file_mode};
use crate::{CmdResult, OperationOutcome};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

include!("observe/index.rs");
include!("act/index.rs");
include!("report-home/index.rs");

#[cfg(test)]
#[path = "tests/index.rs"]
mod tests;
