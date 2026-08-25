//! Compatibility surface for the source-shelf operation owner.

// The transaction body lives in the existing do/source-shelf seat; this lane
// retains only the files-organ compatibility names used by older callers.
pub(crate) use crate::atoms::r#do::source_shelf::{
    source_shelf_sweep, SourceShelfSweepEntry, SourceShelfSweepOrphanRemoval,
    SourceShelfSweepOutcome, SourceShelfSweepRequest,
};
