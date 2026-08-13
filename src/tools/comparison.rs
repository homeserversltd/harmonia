//! Comparison is the kernel gate between cheap observation and costly action.
//!
//! The only constructor for `ActionAuthorization` is private to this module.
//! Consequently an executor that uses `execute` has no action capability on an
//! empty comparison: the action closure is not invoked and cannot receive the
//! authorization value.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiffDecision {
    Empty,
    Different,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ActionAuthorization(());

#[derive(Debug)]
pub(crate) enum ComparisonRun<Observed, Movement> {
    Current {
        observation: Observed,
        decision: DiffDecision,
    },
    Moved {
        observation: Observed,
        decision: DiffDecision,
        movement: Movement,
    },
}

impl<Observed, Movement> ComparisonRun<Observed, Movement> {
    pub(crate) fn observation(&self) -> &Observed {
        match self {
            Self::Current { observation, .. } | Self::Moved { observation, .. } => observation,
        }
    }

    pub(crate) fn decision(&self) -> DiffDecision {
        match self {
            Self::Current { decision, .. } | Self::Moved { decision, .. } => *decision,
        }
    }
}

/// Runs Observe -> Compare -> Act-if-different.  `act` is structurally absent
/// from the empty branch: it can run only when this executor constructs the
/// private `ActionAuthorization` after a nonempty comparison.
pub(crate) fn execute<Observed, Movement, Error>(
    operation: &str,
    observe: impl FnMut() -> Result<Observed, Error>,
    compare: impl FnMut(&Observed) -> DiffDecision,
    act: impl FnOnce(ActionAuthorization, &Observed) -> Result<Movement, Error>,
) -> Result<ComparisonRun<Observed, Movement>, Error>
where
    Error: From<String>,
{
    execute_with_failure_receipt(
        operation,
        observe,
        compare,
        act,
        |_before, _movement, _after| Ok(()),
    )
}

/// Runs the comparison and gives the owner one last chance to persist the
/// complete guard receipt before a persistent post-act mismatch is returned.
pub(crate) fn execute_with_failure_receipt<Observed, Movement, Error>(
    operation: &str,
    mut observe: impl FnMut() -> Result<Observed, Error>,
    mut compare: impl FnMut(&Observed) -> DiffDecision,
    act: impl FnOnce(ActionAuthorization, &Observed) -> Result<Movement, Error>,
    write_failure_receipt: impl FnOnce(&Observed, &Movement, &Observed) -> Result<(), Error>,
) -> Result<ComparisonRun<Observed, Movement>, Error>
where
    Error: From<String>,
{
    let observed_before = observe()?;
    match compare(&observed_before) {
        DiffDecision::Empty => Ok(ComparisonRun::Current {
            observation: observed_before,
            decision: DiffDecision::Empty,
        }),
        DiffDecision::Different => {
            let movement = act(ActionAuthorization(()), &observed_before)?;
            let observed_after = observe()?;
            if compare(&observed_after) == DiffDecision::Different {
                write_failure_receipt(&observed_before, &movement, &observed_after)?;
                return Err(format!("{operation}-act-did-not-converge").into());
            }
            Ok(ComparisonRun::Moved {
                observation: observed_after,
                decision: DiffDecision::Different,
                movement,
            })
        }
    }
}
