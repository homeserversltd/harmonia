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
    observe: impl FnOnce() -> Result<Observed, Error>,
    compare: impl FnOnce(&Observed) -> DiffDecision,
    act: impl FnOnce(ActionAuthorization, &Observed) -> Result<Movement, Error>,
) -> Result<ComparisonRun<Observed, Movement>, Error> {
    let observation = observe()?;
    match compare(&observation) {
        DiffDecision::Empty => Ok(ComparisonRun::Current {
            observation,
            decision: DiffDecision::Empty,
        }),
        DiffDecision::Different => {
            let movement = act(ActionAuthorization(()), &observation)?;
            Ok(ComparisonRun::Moved {
                observation,
                decision: DiffDecision::Different,
                movement,
            })
        }
    }
}
