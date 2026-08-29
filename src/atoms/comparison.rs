//! Comparison is the kernel gate between cheap observation and costly action.
//!
//! The only constructors for `ActionAuthorization` and
//! `QuiescenceAuthorization` are private to this module.
//! Consequently an executor that uses `execute` has no action capability on an
//! empty comparison: the action closure is not invoked and cannot receive the
//! authorization value.
//! A Churning comparison cannot receive `QuiescenceAuthorization`; only the
//! real Settled branch mints it.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiffDecision {
    Empty,
    Different,
}

#[derive(Debug)]
pub(crate) struct ActionAuthorization(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuiescenceDecision {
    Settled,
    Churning,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct QuiescenceAuthorization(());

/// Compare commit-touch time against a lag window without observing anything.
pub(crate) fn quiescence(
    now: u64,
    last_commit_touch_ts: u64,
    lag_days: u64,
) -> (QuiescenceDecision, Option<QuiescenceAuthorization>) {
    let Some(lag_seconds) = lag_days.checked_mul(86_400) else {
        return (QuiescenceDecision::Churning, None);
    };
    if now < last_commit_touch_ts || now - last_commit_touch_ts < lag_seconds {
        (QuiescenceDecision::Churning, None)
    } else {
        (
            QuiescenceDecision::Settled,
            Some(QuiescenceAuthorization(())),
        )
    }
}

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

/// Runs one bounded plan command after a real comparison. This is for
/// planners whose dry-run action is intentionally non-converging: the action
/// still receives authorization only when the observed state differs.
pub(crate) fn execute_once<Observed, Movement, Error>(
    _operation: &str,
    mut observe: impl FnMut() -> Result<Observed, Error>,
    mut compare: impl FnMut(&Observed) -> DiffDecision,
    act: impl FnOnce(ActionAuthorization, &Observed) -> Result<Movement, Error>,
) -> Result<ComparisonRun<Observed, Movement>, Error>
where
    Error: From<String>,
{
    let observation = observe()?;
    match compare(&observation) {
        DiffDecision::Empty => Ok(ComparisonRun::Current {
            observation,
            decision: DiffDecision::Empty,
        }),
        DiffDecision::Different => Ok(ComparisonRun::Moved {
            movement: act(ActionAuthorization(()), &observation)?,
            observation,
            decision: DiffDecision::Different,
        }),
    }
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
pub(crate) fn execute_mode<Observed, Movement, Error>(
    operation: &str,
    mut observe: impl FnMut() -> Result<Observed, Error>,
    mut compare: impl FnMut(&Observed) -> DiffDecision,
    act: impl FnOnce(ActionAuthorization, &Observed) -> Result<Movement, Error>,
    require_convergence: bool,
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
            if !require_convergence {
                return Ok(ComparisonRun::Moved {
                    observation: observed_before,
                    decision: DiffDecision::Different,
                    movement,
                });
            }
            let observed_after = observe()?;
            if compare(&observed_after) == DiffDecision::Different {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_comparison_never_invokes_action() {
        let observed = execute(
            "unit",
            || Ok::<_, String>("synthetic-observed-state"),
            |_| DiffDecision::Empty,
            |_, _| -> Result<(), String> { panic!("empty comparison must not authorize action") },
        )
        .expect("empty comparison");
        assert_eq!(observed.decision(), DiffDecision::Empty);
        assert_eq!(observed.observation(), &"synthetic-observed-state");
    }

    #[test]
    fn different_comparison_authorizes_exactly_one_action() {
        let actions = std::cell::Cell::new(0);
        let result = execute_once(
            "unit",
            || Ok::<_, String>(7_u8),
            |_| DiffDecision::Different,
            |_, value| {
                actions.set(actions.get() + 1);
                assert_eq!(*value, 7);
                Ok::<_, String>("planned")
            },
        )
        .expect("different comparison");
        assert_eq!(actions.get(), 1);
        assert_eq!(result.decision(), DiffDecision::Different);
    }
}
