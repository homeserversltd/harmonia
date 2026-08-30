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
pub(crate) struct CeilingAuthorization(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CeilingComparison {
    Empty,
    DifferentAndWithinCeiling,
    CeilingExceeded,
    Incomparable,
}

#[derive(Debug)]
pub(crate) enum CeilingComparisonRun<Observed, Movement> {
    Current { observation: Observed, comparison: CeilingComparison },
    Moved { observation: Observed, comparison: CeilingComparison, movement: Movement },
}

impl<Observed, Movement> CeilingComparisonRun<Observed, Movement> {
    pub(crate) fn observation(&self) -> &Observed {
        match self {
            Self::Current { observation, .. } | Self::Moved { observation, .. } => observation,
        }
    }
    pub(crate) fn comparison(&self) -> CeilingComparison {
        match self {
            Self::Current { comparison, .. } | Self::Moved { comparison, .. } => *comparison,
        }
    }
}

pub(crate) fn execute_with_ceiling<Observed, Movement, Error>(
    _operation: &str,
    mut observe: impl FnMut() -> Result<Observed, Error>,
    mut compare: impl FnMut(&Observed) -> CeilingComparison,
    act: impl FnOnce(ActionAuthorization, CeilingAuthorization, &Observed) -> Result<Movement, Error>,
) -> Result<CeilingComparisonRun<Observed, Movement>, Error>
where
    Error: From<String>,
{
    let observation = observe()?;
    let comparison = compare(&observation);
    match comparison {
        CeilingComparison::Empty
        | CeilingComparison::CeilingExceeded
        | CeilingComparison::Incomparable => Ok(CeilingComparisonRun::Current { observation, comparison }),
        CeilingComparison::DifferentAndWithinCeiling => Ok(CeilingComparisonRun::Moved {
            movement: act(ActionAuthorization(()), CeilingAuthorization(()), &observation)?,
            observation,
            comparison,
        }),
    }
}

/// Ceiling variant with an optional post-action observation and ordered failure receipt.
pub(crate) fn execute_with_ceiling_failure_receipt<Observed, Movement, Error>(
    operation: &str,
    mut observe: impl FnMut() -> Result<Observed, Error>,
    mut compare: impl FnMut(&Observed) -> CeilingComparison,
    act: impl FnOnce(ActionAuthorization, CeilingAuthorization, &Observed) -> Result<Movement, Error>,
    require_convergence: bool,
    write_failure_receipt: impl FnOnce(&Observed, &Movement, &Observed) -> Result<(), Error>,
) -> Result<CeilingComparisonRun<Observed, Movement>, Error>
where Error: From<String> {
    let before = observe()?;
    let comparison = compare(&before);
    if !matches!(comparison, CeilingComparison::DifferentAndWithinCeiling) {
        return Ok(CeilingComparisonRun::Current { observation: before, comparison });
    }
    let movement = act(ActionAuthorization(()), CeilingAuthorization(()), &before)?;
    if !require_convergence {
        return Ok(CeilingComparisonRun::Moved { observation: before, comparison, movement });
    }
    let after = observe()?;
    if !matches!(compare(&after), CeilingComparison::Empty) {
        write_failure_receipt(&before, &movement, &after)?;
        return Err(format!("{operation}-ceiling-act-did-not-converge").into());
    }
    Ok(CeilingComparisonRun::Moved { observation: after, comparison: CeilingComparison::Empty, movement })
}

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

    #[test]
    fn package_ceiling_empty_never_invokes_action() {
        let result = execute_with_ceiling("package", || Ok::<_, String>(1_u8), |_| CeilingComparison::Empty, |_, _, _| -> Result<(), String> { panic!("ceiling empty action") });
        assert_eq!(result.unwrap().comparison(), CeilingComparison::Empty);
    }

    #[test]
    fn package_ceiling_within_requires_both_authorizations() {
        let result = execute_with_ceiling("package", || Ok::<_, String>(2_u8), |_| CeilingComparison::DifferentAndWithinCeiling, |_, _, value| Ok::<_, String>(*value + 1)).unwrap();
        assert!(matches!(result, CeilingComparisonRun::Moved { movement: 3, .. }));
    }

    #[test]
    fn package_ceiling_exceeded_preserves_state_and_blocks_action() {
        let result = execute_with_ceiling::<_, (), String>("package", || Ok(9_u8), |_| CeilingComparison::CeilingExceeded, |_, _, _| panic!("exceeded action"));
        assert_eq!(result.unwrap().comparison(), CeilingComparison::CeilingExceeded);
    }

    #[test]
    fn package_ceiling_incomparable_is_named_blocker() {
        let result = execute_with_ceiling::<_, (), String>("package", || Ok(9_u8), |_| CeilingComparison::Incomparable, |_, _, _| panic!("incomparable action"));
        assert_eq!(result.unwrap().comparison(), CeilingComparison::Incomparable);
    }

}
