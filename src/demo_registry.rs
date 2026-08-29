pub(crate) const NAMES: &[&str] = &["quiescence"];

pub(crate) fn run(surface: &str) -> Result<(), String> {
    match surface {
        "quiescence" => quiescence_demo(),
        _ => Err("unknown-demo-surface".into()),
    }
}

fn quiescence_demo() -> Result<(), String> {
    const LAST_COMMIT_TOUCH_TS: u64 = 0;
    const LAG_DAYS: u64 = 15;
    const BOUNDARY_NOW: u64 = LAG_DAYS * 86_400;
    const CHURNING_NOW: u64 = 14 * 86_400;

    let (settled_decision, settled_authorization) =
        crate::atoms::comparison::quiescence(BOUNDARY_NOW, LAST_COMMIT_TOUCH_TS, LAG_DAYS);
    let (churning_decision, churning_authorization) =
        crate::atoms::comparison::quiescence(CHURNING_NOW, LAST_COMMIT_TOUCH_TS, LAG_DAYS);
    let checks_pass = settled_decision == crate::atoms::comparison::QuiescenceDecision::Settled
        && settled_authorization.is_some()
        && churning_decision == crate::atoms::comparison::QuiescenceDecision::Churning
        && churning_authorization.is_none();
    let receipt = serde_json::json!({
        "schema": "harmonia.demo.quiescence.v1",
        "name": "quiescence",
        "boundary": {"now": BOUNDARY_NOW, "last_commit_touch_ts": LAST_COMMIT_TOUCH_TS, "lag_days": LAG_DAYS, "decision": format!("{settled_decision:?}"), "authorization": settled_authorization.is_some()},
        "fourteen_days": {"now": CHURNING_NOW, "last_commit_touch_ts": LAST_COMMIT_TOUCH_TS, "lag_days": LAG_DAYS, "decision": format!("{churning_decision:?}"), "authorization": churning_authorization.is_some()},
        "ok": checks_pass
    });
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|e| e.to_string())?
    );
    if checks_pass {
        Ok(())
    } else {
        Err("quiescence-demo-check-failed".to_string())
    }
}
