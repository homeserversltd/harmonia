use crate::atoms;
use serde_json::json;
pub(super) fn receipt(
    request: &super::Request<'_>,
    observation: &super::observe::Observation,
    apply: bool,
    changed: bool,
    movement: &str,
) -> Result<(), String> {
    crate::write_json(
        &request
            .receipt_dir
            .join(format!("{}.json", request.receipt_name)),
        &json!({
            "schema":"harmonia.venv.converge.v1", "ok":true, "apply":apply, "changed":changed,
            "venv":request.venv, "source_root":request.source_root, "dependency_files":observation.dependency_files,
            "dependency_sha256":observation.dependency_sha256, "previous_dependency_sha256":observation.previous_dependency_sha256,
            "diff_decision":if observation.different() {"different"} else {"empty"}, "movement":movement, "first_missing_signal":"none"
        }),
    )?;
    atoms::attest::attest(
        &request.receipt_dir.join("harmonia-atoms.log"),
        &atoms::Receipt {
            atom: "build-venv".into(),
            ok: true,
            drift: atoms::Drift::Current,
            message: format!(
                "dependency_sha256={}; previous_dependency_sha256={}; movement={movement}",
                observation.dependency_sha256.as_deref().unwrap_or("null"),
                observation
                    .previous_dependency_sha256
                    .as_deref()
                    .unwrap_or("null")
            ),
        },
        &[],
    )
}
