//! Observation-only health organ: there is intentionally no act module.
use crate::CmdResult;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn probe(request: &crate::atoms::health::ProbeRequest<'_>) -> CmdResult {
    let result = crate::atoms::health::curl_probe(request);
    result
}

/// Explicit engine proof request.  The health organ owns the proof battery;
/// renew-self only decides whether this request is required.
pub(crate) struct ProofBatteryRequest<'a> {
    pub receipt_dir: &'a Path,
    pub staged: &'a Path,
    pub module_root: &'a Path,
    pub profile_index: &'a Path,
    pub apply: bool,
}

fn sorted_ladder_manifests(module_root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut manifests = Vec::new();
    if module_root.is_dir() {
        for entry in fs::read_dir(module_root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let manifest = entry.path().join("manifest.json");
            if manifest.exists() {
                manifests.push(manifest);
            }
        }
    }
    manifests.sort();
    Ok(manifests)
}

fn run_proof_command(program: &Path, args: &[String], apply: bool) -> CmdResult {
    if !apply {
        return CmdResult {
            ok: true,
            code: 0,
            stdout: format!("planned: {} {}", program.display(), args.join(" ")),
            stderr: String::new(),
        };
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    crate::atoms::command::capture_with_cwd(&program.to_string_lossy(), &refs, None)
}

pub(crate) fn proof_battery(
    request: &ProofBatteryRequest<'_>,
) -> Result<(bool, Option<String>, usize), String> {
    let mut operations = 0usize;
    let staged = request.staged;
    let explain = run_proof_command(staged, &["explain".into()], request.apply);
    crate::atoms::attest::check_health::write_proof_receipt(
        request.receipt_dir,
        "proof-explain",
        &explain,
    )?;
    operations += 1;
    if !explain.ok {
        return Ok((
            false,
            Some("engine-proof-explain-failed".into()),
            operations,
        ));
    }

    let manifests = sorted_ladder_manifests(request.module_root)?;
    if manifests.is_empty() {
        let missing = CmdResult {
            ok: false,
            code: -1,
            stdout: String::new(),
            stderr: format!(
                "deployed-spine-ladder-manifest-missing {}",
                request.module_root.display()
            ),
        };
        crate::atoms::attest::check_health::write_proof_receipt(
            request.receipt_dir,
            "proof-validate-ladder",
            &missing,
        )?;
        operations += 1;
        return Ok((
            false,
            Some("engine-proof-validate-ladder-failed".into()),
            operations,
        ));
    }
    for (index, manifest) in manifests.iter().enumerate() {
        let name = if index == 0 {
            "proof-validate-ladder".to_string()
        } else {
            format!("proof-validate-ladder-{index}")
        };
        let validate = run_proof_command(
            staged,
            &[
                "validate-ladder".into(),
                manifest.to_string_lossy().into_owned(),
            ],
            request.apply,
        );
        crate::atoms::attest::check_health::write_proof_receipt(
            request.receipt_dir,
            &name,
            &validate,
        )?;
        operations += 1;
        if !validate.ok {
            return Ok((
                false,
                Some("engine-proof-validate-ladder-failed".into()),
                operations,
            ));
        }
    }

    let plan_receipts = request.receipt_dir.join("proof-plan-run-receipts");
    let plan = run_proof_command(
        staged,
        &[
            "plan-run".into(),
            request.profile_index.to_string_lossy().into_owned(),
            "--receipt-dir".into(),
            plan_receipts.to_string_lossy().into_owned(),
        ],
        request.apply,
    );
    crate::atoms::attest::check_health::write_proof_receipt(
        request.receipt_dir,
        "proof-plan-run",
        &plan,
    )?;
    operations += 1;
    if !plan.ok {
        return Ok((
            false,
            Some("engine-proof-plan-run-failed".into()),
            operations,
        ));
    }
    Ok((true, None, operations))
}
