//! Typed lchown owner actuator.
use crate::atoms::r#do::InvocationKey;
use crate::atoms::{Drift, Receipt};
use crate::atoms::comparison::ActionAuthorization;
use serde_json::{json, Value};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub path: PathBuf,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub no_follow: bool,
}
pub(crate) fn change(a: &ActionAuthorization, i: &InvocationKey, p: &Plan) -> Result<(), String> {
    if p.uid.is_none() && p.gid.is_none() {
        return Err("change-owner-owner-missing".into());
    };
    if !p.no_follow {
        return Err("change-owner-no-follow-required".into());
    };
    let c = CString::new(p.path.as_os_str().as_bytes())
        .map_err(|_| "change-owner-path-nul".to_string())?;
    let u = p.uid.map_or(!0, |v| v) as libc::uid_t;
    let g = p.gid.map_or(!0, |v| v) as libc::gid_t;
    if unsafe { libc::lchown(c.as_ptr(), u, g) } != 0 {
        return Err(format!(
            "change-owner-failed: {}",
            std::io::Error::last_os_error()
        ));
    };
    let _ = (a, i);
    Ok(())
}

/// Observe, compare, and conditionally change one target's ownership. The
/// InvocationKey is required at the mutation boundary; the typed atom closes
/// its own central receipt before returning a compatibility projection.
fn valid_metadata_preimage(preimage: &crate::atoms::ask::FsPreimage) -> Result<(), String> {
    if !preimage.present {
        return Err(format!(
            "files-metadata-target-absent {}",
            preimage.path.display()
        ));
    }
    match preimage.kind {
        Some(crate::atoms::ask::FsKind::File | crate::atoms::ask::FsKind::Directory) => Ok(()),
        Some(crate::atoms::ask::FsKind::Symlink) => Err(format!(
            "files-metadata-symlink-refused {}",
            preimage.path.display()
        )),
        _ => Err(format!(
            "files-metadata-target-kind-refused {}",
            preimage.path.display()
        )),
    }
}

fn metadata_state(observation: &crate::atoms::ask::change_owner::Observation) -> Value {
    let identity = observation
        .link_identity
        .map(|identity| json!({"device":identity.device,"inode":identity.inode}));
    json!({
        "path":observation.path,
        "exists":observation.preimage.present,
        "kind":format!("{:?}", observation.preimage.kind),
        "uid":observation.prior_uid,
        "gid":observation.prior_gid,
        "identity":identity,
    })
}

pub(crate) fn reconcile(
    plan: &Plan,
    apply: bool,
    invocation: Option<&InvocationKey>,
    receipt_log: &Path,
) -> Result<Value, String> {
    let desired_uid = plan.uid;
    let desired_gid = plan.gid;
    let mut observed_before = None;
    let mut compared_different = None;
    let mut movement_attempted = false;
    let run = crate::atoms::comparison::execute_once(
        "change-owner",
        || {
            let observation =
                crate::atoms::ask::change_owner::probe(&plan.path, desired_uid, desired_gid)?;
            observed_before = Some(observation.clone());
            valid_metadata_preimage(&observation.preimage)?;
            Ok(observation)
        },
        |observation| {
            let decision =
                if observation.prior_uid == desired_uid && observation.prior_gid == desired_gid {
                    crate::atoms::comparison::DiffDecision::Empty
                } else {
                    crate::atoms::comparison::DiffDecision::Different
                };
            compared_different =
                Some(decision == crate::atoms::comparison::DiffDecision::Different);
            decision
        },
        |authorization, _observation| -> Result<bool, String> {
            if !apply {
                return Ok(false);
            }
            let invocation =
                invocation.ok_or_else(|| "change-owner-invocation-key-missing".to_string())?;
            movement_attempted = true;
            change(&authorization, invocation, plan)?;
            Ok(true)
        },
    );
    let (observation, decision, attempted) = match run {
        Ok(crate::atoms::comparison::ComparisonRun::Current {
            observation,
            decision,
        }) => (observation, decision, false),
        Ok(crate::atoms::comparison::ComparisonRun::Moved {
            observation,
            decision,
            movement,
        }) => (observation, decision, movement),
        Err(error) => {
            let (after, readback_blocker) = if movement_attempted {
                match crate::atoms::ask::change_owner::probe(&plan.path, desired_uid, desired_gid) {
                    Ok(after) => {
                        let blocker = valid_metadata_preimage(&after.preimage).err();
                        (Some(after), blocker)
                    }
                    Err(error) => (None, Some(error)),
                }
            } else {
                (None, None)
            };
            let observed_state = observed_before.as_ref().map(metadata_state);
            let final_state = after.as_ref().map(metadata_state);
            let changed = match (observed_before.as_ref(), after.as_ref()) {
                (Some(before), Some(after)) => {
                    Some(before.prior_uid != after.prior_uid || before.prior_gid != after.prior_gid)
                }
                (_, _) if !movement_attempted => Some(false),
                _ => None,
            };
            let changed_value = changed.map_or(Value::Null, |changed| json!(changed));
            let diff_decision = match compared_different {
                Some(true) => "Different",
                Some(false) => "Empty",
                None => "blocked",
            };
            let movement = if movement_attempted {
                "attempted"
            } else {
                "none"
            };
            let proof = if compared_different.is_some() {
                "metadata-action-failed"
            } else {
                "metadata-observation-blocked"
            };
            let desired_state = json!({"uid":desired_uid,"gid":desired_gid});
            let evidence = json!({
                "observed_state":observed_state.clone(),
                "desired_state":desired_state.clone(),
                "diff_decision":diff_decision,
                "movement":movement,
                "changed":changed_value.clone(),
                "final_state":final_state.clone(),
                "blocker":error.clone(),
                "readback_blocker":readback_blocker.clone(),
            });
            let receipt = Receipt {
                atom: "change-owner".into(),
                ok: false,
                drift: Drift::Current,
                message: format!("path={} metadata-failure={evidence}", plan.path.display()),
            };
            crate::atoms::attest::attest(receipt_log, &receipt, &[])?;
            return Ok(json!({
                "atom":"change-owner", "ok":false,
                "observed_state":observed_state,
                "desired_state":desired_state,
                "diff_decision":diff_decision, "movement":movement,
                "final_state":final_state, "proof":proof, "blocker":error,
                "readback_blocker":readback_blocker,
                "changed":changed_value,
            }));
        }
    };
    let after = crate::atoms::ask::change_owner::probe(&plan.path, desired_uid, desired_gid);
    let (after_observation, after_error) = match after {
        Ok(after) => {
            let error = valid_metadata_preimage(&after.preimage).err();
            (Some(after), error)
        }
        Err(error) => (None, Some(error)),
    };
    let final_uid = after_observation.as_ref().and_then(|after| after.prior_uid);
    let final_gid = after_observation.as_ref().and_then(|after| after.prior_gid);
    let before_uid = observation.prior_uid;
    let before_gid = observation.prior_gid;
    let changed = after_observation
        .as_ref()
        .map(|after| before_uid != after.prior_uid || before_gid != after.prior_gid);
    let different = decision == crate::atoms::comparison::DiffDecision::Different;
    let mut blocker = after_error.unwrap_or_else(|| "none".into());
    if apply
        && different
        && blocker == "none"
        && (final_uid != desired_uid || final_gid != desired_gid)
    {
        blocker = "change-owner-act-did-not-converge".into();
    }
    let ok = blocker == "none";
    let movement = if !different {
        "none"
    } else if attempted {
        "attempted"
    } else {
        "report-only"
    };
    let diff_decision = if different { "Different" } else { "Empty" };
    let proof = if !ok && attempted {
        "metadata-action-failed"
    } else if !ok {
        "metadata-observation-blocked"
    } else if different && !apply {
        "report-only"
    } else if different {
        "metadata-readback"
    } else {
        "current"
    };
    let observed_state = metadata_state(&observation);
    let final_state = after_observation.as_ref().map(metadata_state);
    let receipt = Receipt {
        atom: "change-owner".into(),
        ok,
        drift: Drift::Current,
        message: format!(
            "path={} observed_uid={:?} observed_gid={:?} desired_uid={:?} desired_gid={:?} diff={} movement={} changed={:?} final_uid={:?} final_gid={:?} blocker={}",
            plan.path.display(), before_uid, before_gid, desired_uid, desired_gid,
            diff_decision, movement, changed, final_uid, final_gid, blocker
        ),
    };
    crate::atoms::attest::attest(receipt_log, &receipt, &[])?;
    Ok(json!({
        "atom":"change-owner", "ok":ok, "changed":changed,
        "observed_state":observed_state,
        "desired_state":{"uid":desired_uid,"gid":desired_gid},
        "diff_decision":diff_decision, "movement":movement,
        "final_state":final_state, "proof":proof, "blocker":blocker,
    }))
}
