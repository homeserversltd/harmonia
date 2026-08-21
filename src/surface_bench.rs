use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

fn scratch(surface: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "harmonia-{surface}-{}",
        crate::run_id_from_stamp()
    ))
}
fn receipt(
    surface: &str,
    root: &Path,
    route: &str,
    outcome: serde_json::Value,
    key: bool,
) -> Result<(), String> {
    let ok = outcome.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let before = root.exists();
    let cleanup = fs::remove_dir_all(root).is_ok() && !root.exists();
    println!("{}", serde_json::to_string(&json!({"schema":format!("harmonia.{surface}-bench.v2"),"surface":surface,"production_route":route,"scratch_root":root,"authorized":key,"main_receipt":outcome,"actual_cleanup_observed":cleanup,"scratch_existed_before_cleanup":before,"ok":ok&&cleanup})).map_err(|e|e.to_string())?);
    if ok && cleanup {
        Ok(())
    } else {
        Err(format!("{surface}-bench-failed"))
    }
}
pub(crate) fn run(
    surface: &str,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
) -> Result<(), String> {
    let invocation = invocation.or_else(|| Some(crate::atoms::r#do::InvocationKey::for_apply()));
    let root = scratch(surface);
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let receipts = root.join("receipts");
    fs::create_dir_all(&receipts).map_err(|e| e.to_string())?;
    let key = invocation.is_some();
    match surface {
        "files-transaction" => receipt(
            surface,
            &root,
            "crate::atoms::files::files_bench",
            match crate::atoms::files::files_bench(&root, invocation) {
                Ok(v) => v,
                Err(e) => serde_json::json!({"ok":false,"error":e}),
            },
            key,
        ),
        "make-symlink" => receipt(
            surface,
            &root,
            "crate::tools::make_symlink::make_symlink_bench",
            crate::tools::make_symlink::make_symlink_bench(&root, invocation)?,
            key,
        ),
        "aur" => receipt(
            surface,
            &root,
            "crate::atoms::aur::aur_bench",
            match crate::atoms::aur::aur_bench(&root, invocation) {
                Ok(v) => v,
                Err(e) => serde_json::json!({"ok":false,"error":e}),
            },
            key,
        ),
        "git-artifact" => receipt(
            surface,
            &root,
            "crate::atoms::git_artifact::git_artifact_bench",
            match crate::atoms::git_artifact::git_artifact_bench(&root, invocation) {
                Ok(v) => v,
                Err(e) => serde_json::json!({"ok":false,"error":e}),
            },
            key,
        ),
        "systemd-unit" => receipt(
            surface,
            &root,
            "crate::atoms::systemd::systemd_bench",
            crate::atoms::systemd::systemd_bench(&root, invocation)?,
            key,
        ),
        "package" => receipt(
            surface,
            &root,
            "crate::atoms::package::package_bench",
            match crate::atoms::package::package_bench(&root, invocation) {
                Ok(v) => v,
                Err(e) => serde_json::json!({"ok":false,"error":e}),
            },
            key,
        ),
        "command" => receipt(
            surface,
            &root,
            "crate::atoms::command::command_bench",
            crate::atoms::command::command_bench(&root, invocation)?,
            key,
        ),
        "subscription-interactables" => receipt(
            surface,
            &root,
            "crate::subscription::subscription_bench",
            crate::subscription::subscription_bench(
                &root,
                invocation.unwrap_or_else(crate::atoms::r#do::InvocationKey::for_apply),
            )?,
            key,
        ),
        "ladder-profile" => receipt(
            surface,
            &root,
            "crate::tools::ladder::ladder_bench",
            crate::tools::ladder::ladder_bench(&root, invocation)?,
            key,
        ),
        "renew-self" => receipt(
            surface,
            &root,
            "crate::bands::renew_self::renew_self_bench",
            crate::bands::renew_self::renew_self_bench(&root, invocation)?,
            key,
        ),
        "capsule" => receipt(
            surface,
            &root,
            "crate::bands::stage_profile::capsule::capsule_bench",
            crate::bands::stage_profile::capsule::capsule_bench(
                &root,
                invocation.unwrap_or_else(crate::atoms::r#do::InvocationKey::for_apply),
            )?,
            key,
        ),
        "household-time" => receipt(
            surface,
            &root,
            "crate::tools::household_time::household_time_bench",
            crate::tools::household_time::household_time_bench(&root, invocation)?,
            key,
        ),
        _ => Err("unknown-bench-surface".into()),
    }
}
