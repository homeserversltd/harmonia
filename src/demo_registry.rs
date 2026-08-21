use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

fn scratch(surface: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "harmonia-demo-{surface}-{}",
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
    println!("{}", serde_json::to_string(&json!({"schema":format!("harmonia.{surface}-demo.v2"),"surface":surface,"production_route":route,"scratch_root":root,"authorized":key,"main_receipt":outcome,"actual_cleanup_observed":cleanup,"scratch_existed_before_cleanup":before,"ok":ok&&cleanup})).map_err(|e|e.to_string())?);
    if ok && cleanup {
        Ok(())
    } else {
        Err(format!("{surface}-demo-failed"))
    }
}
pub(crate) const NAMES: &[&str] = &[
    "files-transaction",
    "make-symlink",
    "aur",
    "git-artifact",
    "systemd-unit",
    "package",
    "command",
    "subscription-interactables",
    "ladder-profile",
    "renew-self",
    "capsule",
    "household-time",
    "stillness",
    "proposal-refresh",
    "structural-wall",
    "foundation",
    "update-set",
    "clock",
    "renew-schedule",
];

pub(crate) fn run(
    surface: &str,
    invocation: Option<crate::atoms::r#do::InvocationKey>,
    context: Option<crate::RunContext>,
) -> Result<(), String> {
    let invocation = invocation.or_else(|| Some(crate::atoms::r#do::InvocationKey::for_apply()));
    let direct_surface = matches!(
        surface,
        "files-transaction"
            | "make-symlink"
            | "aur"
            | "git-artifact"
            | "systemd-unit"
            | "package"
            | "command"
            | "subscription-interactables"
            | "ladder-profile"
            | "renew-self"
            | "capsule"
            | "household-time"
    );
    let root = scratch(surface);
    if direct_surface {
        fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let receipts = root.join("receipts");
        fs::create_dir_all(&receipts).map_err(|e| e.to_string())?;
    }
    let authorized = invocation.is_some();
    let result = match surface {
        "files-transaction" => receipt(
            surface,
            &root,
            "crate::atoms::files::demo",
            match crate::atoms::files::demo(&root, invocation) {
                Ok(v) => v,
                Err(e) => serde_json::json!({"ok":false,"error":e}),
            },
            authorized,
        ),
        "make-symlink" => receipt(
            surface,
            &root,
            "crate::tools::make_symlink::demo",
            crate::tools::make_symlink::demo(&root, invocation)?,
            authorized,
        ),
        "aur" => receipt(
            surface,
            &root,
            "crate::atoms::aur::demo",
            match crate::atoms::aur::demo(&root, invocation) {
                Ok(v) => v,
                Err(e) => serde_json::json!({"ok":false,"error":e}),
            },
            authorized,
        ),
        "git-artifact" => receipt(
            surface,
            &root,
            "crate::atoms::git_artifact::demo",
            match crate::atoms::git_artifact::demo(&root, invocation) {
                Ok(v) => v,
                Err(e) => serde_json::json!({"ok":false,"error":e}),
            },
            authorized,
        ),
        "systemd-unit" => receipt(
            surface,
            &root,
            "crate::atoms::systemd::demo",
            crate::atoms::systemd::demo(&root, invocation)?,
            authorized,
        ),
        "package" => receipt(
            surface,
            &root,
            "crate::atoms::package::demo",
            match crate::atoms::package::demo(&root, invocation) {
                Ok(v) => v,
                Err(e) => serde_json::json!({"ok":false,"error":e}),
            },
            authorized,
        ),
        "command" => receipt(
            surface,
            &root,
            "crate::atoms::command::demo",
            crate::atoms::command::demo(&root, invocation)?,
            authorized,
        ),
        "subscription-interactables" => receipt(
            surface,
            &root,
            "crate::subscription::demo",
            crate::subscription::demo(
                &root,
                invocation.unwrap_or_else(crate::atoms::r#do::InvocationKey::for_apply),
            )?,
            authorized,
        ),
        "ladder-profile" => receipt(
            surface,
            &root,
            "crate::tools::ladder::demo",
            crate::tools::ladder::demo(&root, invocation)?,
            authorized,
        ),
        "renew-self" => receipt(
            surface,
            &root,
            "crate::bands::renew_self::demo",
            crate::bands::renew_self::demo(&root, invocation)?,
            authorized,
        ),
        "capsule" => receipt(
            surface,
            &root,
            "crate::bands::stage_profile::capsule::demo",
            crate::bands::stage_profile::capsule::demo(
                &root,
                invocation.unwrap_or_else(crate::atoms::r#do::InvocationKey::for_apply),
            )?,
            authorized,
        ),
        "household-time" => receipt(
            surface,
            &root,
            "crate::tools::household_time::demo",
            crate::tools::household_time::demo(&root, invocation)?,
            authorized,
        ),
        "update-set" => crate::atoms::r#do::transaction::update_set_demo(
            &[],
            context.ok_or("update-set-invocation-context-missing")?,
        ),
        "foundation" => crate::atoms::r#do::ritual::demo(
            &[],
            context.ok_or("foundation-invocation-context-missing")?,
        ),
        "renew-schedule" => crate::stillness_demo::renew_schedule_demo(
            invocation.ok_or("renew-schedule-invocation-key-missing")?,
        ),
        "clock" => {
            crate::stillness_demo::clock_demo(invocation.ok_or("clock-invocation-key-missing")?)
        }
        "stillness" => crate::stillness_demo::run(invocation),
        "proposal-refresh" => crate::bands::propose_edits::proposal_refresh_demo(),
        "structural-wall" => crate::structural_wall_demo::run(invocation),
        _ => Err("unknown-demo-surface".into()),
    };
    if direct_surface {
        let _ = fs::remove_dir_all(&root);
    }
    result
}
