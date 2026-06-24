use crate::module_dispatch::{
    reject_executable_sidecar, require_packages, require_path, ModuleExecution,
};
use crate::*;
use serde_json::json;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

pub(crate) const ID: &str = "local-ai-runtime";
const SYSTEM_LLAMA_SERVER: &str = "/usr/bin/llama-server";
const SYSTEM_LLAMA_CLI: &str = "/usr/bin/llama-cli";
const LOCAL_LLAMA_SERVER: &str = "/usr/local/bin/llama-server";
const LOCAL_LLAMA_CLI: &str = "/usr/local/bin/llama-cli";
const LOCAL_AI_STATE_DIR: &str = "/var/lib/arcadia";

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    reject_executable_sidecar(module)?;
    require_packages(module)?;
    require_path(module, &module.path, "path")?;
    require_path(module, &module.install_bin, "install_bin")?;
    Ok(())
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    validate(module)?;
    let packages = package_tool(
        receipt_dir,
        "local-ai-package-install",
        "install",
        &module.packages,
        apply,
    )?;
    let model_dir = PathBuf::from(require_path(module, &module.path, "path")?);
    let dirs = local_ai_dirs(receipt_dir, &model_dir, apply)?;
    let links = local_ai_binary_links(receipt_dir, apply)?;
    let binary = local_ai_binary_readback(receipt_dir, apply)?;
    let service = local_ai_service_readback(
        receipt_dir,
        module
            .service
            .as_deref()
            .unwrap_or("arcadia-llama-server.service"),
    )?;

    write_json(
        &receipt_dir.join("local-ai-runtime.json"),
        &json!({
            "schema": "harmonia.local_ai_runtime.v1",
            "ok": packages.ok && dirs.ok && links.ok && binary.ok,
            "mutation": apply,
            "packages": module.packages,
            "model_dir": model_dir,
            "install_bin": require_path(module, &module.install_bin, "install_bin")?,
            "service": module.service,
            "health_url": module.url,
            "server_binary": LOCAL_LLAMA_SERVER,
            "cli_binary": LOCAL_LLAMA_CLI,
            "first_missing_signal": if !(packages.ok && dirs.ok && links.ok && binary.ok) { "local-ai-runtime-incomplete" } else { "none" }
        }),
    )?;

    let mut execution = ModuleExecution::from_operations(
        vec![
            ("local-ai-package-install", packages),
            ("local-ai-directories", dirs),
            ("local-ai-binary-links", links),
            ("local-ai-binary-readback", binary),
            ("local-ai-service-readback", service),
        ],
        &module.id,
    );
    if !execution.ok {
        execution.first_missing_signal = Some("local-ai-runtime-incomplete".to_string());
    }
    Ok(execution)
}

fn local_ai_dirs(
    receipt_dir: &Path,
    model_dir: &Path,
    apply: bool,
) -> Result<OperationOutcome, String> {
    if apply {
        fs::create_dir_all(model_dir)
            .map_err(|e| format!("model-dir-create-failed {}: {e}", model_dir.display()))?;
        fs::create_dir_all(LOCAL_AI_STATE_DIR)
            .map_err(|e| format!("state-dir-create-failed {LOCAL_AI_STATE_DIR}: {e}"))?;
    }
    let ok = !apply || (model_dir.is_dir() && Path::new(LOCAL_AI_STATE_DIR).is_dir());
    let outcome = OperationOutcome {
        ok,
        changed: apply,
        skipped: !apply,
        message: if ok {
            "local AI directories present"
        } else {
            "local AI directories missing"
        }
        .to_string(),
        command: None,
    };
    write_tool_receipt(
        receipt_dir,
        "local-ai-directories",
        "files",
        "ensure-directories",
        &outcome,
    )?;
    Ok(outcome)
}

fn local_ai_binary_links(receipt_dir: &Path, apply: bool) -> Result<OperationOutcome, String> {
    if !apply {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "llama.cpp compatibility links planned".to_string(),
            command: None,
        };
        write_tool_receipt(
            receipt_dir,
            "local-ai-binary-links",
            "files",
            "symlink",
            &outcome,
        )?;
        return Ok(outcome);
    }
    let mut ok = true;
    let mut changed = false;
    for (src, dst) in [
        (SYSTEM_LLAMA_SERVER, LOCAL_LLAMA_SERVER),
        (SYSTEM_LLAMA_CLI, LOCAL_LLAMA_CLI),
    ] {
        let src_path = Path::new(src);
        let dst_path = Path::new(dst);
        if !src_path.exists() {
            ok = false;
            continue;
        }
        if let Some(parent) = dst_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let existing = fs::read_link(dst_path).ok();
        if existing.as_deref() == Some(src_path) || dst_path.exists() {
            continue;
        }
        symlink(src_path, dst_path)
            .map_err(|e| format!("symlink-failed {} -> {}: {e}", dst, src))?;
        changed = true;
    }
    let outcome = OperationOutcome {
        ok,
        changed,
        skipped: false,
        message: if ok {
            "llama.cpp compatibility links present"
        } else {
            "llama.cpp packaged binaries missing"
        }
        .to_string(),
        command: None,
    };
    write_tool_receipt(
        receipt_dir,
        "local-ai-binary-links",
        "files",
        "symlink",
        &outcome,
    )?;
    Ok(outcome)
}

fn local_ai_binary_readback(receipt_dir: &Path, apply: bool) -> Result<OperationOutcome, String> {
    if !apply {
        let outcome = OperationOutcome {
            ok: true,
            changed: false,
            skipped: true,
            message: "llama-server version readback planned".to_string(),
            command: None,
        };
        write_tool_receipt(
            receipt_dir,
            "local-ai-binary-readback",
            "command",
            "version",
            &outcome,
        )?;
        return Ok(outcome);
    }
    let mut result = command_capture(LOCAL_LLAMA_SERVER, &["--version"]);
    if !result.ok
        && result.stderr.contains("Exec format error")
        && Path::new(SYSTEM_LLAMA_SERVER).exists()
    {
        result = command_capture(SYSTEM_LLAMA_SERVER, &["--version"]);
    }
    write_command_receipt(receipt_dir, "local-ai-binary-readback", &result)?;
    Ok(OperationOutcome {
        ok: result.ok,
        changed: false,
        skipped: false,
        message: if result.ok {
            "llama-server version read"
        } else {
            "llama-server version failed"
        }
        .to_string(),
        command: Some(result),
    })
}

fn local_ai_service_readback(
    receipt_dir: &Path,
    service: &str,
) -> Result<OperationOutcome, String> {
    let result = command_capture("/usr/bin/systemctl", &["status", service, "--no-pager"]);
    write_command_receipt(receipt_dir, "local-ai-service-readback", &result)?;
    Ok(OperationOutcome {
        ok: true,
        changed: false,
        skipped: !result.ok,
        message: if result.ok {
            "local AI service/transient unit readable"
        } else {
            "local AI service may be transient until a model is loaded"
        }
        .to_string(),
        command: Some(result),
    })
}
