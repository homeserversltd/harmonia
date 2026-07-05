use crate::module_dispatch::ModuleExecution;
use crate::*;
use std::path::Path;

pub(crate) const ID: &str = "homeconsole-caduceus-public-lever";

const SPEC: tools::service_runtime::ServiceRuntimeSpec =
    tools::service_runtime::ServiceRuntimeSpec {
        op_prefix: "caduceus",
        run_schema: "harmonia.homeconsole.caduceus_public_lever.v1",
        managed_files_schema: "harmonia.homeconsole.caduceus_managed_files.v1",
        source_op: "caduceus-source-git-artifact",
        source_sha_op: "caduceus-source-sha",
        managed_files_op: "caduceus-managed-files",
        build_op: "caduceus-cargo-build",
        binary_install_op: "caduceus-binary-install",
        service_stop_op: "caduceus-service-stop",
        daemon_reload_op: "caduceus-daemon-reload",
        service_enable_op: "caduceus-service-enable",
        service_active_op: "caduceus-service-active",
        service_op: "caduceus-service",
        health_op: "caduceus-health",
        binary_name: "caduceus",
    };

pub(crate) fn validate(module: &ModuleManifest) -> Result<(), String> {
    tools::service_runtime::validate(module)
}

pub(crate) fn execute(
    module: &ModuleManifest,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    tools::service_runtime::execute(module, receipt_dir, apply, &SPEC)
}
