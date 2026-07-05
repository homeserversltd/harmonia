use crate::module_dispatch::ModuleExecution;
use crate::*;
use std::path::Path;

pub(crate) const ID: &str = "coronatio";

const SPEC: tools::service_runtime::ServiceRuntimeSpec =
    tools::service_runtime::ServiceRuntimeSpec {
        op_prefix: "coronatio",
        run_schema: "harmonia.homeserver.coronatio_runtime.v1",
        managed_files_schema: "harmonia.homeserver.coronatio_managed_files.v1",
        source_op: "coronatio-source-git-artifact",
        source_sha_op: "coronatio-source-sha",
        managed_files_op: "coronatio-managed-files",
        build_op: "coronatio-cargo-build",
        binary_install_op: "coronatio-binary-install",
        service_stop_op: "coronatio-service-stop",
        daemon_reload_op: "coronatio-daemon-reload",
        service_enable_op: "coronatio-service-enable",
        service_active_op: "coronatio-service-active",
        service_op: "coronatio-service",
        health_op: "coronatio-health",
        binary_name: "coronatio",
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
