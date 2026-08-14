use super::Band;
use crate::ladder::{LadderManifest, RoutineStep};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) fn enter(enter: &mut impl FnMut(Band) -> Result<(), String>) -> Result<(), String> {
    enter(Band::RestartServices)
}

pub(crate) fn lower_service_runtime_steps(manifest: &mut LadderManifest) {
    for step in &mut manifest.ladder {
        if step.tool != "service-runtime" || step.permutation != "converge" {
            continue;
        }
        let args = step.args.clone();
        let mut pull = BTreeMap::new();
        if let Some(v) = args.get("component") {
            pull.insert("component".into(), v.clone());
        }
        pull.insert(
            "bearer".into(),
            args.get("bearer")
                .cloned()
                .unwrap_or_else(|| Value::String("owner".into())),
        );
        pull.insert(
            "path".into(),
            args.get("source_dir")
                .cloned()
                .unwrap_or_else(|| Value::String(String::new())),
        );
        let stages = [
            ("pull-repo", "pull-repo", "acquire"),
            ("build", "build-crate", "build"),
            ("binary-install", "place-file", "binary-promotion"),
            ("managed-files", "service-runtime", "managed-files"),
            ("service-daemon-reload", "systemd", "daemon-reload"),
            ("service-enable", "enable-unit", "enable"),
            ("service-restart", "systemd", "restart"),
            ("service-active", "systemd", "is-active-probe"),
            ("health-proof", "check-health", "probe"),
        ];
        step.tool = "routine".into();
        step.permutation = "execute".into();
        step.args.clear();
        step.steps = stages
            .into_iter()
            .map(|(name, tool, permutation)| {
                let child_args = match name {
                    "pull-repo" => pull.clone(),
                    "build" => {
                        let mut c = args.clone();
                        if let Some(v) = args.get("component") {
                            c.insert("component".into(), v.clone());
                        }
                        c.insert("cwd".into(), serde_json::json!({"from":"pull-repo.path"}));
                        c.insert(
                            "source_build_sha".into(),
                            serde_json::json!({"from":"pull-repo.resolved_commit"}),
                        );
                        c.insert(
                            "installed_binary".into(),
                            args.get("install_bin")
                                .cloned()
                                .unwrap_or(Value::String(String::new())),
                        );
                        c.insert(
                            "artifact_name".into(),
                            args.get("binary_name")
                                .cloned()
                                .unwrap_or(Value::String(String::new())),
                        );
                        c.insert(
                            "bearer".into(),
                            args.get("bearer")
                                .cloned()
                                .unwrap_or_else(|| Value::String("owner".into())),
                        );
                        if let Some(v) = args.get("build_environment") {
                            c.insert("environment".into(), v.clone());
                        }
                        if let Some(op) = args.get("op_prefix").and_then(Value::as_str) {
                            c.insert(
                                "legacy_build_receipt".into(),
                                Value::String(format!("{op}-cargo-build")),
                            );
                        }
                        c
                    }
                    "binary-install" => {
                        let mut c = args.clone();
                        c.insert(
                            "path".into(),
                            args.get("install_bin")
                                .cloned()
                                .unwrap_or(Value::String(String::new())),
                        );
                        c.insert(
                            "source_path".into(),
                            serde_json::json!({"from":"build.artifact"}),
                        );
                        c.insert("mode".into(), Value::from(493_u64));
                        if let Some(op) = args.get("op_prefix").and_then(Value::as_str) {
                            c.insert(
                                "legacy_binary_install_receipt".into(),
                                Value::String(format!("{op}-binary-install")),
                            );
                        }
                        c
                    }
                    "service-daemon-reload"
                    | "service-enable"
                    | "service-restart"
                    | "service-active" => {
                        let mut c = args.clone();
                        for (k, r) in [
                            ("source_dir", "pull-repo.path"),
                            ("source_sha", "pull-repo.resolved_commit"),
                            ("source_reference", "pull-repo.source_reference"),
                            ("source_remote", "pull-repo.source_remote"),
                            ("source_changed", "pull-repo.changed"),
                            ("binary_changed", "binary-install.changed"),
                            ("managed_files_changed", "managed-files.changed"),
                        ] {
                            c.insert(k.into(), serde_json::json!({"from":r}));
                        }
                        c.insert(
                            "user".into(),
                            args.get("user").cloned().unwrap_or(Value::Bool(false)),
                        );
                        if name == "service-active" {
                            c.insert(
                                "binary_changed".into(),
                                serde_json::json!({"from":"binary-install.changed"}),
                            );
                            c.insert(
                                "managed_files_changed".into(),
                                serde_json::json!({"from":"managed-files.changed"}),
                            );
                        }
                        if let Some(policy) = args.get("restart_policy") {
                            c.insert("restart_policy".into(), policy.clone());
                        }
                        if let Some(op) = args.get("op_prefix").and_then(Value::as_str) {
                            let suffix = match name {
                                "service-daemon-reload" => "daemon-reload",
                                "service-enable" => "service-enable",
                                "service-active" => "service-active",
                                _ => "service",
                            };
                            c.insert(
                                "legacy_receipt".into(),
                                Value::String(format!("{op}-{suffix}")),
                            );
                        }
                        c
                    }
                    _ => {
                        let mut c = args.clone();
                        c.insert(
                            "url".into(),
                            args.get("url")
                                .cloned()
                                .unwrap_or(Value::String(String::new())),
                        );
                        if let Some(v) = args.get("health_expected_contains") {
                            c.insert("expected_contains".into(), v.clone());
                        } else {
                            c.insert(
                                "expected_contains".into(),
                                serde_json::json!({"from":"pull-repo.resolved_commit"}),
                            );
                        }
                        if let Some(op) = args.get("op_prefix").and_then(Value::as_str) {
                            c.insert(
                                "legacy_receipt".into(),
                                Value::String(format!("{op}-health")),
                            );
                        }
                        c
                    }
                };
                RoutineStep {
                    name: name.into(),
                    tool: tool.into(),
                    permutation: Some(permutation.into()),
                    args: child_args,
                    extra: BTreeMap::new(),
                }
            })
            .collect();
    }
}
