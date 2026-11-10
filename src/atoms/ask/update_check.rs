//! Trace-free observer for `harmonia update --check`.
//! This deliberately returns its receipt to stdout and creates no local state.
use crate::bands::stage_profile::projection::LoadedModule;
use crate::tools::ladder::{LadderManifest, ValidatedStep};
use crate::PackageBackend;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const CHECK_TIMEOUT: Duration = Duration::from_secs(45);
const PACKAGE_OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const STDERR_OUTPUT_LIMIT: usize = 16 * 1024;

#[derive(Default)]
struct ModuleObservation {
    steps: BTreeSet<String>,
    pending: bool,
    config: bool,
    signal: Option<&'static str>,
}

fn fail_step(modules: &mut std::collections::BTreeMap<String, ModuleObservation>, errors: &mut Vec<Value>, module: &str, step: &str, signal: &'static str) {
    let entry = modules.entry(module.to_owned()).or_default();
    if !step.is_empty() { entry.steps.insert(step.to_owned()); }
    entry.signal.get_or_insert(signal);
    errors.push(json!({"module":module,"step":step,"signal":signal}));
}

fn response_error(signal: &'static str) -> Value {
    json!({"schema":"harmonia.update.check.v1","ok":false,"pending":null,
        "first_missing_signal":signal,"checked_at":checked_at(),
        "wearing":{"profile":null,"harmonia_sha":option_env!("HARMONIA_BUILD_SHA"),"caduceus_sha":null,"set_digest":null},
        "modules":null,"software":null,"config":null,"interactables":null,"last_run":null,
        "freshness":"relative-to-cached-package-indexes","index_refresh":"never",
        "coverage":"profile could not be resolved"})
}

fn checked_at() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn emit(value: Value, code: i32) -> i32 {
    println!("{}", value);
    code
}

/// Intercept before any invocation seats or apply dispatch can be reached.
pub(crate) fn invoke_check(args: &[String]) -> Option<i32> {
    if args.first().map(String::as_str) != Some("update") || !args.iter().any(|a| a == "--check") {
        return None;
    }
    Some(match parse_check_args(&args[1..]) {
        Ok(()) => match observe() {
            Ok(value) => {
                let code = if value["pending"] == true { 0 } else { 7 };
                emit(value, code)
            }
            Err(_) => emit(response_error("update-check-profile-unavailable"), 1),
        },
        Err(_) => emit(response_error("update-check-arguments-invalid"), 1),
    })
}

fn parse_check_args(args: &[String]) -> Result<(), String> {
    let mut check_count = 0;
    let mut apply = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--check" => { check_count += 1; i += 1; }
            "--apply" => { apply = true; i += 1; }
            "--receipt-dir" => return Err("update-check-receipt-dir-unsupported-no-write-query".into()),
            _ => return Err("update-check-argument-unsupported".into()),
        }
    }
    if check_count != 1 || apply { return Err("update-check-arguments-invalid".into()); }
    Ok(())
}

fn interactables() -> Result<Option<Value>, String> {
    let Some(connection) = crate::ledger::reader()? else { return Ok(None); };
    let feed = crate::ledger::load_proposals_on(&connection)?;
    let items: Vec<_> = feed.interactables.into_iter().filter(|item| item.kind != "engine-replacement").collect();
    let mut kinds = std::collections::BTreeMap::<String, usize>::new();
    for item in &items { *kinds.entry(item.kind.clone()).or_default() += 1; }
    Ok(Some(json!({"total":items.len(),"silenced":items.iter().filter(|item| item.silenced).count(),"by_kind":kinds})))
}

fn last_run() -> Option<Value> {
    let bytes = std::fs::read("/var/lib/harmonia/receipts/update-latest/run.json").ok()?;
    let run: Value = serde_json::from_slice(&bytes).ok()?;
    Some(json!({"run_id":run.get("run_id"),
        "finished_at":run.pointer("/final_receipt/stamps/0/at"),
        "converged":run.pointer("/final_receipt/converged"),
        "promoted":run.pointer("/final_receipt/promoted")}))
}

fn observe() -> Result<Value, String> {
    let (mut profile, profile_path) = crate::device_profile::resolve_certificate_profile()?;
    let policy = crate::read_device_module_policy()?;
    profile.syzygy_declaration = policy.syzygy_declaration.clone();
    let module_root = crate::default_module_root(&profile_path);
    let projection = crate::load_profile_projection(&profile, &module_root, &policy.disabled_modules)?;
    let mut modules = std::collections::BTreeMap::<String, ModuleObservation>::new();
    let mut errors = Vec::new();
    let mut pending_steps = BTreeSet::new();
    let mut config_proposals = BTreeSet::new();
    let mut package_updates = Vec::new();
    let mut cached_roots = Vec::new();
    let mut kernel_plan = Vec::new();
    let mut packages = BTreeSet::new();
    for module in projection.errors.keys() {
        fail_step(&mut modules, &mut errors, module, "", "update-check-module-projection-failed");
    }
    for (module_id, projected) in &projection.modules {
        modules.entry(module_id.clone()).or_default();
        let manifest = match &projected.loaded {
            LoadedModule::Sidecar(_) => {
                fail_step(&mut modules, &mut errors, module_id, "", "update-check-sidecar-unobserved");
                continue;
            }
            LoadedModule::Ladder(manifest) => manifest,
        };
        for step in &projected.steps {
            modules.get_mut(module_id).unwrap().steps.insert(step.step_id.clone());
            let mut step_proposals = BTreeSet::new();
            if step.tool == "routine" {
                if let Some(children) = projected.routines.get(&step.step_id) {
                    for child in children {
                        let child_step = ValidatedStep { step_id: format!("{}:{}", step.step_id, child.name), tool: child.tool.clone(), permutation: child.permutation.clone(), args: child.args.clone(), on_failure: child.on_failure };
                        modules.get_mut(module_id).unwrap().steps.insert(child_step.step_id.clone());
                        if observe_step(&child_step, manifest, module_id, &profile, &mut pending_steps, &mut step_proposals, &mut package_updates).is_err() {
                            fail_step(&mut modules, &mut errors, module_id, &child_step.step_id, "update-check-step-unobserved");
                        }
                    }
                } else {
                    fail_step(&mut modules, &mut errors, module_id, &step.step_id, "update-check-routine-unobserved");
                }
            } else if observe_step(step, manifest, module_id, &profile, &mut pending_steps, &mut step_proposals, &mut package_updates).is_err() {
                fail_step(&mut modules, &mut errors, module_id, &step.step_id, "update-check-step-unobserved");
            }
            if !step_proposals.is_empty() { modules.get_mut(module_id).unwrap().config = true; }
            config_proposals.extend(step_proposals);
        }
    }
    if !package_updates.is_empty() {
        let common = (|| -> Result<_, String> {
            let backend = profile.package_authority.as_ref().ok_or("update-check-package-authority-missing")?.backend()?;
            cached_roots = ensure_cached_indexes(backend)?;
            let (entries, ignored) = match backend {
                PackageBackend::Pacman => (query_pacman()?, query_pacman_ignored()?),
                PackageBackend::Apt => (query_apt()?, BTreeSet::new()),
            };
            if backend == PackageBackend::Apt && package_updates.iter().any(|u| u.kernel_purge) { kernel_plan = query_kernel_purge()?; }
            Ok((backend, entries, ignored))
        })();
        for update in package_updates {
            let (module, step) = update.label.split_once(':').unwrap_or((&update.label, ""));
            let result = (|| -> Result<bool, String> {
                let (backend, entries, ignored) = common.as_ref().map_err(|e| e.clone())?;
                if *backend == PackageBackend::Apt && !update.pins.is_empty() { return Err("update-check-apt-package-pins-simulation-unsupported".into()); }
                if *backend == PackageBackend::Pacman && !update.ceilings.is_empty() { return Err("update-check-package-ceiling-backend-unsupported-pacman".into()); }
                let mut found = update.kernel_purge && !kernel_plan.is_empty();
                let mut names = BTreeSet::new();
                for (name, current, candidate) in entries {
                    let base = name.split_once(':').map_or(name.as_str(), |(base, _)| base);
                    if (!update.scope.is_empty() && !update.scope.contains(name) && !update.scope.contains(base)) || update.pins.contains(name) || update.pins.contains(base) || ignored.contains(name) || ignored.contains(base) || current.is_empty() || candidate == "<removed>" || current == candidate { continue; }
                    if let Some(ceiling) = update.ceilings.get(name).or_else(|| update.ceilings.get(base)) {
                        if !apt_candidate_within_ceiling(candidate, ceiling)? { return Err("update-check-package-ceiling-exceeded".into()); }
                    }
                    found = true;
                    names.insert(name.clone());
                }
                packages.extend(names);
                Ok(found)
            })();
            match result {
                Ok(true) => { pending_steps.insert(update.label.clone()); }
                Ok(false) => {}
                Err(_) => fail_step(&mut modules, &mut errors, module, step, "update-check-package-unobserved"),
            }
        }
    }
    for label in &pending_steps {
        if let Some((module, _)) = label.split_once(':') {
            if let Some(observation) = modules.get_mut(module) { observation.pending = true; }
        }
    }
    let list: Vec<Value> = modules.iter().map(|(id, item)| {
        let state = if item.pending { "pending" } else if item.signal.is_some() { "unobserved" } else if item.config { "config" } else { "current" };
        json!({"id":id,"state":state,"steps":item.steps,"signal":item.signal})
    }).collect();
    let count = |state: &str| list.iter().filter(|row| row["state"] == state).count();
    let (interactables, ledger_signal) = match interactables() {
        Ok(Some(value)) => (Some(value), None),
        Ok(None) => (None, Some("update-check-ledger-unavailable")),
        Err(_) => (None, Some("update-check-ledger-unobserved")),
    };
    let signal = errors.first().and_then(|e| e["signal"].as_str()).or(ledger_signal).unwrap_or("none");
    Ok(json!({"schema":"harmonia.update.check.v1","ok":true,"pending":!pending_steps.is_empty(),"first_missing_signal":signal,"checked_at":checked_at(),
        "wearing":{"profile":profile.id,"harmonia_sha":option_env!("HARMONIA_BUILD_SHA"),"caduceus_sha":null,"set_digest":null},
        "modules":{"total":list.len(),"current":count("current"),"pending":count("pending"),"config":count("config"),"unobserved":count("unobserved"),"list":list},
        "software":{"pending_steps":pending_steps.len(),"packages_upgradable":packages.len(),"releases_newer":crate::atoms::ask::update_check_releases::take_newer(),"kernel_purge_plan":kernel_plan},
        "config":{"proposals":config_proposals.len()},"interactables":interactables,"interactables_signal":ledger_signal,"last_run":last_run(),"unobserved_steps":errors,
        "index_refresh":"never","freshness":"relative-to-cached-package-indexes","cached_index_roots_consulted":cached_roots,
        "coverage":"readable file and cached-package steps observed; unsupported or unreadable steps marked unobserved; release lookup deferred"}))
}

struct PackageUpdateScope {
    label: String,
    kernel_purge: bool,
    scope: BTreeSet<String>,
    pins: BTreeSet<String>,
    ceilings: std::collections::BTreeMap<String, String>,
}

fn observe_package_check(step: &ValidatedStep, profile: &crate::Profile) -> Result<(), String> {
    let mut packages = Vec::new();
    if let Some(raw_values) = step.args.get("packages") {
        let values = raw_values.as_array().ok_or_else(|| {
            format!(
                "update-check-package-check-scope-malformed-{}",
                step.step_id
            )
        })?;
        for value in values {
            let name = value.as_str().ok_or_else(|| {
                format!(
                    "update-check-package-check-scope-malformed-{}",
                    step.step_id
                )
            })?;
            if name.is_empty() {
                return Err(format!(
                    "update-check-package-check-scope-malformed-{}",
                    step.step_id
                ));
            }
            packages.push(name.to_owned());
        }
    }
    if let Some(name) = step.args.get("package").and_then(Value::as_str) {
        packages.push(name.to_owned());
    }
    packages.sort();
    packages.dedup();
    if packages.is_empty() {
        return Ok(());
    }
    let backend = profile
        .package_authority
        .as_ref()
        .ok_or_else(|| "update-check-package-authority-missing".to_string())?
        .backend()
        .map_err(|e| format!("update-check-{e}"))?;
    for name in packages {
        let (program, args) = match backend {
            PackageBackend::Pacman => (
                crate::atoms::package::pacman_program(),
                vec!["-Q".into(), "--".into(), name.clone()],
            ),
            PackageBackend::Apt => (
                "/usr/bin/dpkg-query".to_string(),
                vec!["-W".into(), "-f=${Status}".into(), name.clone()],
            ),
        };
        let result =
            crate::atoms::ask::read_only_command_with_timeout(&program, &args, CHECK_TIMEOUT);
        if !result.ok {
            let stderr = result.stderr.to_ascii_lowercase();
            if result.code == Some(1)
                && (stderr.contains("not found") || stderr.contains("no packages found matching"))
            {
                return Err(format!(
                    "update-check-package-check-not-installed-{}-{}",
                    step.step_id, name
                ));
            }
            return Err(format!(
                "update-check-package-check-query-failed-{}-{}:{}",
                step.step_id,
                name,
                result.stderr.trim()
            ));
        }
        if backend == PackageBackend::Apt && result.stdout.trim() != "install ok installed" {
            return Err(format!(
                "update-check-package-check-not-installed-{}-{}",
                step.step_id, name
            ));
        }
        if backend == PackageBackend::Pacman
            && result.stdout.trim().split_whitespace().next() != Some(name.as_str())
        {
            return Err(format!(
                "update-check-package-check-result-unrecognized-{}-{}",
                step.step_id, name
            ));
        }
    }
    Ok(())
}

fn collect_package_scope(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_id: &str,
) -> Result<PackageUpdateScope, String> {
    let mut scope = BTreeSet::new();
    if let Some(packages) = step.args.get("packages").and_then(Value::as_array) {
        for item in packages {
            let name = item
                .as_str()
                .ok_or_else(|| format!("update-check-package-scope-malformed-{}", step.step_id))?;
            let name = name.split_once('=').map_or(name, |(package, _)| package);
            if name.is_empty() {
                return Err(format!(
                    "update-check-package-scope-malformed-{}",
                    step.step_id
                ));
            }
            scope.insert(name.to_string());
        }
    }
    Ok(PackageUpdateScope {
        label: format!("{module_id}:{}", step.step_id),
        kernel_purge: step.permutation == "upgrade",
        scope,
        pins: manifest.package_pins.keys().cloned().collect(),
        ceilings: manifest.package_ceilings.clone(),
    })
}

fn observe_step(
    step: &ValidatedStep,
    manifest: &LadderManifest,
    module_id: &str,
    profile: &crate::Profile,
    pending_steps: &mut BTreeSet<String>,
    config_proposals: &mut BTreeSet<PathBuf>,
    package_updates: &mut Vec<PackageUpdateScope>,
) -> Result<(), String> {
    match step.tool.as_str() {
        "files" => match step.permutation.as_str() {
            "converge" | "directory-sync" => {
                let (software, config) = observe_converge(step, manifest)?;
                if software {
                    pending_steps.insert(format!("{module_id}:{}", step.step_id));
                }
                config_proposals.extend(config);
            }
            "managed-files" => {
                let (software, config) = observe_managed_files(step, manifest)?;
                if software {
                    pending_steps.insert(format!("{module_id}:{}", step.step_id));
                }
                config_proposals.extend(config);
            }
            "metadata" => {
                let (software, config) = observe_metadata(step)?;
                if software {
                    pending_steps.insert(format!("{module_id}:{}", step.step_id));
                }
                config_proposals.extend(config);
            }
            "validated-symlink" | "symlink-converge" | "validated-file-symlink" => {
                let (software, config) = observe_symlink(step, manifest)?;
                if software {
                    pending_steps.insert(format!("{module_id}:{}", step.step_id));
                }
                config_proposals.extend(config);
            }
            "remove" | "source-shelf-sweep" => {
                let (software, config) = observe_remove(step)?;
                if software {
                    pending_steps.insert(format!("{module_id}:{}", step.step_id));
                }
                config_proposals.extend(config);
            }
            "executable-present" | "probe" | "health" => {}
            other => {
                return Err(format!(
                    "update-check-files-permutation-unsupported-{module_id}-{}-{other}",
                    step.step_id
                ))
            }
        },
        "package" | "packages" if step.permutation == "check" => {
            observe_package_check(step, profile)?
        }
        "package" | "packages" if matches!(step.permutation.as_str(), "list" | "show") => {
            return Err(format!(
                "update-check-package-observer-unsupported-{module_id}-{}-{}",
                step.step_id, step.permutation
            ));
        }
        "package" | "packages" if matches!(step.permutation.as_str(), "update" | "upgrade") => {
            package_updates.push(collect_package_scope(step, manifest, module_id)?);
        }
        "check-health" | "health" | "probe" | "executable-present" => {}
        "pull-repo" | "pull_repo" | "git-artifact" => {
            let label = format!("{module_id}:{}", step.step_id);
            if crate::atoms::ask::update_check_releases::source(step, manifest, &label)? {
                pending_steps.insert(label);
            }
        }
        "fetch-artifact" | "artifact" | "source" | "release-binary" => {
            let label = format!("{module_id}:{}", step.step_id);
            if crate::atoms::ask::update_check_releases::binary(step, &label)? {
                pending_steps.insert(label);
            }
        }
        other => {
            return Err(format!(
                "update-check-step-observer-unsupported-{module_id}-{}-{other}-{}",
                step.step_id, step.permutation
            ))
        }
    }
    Ok(())
}

fn observe_symlink(step: &ValidatedStep, manifest: &LadderManifest) -> Result<(bool, BTreeSet<PathBuf>), String> {
    // The declared files form is source -> target; legacy aliases use target
    // as the destination of the link, so do not mix the two interpretations.
    let declared_form = step.args.get("source").and_then(Value::as_str).is_some()
        && step.args.get("target").and_then(Value::as_str).is_some();
    let path_keys: &[&str] = if declared_form { &["target"] }
        else { &["path", "link", "destination", "target_path"] };
    let desired_keys: &[&str] = if declared_form { &["source"] }
        else { &["link_target", "target", "source"] };
    let path = path_keys
        .iter()
        .find_map(|key| step.args.get(*key).and_then(Value::as_str))
        .ok_or_else(|| format!("update-check-symlink-path-missing-{}", step.step_id))?;
    let desired = desired_keys
        .iter()
        .find_map(|key| step.args.get(*key).and_then(Value::as_str))
        .ok_or_else(|| format!("update-check-symlink-target-missing-{}", step.step_id))?;
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(format!(
            "update-check-symlink-path-not-absolute-{}",
            path.display()
        ));
    }
    let class = crate::atoms::files::classify_target(&path);
    if let crate::atoms::files::TargetClass::Refused(reason) = class {
        return Err(format!("update-check-symlink-target-refused-{reason}"));
    }
    let equal = match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            std::fs::read_link(&path)
                .map_err(|e| format!("update-check-symlink-read-failed-{}:{e}", path.display()))?
                == PathBuf::from(desired)
        }
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(format!(
                "update-check-symlink-observe-failed-{}:{error}",
                path.display()
            ))
        }
    };
    let owner_only = matches!(class, crate::atoms::files::TargetClass::Config)
        || (step.permutation == "validated-symlink"
            && crate::tools::files::validated_symlink_requires_owner(step, manifest)?);
    let mut config = BTreeSet::new();
    if owner_only && !equal {
        config.insert(path);
    }
    Ok((
        !owner_only && !equal,
        config,
    ))
}

fn observe_remove(step: &ValidatedStep) -> Result<(bool, BTreeSet<PathBuf>), String> {
    let mut paths = Vec::<String>::new();
    for key in ["paths", "files", "targets"] {
        if let Some(values) = step.args.get(key).and_then(Value::as_array) {
            for value in values {
                if let Some(path) = value
                    .as_str()
                    .or_else(|| value.get("path").and_then(Value::as_str))
                {
                    paths.push(path.to_string());
                } else {
                    return Err(format!(
                        "update-check-remove-path-malformed-{}",
                        step.step_id
                    ));
                }
            }
        }
    }
    if paths.is_empty() {
        if let Some(path) = step.args.get("path").and_then(Value::as_str) {
            paths.push(path.to_string());
        }
    }
    if paths.is_empty() {
        return Err(format!(
            "update-check-remove-paths-missing-{}",
            step.step_id
        ));
    }
    let mut software = false;
    let mut config = BTreeSet::new();
    for raw in paths {
        let path = PathBuf::from(&raw);
        if !path.is_absolute() {
            return Err(format!("update-check-remove-path-not-absolute-{raw}"));
        }
        let class = crate::atoms::files::classify_target(&path);
        if let crate::atoms::files::TargetClass::Refused(reason) = class {
            return Err(format!("update-check-remove-target-refused-{reason}"));
        }
        let exists = match std::fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(format!(
                    "update-check-remove-observe-failed-{}:{error}",
                    path.display()
                ))
            }
        };
        if exists && matches!(class, crate::atoms::files::TargetClass::Software) {
            software = true;
        }
        if exists && matches!(class, crate::atoms::files::TargetClass::Config) {
            config.insert(path);
        }
    }
    Ok((software, config))
}

fn apt_config_shell_value(variable: &str, key: &str) -> Result<String, String> {
    let result = crate::atoms::ask::read_only_command_with_timeout(
        "/usr/bin/apt-config",
        &["shell".into(), variable.into(), key.into()],
        CHECK_TIMEOUT,
    );
    if !result.ok {
        return Err(format!(
            "update-check-apt-config-query-failed-{key}:{}",
            result.stderr.trim()
        ));
    }
    let mut lines = result.stdout.lines();
    let line = lines
        .next()
        .ok_or_else(|| format!("update-check-apt-config-output-malformed-{key}"))?;
    if lines.next().is_some() {
        return Err(format!("update-check-apt-config-output-malformed-{key}"));
    }
    let prefix = format!("{variable}='");
    line.strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix('\''))
        .map(str::to_owned)
        .ok_or_else(|| format!("update-check-apt-config-output-malformed-{key}"))
}

fn ensure_cached_indexes(backend: PackageBackend) -> Result<Vec<String>, String> {
    match backend {
        PackageBackend::Apt => {
            let lists_config = apt_config_shell_value("HARMONIA_LISTS", "Dir::State::lists/d")?;
            if !matches!(
                lists_config.as_str(),
                "/var/lib/apt/lists" | "/var/lib/apt/lists/"
            ) {
                return Err(format!(
                    "update-check-apt-custom-state-path-unsupported-Dir::State::lists-{lists_config}"
                ));
            }
            let status_config = apt_config_shell_value("HARMONIA_STATUS", "Dir::State::status/f")?;
            if status_config != "/var/lib/dpkg/status" {
                return Err(format!(
                    "update-check-apt-custom-state-path-unsupported-Dir::State::status-{status_config}"
                ));
            }
            let status = std::fs::metadata(&status_config)
                .map_err(|e| format!("update-check-dpkg-installed-state-unavailable:{e}"))?;
            if !status.is_file() || status.len() == 0 {
                return Err(format!(
                    "update-check-dpkg-installed-state-unusable-{status_config}"
                ));
            }
            let root = Path::new(lists_config.trim_end_matches('/'));
            let entries = std::fs::read_dir(root).map_err(|e| {
                format!(
                    "update-check-apt-cached-index-root-unavailable-{}:{e}",
                    root.display()
                )
            })?;
            let mut usable = false;
            for entry in entries {
                let entry =
                    entry.map_err(|e| format!("update-check-apt-cached-index-read-failed:{e}"))?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path).map_err(|e| {
                    format!(
                        "update-check-apt-cached-index-stat-failed-{}:{e}",
                        path.display()
                    )
                })?;
                if metadata.file_type().is_file()
                    && (name.contains("_Packages") || name.ends_with("Packages"))
                    && metadata.len() > 0
                {
                    usable = true;
                    break;
                }
            }
            if !usable {
                return Err(
                    "update-check-apt-cached-package-index-unavailable-/var/lib/apt/lists".into(),
                );
            }
            return Ok(vec![root.display().to_string(), status_config]);
        }
        PackageBackend::Pacman => {
            let conf = crate::atoms::package::pacman_conf_program();
            let result = crate::atoms::ask::read_only_command_with_timeout(
                &conf,
                &["DBPath".into()],
                CHECK_TIMEOUT,
            );
            if !result.ok {
                return Err(format!(
                    "update-check-pacman-dbpath-query-failed:{}",
                    result.stderr.trim()
                ));
            }
            let db = result.stdout.trim();
            if db.is_empty() || !Path::new(db).is_absolute() {
                return Err("update-check-pacman-dbpath-invalid".into());
            }
            let sync = Path::new(db).join("sync");
            let repo_list = crate::atoms::ask::read_only_command_with_timeout_and_limit(
                &conf,
                &["--repo-list".into()],
                CHECK_TIMEOUT,
                STDERR_OUTPUT_LIMIT,
            );
            if !repo_list.ok {
                return Err(format!(
                    "update-check-pacman-repo-list-query-failed:{}",
                    repo_list.stderr.trim()
                ));
            }
            if repo_list.stdout.len() >= STDERR_OUTPUT_LIMIT {
                return Err("update-check-pacman-repo-list-output-bound-reached".into());
            }
            let repositories = repo_list
                .stdout
                .lines()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .collect::<Vec<_>>();
            if repositories.is_empty() {
                return Err("update-check-pacman-repo-list-empty".into());
            }
            for repository in repositories {
                if repository.contains('/') || repository == "." || repository == ".." {
                    return Err(format!(
                        "update-check-pacman-repo-name-invalid-{repository}"
                    ));
                }
                let index = sync.join(format!("{repository}.db"));
                let metadata = std::fs::symlink_metadata(&index).map_err(|error| {
                    format!(
                        "update-check-pacman-cached-repo-index-unavailable-{}:{error}",
                        index.display()
                    )
                })?;
                if !metadata.file_type().is_file() || metadata.len() == 0 {
                    return Err(format!(
                        "update-check-pacman-cached-repo-index-unusable-{}",
                        index.display()
                    ));
                }
            }
            let local = Path::new(db).join("local");
            let entries = std::fs::read_dir(&local).map_err(|e| {
                format!(
                    "update-check-pacman-installed-state-unavailable-{}:{e}",
                    local.display()
                )
            })?;
            if entries.into_iter().next().is_none() {
                return Err(format!(
                    "update-check-pacman-installed-state-unusable-{}",
                    local.display()
                ));
            }
            return Ok(vec![
                sync.display().to_string(),
                local.display().to_string(),
            ]);
        }
    }
}

fn query_pacman() -> Result<Vec<(String, String, String)>, String> {
    let program = crate::atoms::package::pacman_program();
    let args = vec!["-Qu".into(), "--logfile".into(), "/dev/null".into()];
    // Query the installed database against already-cached sync indexes only;
    // never use pacman -Sy from a trace-free check.
    let result = crate::atoms::ask::read_only_command_with_timeout_and_limit(
        &program,
        &args,
        CHECK_TIMEOUT,
        PACKAGE_OUTPUT_LIMIT,
    );
    if result.stdout.len() >= PACKAGE_OUTPUT_LIMIT || result.stderr.len() >= STDERR_OUTPUT_LIMIT {
        return Err("update-check-pacman-output-bound-reached".into());
    }
    if !result.ok
        && !(result.code == Some(1) && result.stdout.is_empty() && result.stderr.is_empty())
    {
        return Err(format!(
            "update-check-pacman-index-query-failed:{}",
            result.stderr.trim()
        ));
    }
    if !result.ok {
        return Ok(Vec::new());
    }
    let mut parsed = Vec::new();
    for line in result.stdout.lines().filter(|line| !line.trim().is_empty()) {
        let (name, versions) = line
            .split_once(' ')
            .ok_or("update-check-pacman-output-malformed")?;
        let (current, candidate) = versions
            .trim()
            .split_once(" -> ")
            .ok_or("update-check-pacman-output-malformed")?;
        if name.is_empty() || current.is_empty() || candidate.is_empty() {
            return Err("update-check-pacman-output-malformed".into());
        }
        parsed.push((name.to_string(), current.to_string(), candidate.to_string()));
    }
    Ok(parsed)
}

fn query_pacman_ignored() -> Result<BTreeSet<String>, String> {
    let conf = crate::atoms::package::pacman_conf_program();
    let mut ignored = BTreeSet::new();
    for key in ["IgnorePkg", "IgnoreGroup"] {
        let args = vec![key.to_string()];
        let result = crate::atoms::ask::read_only_command_with_timeout(&conf, &args, CHECK_TIMEOUT);
        if result.stdout.len() >= STDERR_OUTPUT_LIMIT || result.stderr.len() >= STDERR_OUTPUT_LIMIT
        {
            return Err(format!(
                "update-check-pacman-config-output-bound-reached-{key}"
            ));
        }
        if !result.ok {
            return Err(format!(
                "update-check-pacman-config-query-failed-{key}:{}",
                result.stderr.trim()
            ));
        }
        for entry in result.stdout.split_whitespace() {
            if key == "IgnorePkg" {
                ignored.insert(entry.to_string());
            } else {
                let program = crate::atoms::package::pacman_program();
                let args = vec![
                    "-Sgq".into(),
                    "--logfile".into(),
                    "/dev/null".into(),
                    entry.to_string(),
                ];
                let group = crate::atoms::ask::read_only_command_with_timeout_and_limit(
                    &program,
                    &args,
                    CHECK_TIMEOUT,
                    PACKAGE_OUTPUT_LIMIT,
                );
                if group.stdout.len() >= PACKAGE_OUTPUT_LIMIT
                    || group.stderr.len() >= STDERR_OUTPUT_LIMIT
                {
                    return Err(format!(
                        "update-check-pacman-ignore-group-output-bound-reached-{entry}"
                    ));
                }
                if !group.ok {
                    return Err(format!(
                        "update-check-pacman-ignore-group-query-failed-{entry}:{}",
                        group.stderr.trim()
                    ));
                }
                ignored.extend(
                    group
                        .stdout
                        .lines()
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_string),
                );
            }
        }
    }
    Ok(ignored)
}

fn apt_candidate_within_ceiling(candidate: &str, ceiling: &str) -> Result<bool, String> {
    let args = vec![
        "--compare-versions".into(),
        candidate.into(),
        "le".into(),
        ceiling.into(),
    ];
    let result =
        crate::atoms::ask::read_only_command_with_timeout("/usr/bin/dpkg", &args, CHECK_TIMEOUT);
    match result.code {
        Some(0) if result.ok => Ok(true),
        Some(1) if !result.ok && result.stderr.is_empty() => Ok(false),
        _ => Err(format!(
            "update-check-package-ceiling-comparison-failed:{}",
            result.stderr.trim()
        )),
    }
}

fn query_kernel_purge() -> Result<Vec<String>, String> {
    let args = ["-s", "-o", "Debug::NoLocking=1", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "-o", "Dir::Log::History=/dev/null", "-o", "Dir::Log::Terminal=/dev/null", "-o", "Dir::Log::Planner=", "autoremove"]
        .iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let result = crate::atoms::ask::read_only_command_with_timeout_and_limit(
        "/usr/bin/apt-get", &args, CHECK_TIMEOUT, PACKAGE_OUTPUT_LIMIT,
    );
    if !result.ok || result.stdout.len() >= PACKAGE_OUTPUT_LIMIT || result.stderr.len() >= STDERR_OUTPUT_LIMIT {
        return Err(format!("update-check-kernel-purge-query-failed:{}", result.stderr));
    }
    Ok(crate::atoms::ask::kernel_purge::kernel_plan(&result.stdout))
}

fn query_apt() -> Result<Vec<(String, String, String)>, String> {
    let args = vec![
        "-s".into(),
        "-o".into(),
        "Debug::NoLocking=1".into(),
        "-o".into(),
        "Dir::Cache::pkgcache=".into(),
        "-o".into(),
        "Dir::Cache::srcpkgcache=".into(),
        "-o".into(),
        "Dir::Log::History=/dev/null".into(),
        "-o".into(),
        "Dir::Log::Terminal=/dev/null".into(),
        "full-upgrade".into(),
        "-o".into(),
        "Dir::Log::Planner=".into(),
    ];
    // Simulation parity with the apply full-upgrade: read current apt lists,
    // disable locking and both package caches, discard terminal output, and disable planner output.
    let result = crate::atoms::ask::read_only_command_with_timeout_and_limit(
        "/usr/bin/apt-get",
        &args,
        CHECK_TIMEOUT,
        PACKAGE_OUTPUT_LIMIT,
    );
    if result.stdout.len() >= PACKAGE_OUTPUT_LIMIT || result.stderr.len() >= STDERR_OUTPUT_LIMIT {
        return Err("update-check-apt-output-bound-reached".into());
    }
    if !result.ok {
        return Err(format!(
            "update-check-apt-cached-index-query-failed:{}",
            result.stderr.trim()
        ));
    }
    let mut parsed = Vec::new();
    let mut saw_summary = false;
    for line in result.stdout.lines() {
        if line.contains(" upgraded,") || line.trim_start().starts_with("0 upgraded") {
            saw_summary = true;
        }
        if let Some(rest) = line.strip_prefix("Remv ") {
            let name = rest
                .split_whitespace()
                .next()
                .ok_or("update-check-apt-output-malformed")?;
            parsed.push((name.to_string(), String::new(), "<removed>".to_string()));
            continue;
        }
        if let Some(rest) = line.strip_prefix("Inst ") {
            let mut fields = rest.split_whitespace();
            let name = fields.next().ok_or("update-check-apt-output-malformed")?;
            let next = fields.next().ok_or("update-check-apt-output-malformed")?;
            let current = if next.starts_with('[') {
                next.strip_prefix('[')
                    .and_then(|value| value.strip_suffix(']'))
                    .ok_or("update-check-apt-output-malformed")?
            } else {
                ""
            };
            let candidate_token = if current.is_empty() {
                // A row without an installed-version token is a proposed new
                // install, not an upgrade that `update --apply` will perform.
                if !next.starts_with('(') {
                    return Err("update-check-apt-output-malformed".into());
                }
                next
            } else {
                fields
                    .find(|value| value.starts_with('('))
                    .ok_or("update-check-apt-output-malformed")?
            };
            let candidate = candidate_token
                .trim_start_matches('(')
                .trim_end_matches(')');
            if name.is_empty() || candidate.is_empty() {
                return Err("update-check-apt-output-malformed".into());
            }
            if !current.is_empty() {
                parsed.push((name.to_string(), current.to_string(), candidate.to_string()));
            }
        }
    }
    if !saw_summary {
        return Err("update-check-apt-output-summary-missing".into());
    }
    Ok(parsed)
}

fn observe_converge(
    step: &ValidatedStep,
    manifest: &LadderManifest,
) -> Result<(bool, BTreeSet<PathBuf>), String> {
    let source_root = step
        .args
        .get("source_root")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("update-check-files-source-root-missing-{}", step.step_id))?;
    let target_root = step
        .args
        .get("target_root")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("update-check-files-target-root-missing-{}", step.step_id))?;
    let sources = step
        .args
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("update-check-files-list-missing-{}", step.step_id))?;
    let source_root = resolve_manifest_path(manifest, source_root);
    let target_root = PathBuf::from(target_root);
    let declared_mode = step
        .args
        .get("mode")
        .and_then(Value::as_u64)
        .map(|v| v as u32);
    let mut software_diff = false;
    let mut config_diff = BTreeSet::new();
    for value in sources {
        let relative = value
            .as_str()
            .ok_or_else(|| format!("update-check-files-entry-unsupported-{}", step.step_id))?;
        let rel = safe_relative(relative)?;
        let mut file_ownership = resolve_ownership(step)?;
        let source = source_root.join(&rel);
        verify_source_path(&source)?;
        let meta = std::fs::symlink_metadata(&source).map_err(|e| {
            format!(
                "update-check-source-observe-failed-{}:{e}",
                source.display()
            )
        })?;
        if !meta.file_type().is_file() {
            return Err(format!(
                "update-check-source-not-regular-file-{}",
                source.display()
            ));
        }
        #[cfg(unix)]
        let mode = declared_mode.or_else(|| {
            use std::os::unix::fs::PermissionsExt;
            Some(meta.permissions().mode() & 0o7777)
        });
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            file_ownership.uid = file_ownership.uid.or(Some(meta.uid()));
            file_ownership.gid = file_ownership.gid.or(Some(meta.gid()));
        }
        #[cfg(not(unix))]
        let mode = declared_mode;
        let bytes = std::fs::read(&source)
            .map_err(|e| format!("update-check-source-read-failed-{}:{e}", source.display()))?;
        let target = target_root.join(&rel);
        match crate::atoms::files::classify_target(&target) {
            crate::atoms::files::TargetClass::Refused(reason) => {
                return Err(format!("update-check-target-refused-{reason}"))
            }
            class => {
                let target_exists = match std::fs::symlink_metadata(&target) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(format!(
                            "update-check-target-symlink-no-follow-refused-{}",
                            target.display()
                        ));
                    }
                    Ok(metadata) if !metadata.file_type().is_file() => {
                        return Err(format!(
                            "update-check-target-not-regular-file-{}",
                            target.display()
                        ));
                    }
                    Ok(_) => true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                    Err(error) => {
                        return Err(format!(
                            "update-check-target-kind-observe-failed-{}:{error}",
                            target.display()
                        ))
                    }
                };
                let observation = crate::atoms::ask::backfill_file::probe::file(
                    &target,
                    &bytes,
                    mode,
                    file_ownership,
                    None,
                )
                .map_err(|e| {
                    format!("update-check-target-probe-failed-{}:{e}", target.display())
                })?;
                let equal = observation.current();
                match class {
                    crate::atoms::files::TargetClass::Config if !equal && target_exists => {
                        if crate::bands::propose_edits::config_offer_eligible(
                            manifest, &source, &target,
                        )? {
                            config_diff.insert(target.clone());
                        }
                    }
                    crate::atoms::files::TargetClass::Software if !equal => software_diff = true,
                    _ => {}
                }
            }
        }
    }
    Ok((software_diff, config_diff))
}

fn observe_managed_files(
    step: &ValidatedStep,
    manifest: &LadderManifest,
) -> Result<(bool, BTreeSet<PathBuf>), String> {
    let files = crate::tools::files::materialize_managed_files(step, manifest)
        .map_err(|e| format!("update-check-managed-files-materialize-failed:{e}"))?;
    let modes = crate::tools::files::parse_managed_file_modes(&step.args)
        .map_err(|e| format!("update-check-managed-files-mode-failed:{e}"))?;
    let software_diff = false;
    let mut config_diff = BTreeSet::new();
    for file in files {
        let target = PathBuf::from(&file.path);
        let class = crate::atoms::files::classify_target(&target);
        if let crate::atoms::files::TargetClass::Refused(reason) = class {
            return Err(format!("update-check-managed-target-refused-{reason}"));
        }
        if matches!(class, crate::atoms::files::TargetClass::Software) {
            // Managed known-good software files are attestations/presence
            // checks, not convergence targets. An absent target is a blocker.
            if !target.exists() {
                return Err(format!(
                    "update-check-managed-known-good-target-absent-{}",
                    target.display()
                ));
            }
            continue;
        }
        let mode = modes.get(&file.path).copied().or(file.mode);
        let obs = crate::atoms::ask::backfill_file::probe::file(
            &target,
            file.content.as_bytes(),
            mode,
            resolve_ownership(step)?,
            None,
        )
        .map_err(|e| {
            format!(
                "update-check-managed-target-probe-failed-{}:{e}",
                target.display()
            )
        })?;
        if !obs.current() && target.is_file() {
            // Managed-file content may be materialized from files_root or generated
            // inline. The proposer resolves lineage from the actual bytes.
            let source = manifest.files_root.as_ref()
                .and_then(|root| target.strip_prefix("/").ok().map(|relative| manifest.base_dir.join(root).join(relative)))
                .filter(|path| std::fs::read(path).ok().as_deref() == Some(file.content.as_bytes()))
                .unwrap_or_default();
            if crate::bands::propose_edits::config_offer_eligible_bytes(
                manifest, &source, &target, file.content.as_bytes(),
            )? {
                config_diff.insert(target.clone());
            }
        }
    }
    Ok((software_diff, config_diff))
}

fn observe_metadata(step: &ValidatedStep) -> Result<(bool, BTreeSet<PathBuf>), String> {
    let files = step
        .args
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("update-check-metadata-files-missing-{}", step.step_id))?;
    if files.is_empty() {
        return Err("update-check-metadata-files-empty".into());
    }
    let mut software_diff = false;
    let config_diff = BTreeSet::new();
    for value in files {
        let spec: crate::atoms::r#do::change_mode::MetadataFileSpec =
            serde_json::from_value(value.clone())
                .map_err(|e| format!("update-check-metadata-spec-invalid:{e}"))?;
        let path = PathBuf::from(&spec.path);
        if !path.is_absolute() {
            return Err(format!(
                "update-check-metadata-path-not-absolute-{}",
                path.display()
            ));
        }
        let class = crate::atoms::files::classify_target(&path);
        if let crate::atoms::files::TargetClass::Refused(reason) = class {
            return Err(format!("update-check-metadata-target-refused-{reason}"));
        }
        let mode = crate::atoms::ask::change_mode::probe(&path, spec.mode).map_err(|e| {
            format!(
                "update-check-metadata-mode-probe-failed-{}:{e}",
                path.display()
            )
        })?;
        if !matches!(
            mode.preimage.kind,
            Some(crate::atoms::ask::FsKind::File | crate::atoms::ask::FsKind::Directory)
        ) {
            return Err(format!(
                "update-check-metadata-target-kind-refused-{}",
                path.display()
            ));
        }
        let ownership = resolve_owner_group_names(Some(&spec.owner), Some(&spec.group))?;
        let owner = crate::atoms::ask::change_owner::probe(&path, ownership.uid, ownership.gid)
            .map_err(|e| {
                format!(
                    "update-check-metadata-owner-probe-failed-{}:{e}",
                    path.display()
                )
            })?;
        let different = mode.prior_mode != Some(spec.mode)
            || owner.prior_uid != ownership.uid
            || owner.prior_gid != ownership.gid;
        match class {
            crate::atoms::files::TargetClass::Software if different => software_diff = true,
            _ => {}
        }
    }
    Ok((software_diff, config_diff))
}

fn resolve_manifest_path(manifest: &LadderManifest, path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        p
    } else {
        manifest.base_dir.join(p)
    }
}

fn verify_source_path(path: &Path) -> Result<(), String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("update-check-source-cwd-unavailable:{e}"))?
            .join(path)
    };
    let components = absolute.components().collect::<Vec<_>>();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => current.push("/"),
            Component::Normal(part) => current.push(part),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(format!(
                    "update-check-source-path-parent-refused-{}",
                    path.display()
                ))
            }
            Component::Prefix(_) => {
                return Err(format!(
                    "update-check-source-path-prefix-refused-{}",
                    path.display()
                ))
            }
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(|e| {
            format!(
                "update-check-source-observe-failed-{}:{e}",
                current.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "update-check-source-symlink-refused-{}",
                current.display()
            ));
        }
        if index + 1 < components.len() && !metadata.is_dir() {
            return Err(format!(
                "update-check-source-parent-not-directory-{}",
                current.display()
            ));
        }
    }
    Ok(())
}

fn safe_relative(path: &str) -> Result<PathBuf, String> {
    let p = Path::new(path);
    if p.is_absolute() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(format!("update-check-relative-path-refused-{path}"));
    }
    Ok(p.to_path_buf())
}

fn resolve_ownership(
    step: &ValidatedStep,
) -> Result<crate::atoms::ask::backfill_file::DeclaredOwnership, String> {
    let owner = step.args.get("owner").and_then(Value::as_str);
    let group = step.args.get("group").and_then(Value::as_str);
    resolve_owner_group_names(owner, group)
}

fn resolve_owner_group_names(
    owner: Option<&str>,
    group: Option<&str>,
) -> Result<crate::atoms::ask::backfill_file::DeclaredOwnership, String> {
    let uid = owner.map(|name| lookup_id(name, true)).transpose()?;
    let gid = group.map(|name| lookup_id(name, false)).transpose()?;
    Ok(crate::atoms::ask::backfill_file::DeclaredOwnership { uid, gid })
}

fn lookup_id(name: &str, user: bool) -> Result<u32, String> {
    if let Ok(id) = name.parse::<u32>() {
        return Ok(id);
    }
    let c = CString::new(name).map_err(|_| format!("update-check-owner-name-invalid-{name}"))?;
    unsafe {
        let entry = if user {
            libc::getpwnam(c.as_ptr()).cast::<libc::passwd>() as *const libc::passwd
        } else {
            std::ptr::null()
        };
        if user {
            if entry.is_null() {
                return Err(format!("update-check-owner-account-unavailable-{name}"));
            }
            return Ok((*entry).pw_uid);
        }
        let group = libc::getgrnam(c.as_ptr());
        if group.is_null() {
            return Err(format!("update-check-group-account-unavailable-{name}"));
        }
        Ok((*group).gr_gid)
    }
}
