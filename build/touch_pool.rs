use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, String>;

fn read_json(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

fn array(value: &Value) -> &[Value] {
    value.as_array().map(Vec::as_slice).unwrap_or(&[])
}

fn strings(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn resolve(value: &Value, constants: &Map<String, Value>) -> Result<Value> {
    match value {
        Value::String(s) => {
            let name = s
                .strip_prefix("$constants.")
                .or_else(|| s.strip_prefix("${").and_then(|s| s.strip_suffix('}')));
            match name {
                Some(name) => constants
                    .get(name)
                    .cloned()
                    .ok_or_else(|| format!("dangling-constant-{name}")),
                None => Ok(value.clone()),
            }
        }
        Value::Array(a) => Ok(Value::Array(
            a.iter()
                .map(|v| resolve(v, constants))
                .collect::<Result<_>>()?,
        )),
        Value::Object(o) => Ok(Value::Object(
            o.iter()
                .map(|(k, v)| Ok((k.clone(), resolve(v, constants)?)))
                .collect::<Result<_>>()?,
        )),
        _ => Ok(value.clone()),
    }
}

fn normalize(path: &str) -> Result<String> {
    if path.split('/').any(|p| p == "..") {
        return Err(format!("path-dotdot-refused {path}"));
    }
    if !path.starts_with('/') {
        return Err(format!("path-not-absolute {path}"));
    }
    let parts: Vec<_> = path
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    Ok(format!("/{}", parts.join("/")))
}

fn files(root: &Path) -> Result<Vec<PathBuf>> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }
        let mut entries = fs::read_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| e.to_string())?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let ty = entry.file_type().map_err(|e| e.to_string())?;
            let path = entry.path();
            if ty.is_dir() {
                walk(root, &path, out)?;
            } else if ty.is_file() || ty.is_symlink() {
                out.push(
                    path.strip_prefix(root)
                        .map_err(|e| e.to_string())?
                        .to_path_buf(),
                );
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

fn module_list(root: &Path, profile: &Value) -> Result<Vec<(String, bool)>> {
    let mut modules = Vec::new();
    if let Some(base) = profile.get("extends").and_then(Value::as_str) {
        let base_profile = read_json(&root.join("profiles").join(base).join("index.json"))?;
        if !base_profile["extends"].is_null() {
            return Err("profile-extends-chain-refused".into());
        }
        let excludes: BTreeSet<_> = strings(&profile["excludes"]).into_iter().collect();
        for m in strings(&base_profile["modules"]) {
            if !excludes.contains(&m) {
                modules.push((m, true));
            }
        }
    }
    modules.extend(strings(&profile["modules"]).into_iter().map(|m| (m, false)));
    Ok(modules)
}

fn apply_profile_input(
    manifest: &mut Value,
    module_dir: &Path,
    profile: &str,
    base: Option<&str>,
) -> Result<()> {
    let Some(selector) = manifest
        .get("profile_input")
        .filter(|v| !v.is_null())
        .cloned()
    else {
        return Ok(());
    };
    let fragment = selector["fragment"]
        .as_str()
        .ok_or("profile-input-fragment-invalid")?;
    let files_root = manifest["files_root"]
        .as_str()
        .ok_or("profile-input-files-root-missing")?;
    let root = module_dir.join(files_root);
    let mut choices = vec![profile];
    if let Some(b) = base {
        choices.push(b);
    }
    if let Some(f) = selector["fallback"].as_str() {
        choices.push(f);
    }
    let file = choices
        .iter()
        .map(|id| root.join(id).join(fragment))
        .find(|p| p.is_file())
        .ok_or_else(|| format!("profile-input-fragment-missing profile={profile}"))?;
    let selected = read_json(&file)?;
    let step = manifest["ladder"]
        .as_array_mut()
        .and_then(|steps| {
            steps
                .iter_mut()
                .find(|s| s["tool"] == "service-runtime" && s["permutation"] == "converge")
        })
        .ok_or("profile-input-service-runtime-step-missing")?;
    let args = step["args"]
        .as_object_mut()
        .ok_or("profile-input-service-runtime-args-invalid")?;
    for key in ["url", "managed_files"] {
        if let Some(v) = selected.get(key) {
            args.insert(key.to_owned(), v.clone());
        }
    }
    Ok(())
}

struct Pool<'a> {
    registry: &'a Value,
    module: &'a str,
    module_dir: &'a Path,
    manifest: &'a Value,
    constants: &'a Map<String, Value>,
    paths: Vec<Value>,
    operations: Vec<Value>,
}

impl Pool<'_> {
    fn step(&mut self, step: &Value, parent: Option<&str>) -> Result<()> {
        let name = if parent.is_some() {
            step["name"].as_str().unwrap_or("")
        } else {
            step["step_id"].as_str().unwrap_or("")
        };
        let id = parent
            .map(|p| format!("{p}/{name}"))
            .unwrap_or_else(|| name.to_string());
        self.step_inner(step, parent.is_some(), &id)
            .map_err(|e| format!("module={} step={id}: {e}", self.module))?;
        for child in array(&step["steps"]) {
            self.step(child, Some(&id))?;
        }
        Ok(())
    }

    fn step_inner(&mut self, step: &Value, child: bool, id: &str) -> Result<()> {
        let tool = step["tool"].as_str().unwrap_or("");
        let entry = array(&self.registry["entries"])
            .iter()
            .find(|e| e["name"] == tool)
            .ok_or_else(|| format!("undeclared-tool {tool}"))?;
        let permutation = step["permutation"].as_str().unwrap_or_else(|| {
            if child {
                entry["permutations"][0]["name"].as_str().unwrap_or("")
            } else {
                "execute"
            }
        });
        let perm = array(&entry["permutations"])
            .iter()
            .find(|p| p["name"] == permutation)
            .ok_or_else(|| format!("undeclared-permutation {tool}.{permutation}"))?;
        let args = resolve(&step["args"], self.constants)?;
        let label = format!("{tool}.{permutation}");
        for rule in array(&perm["touches"]["paths"]) {
            let mut paths = Vec::new();
            if let Some(arg) = rule["arg"].as_str() {
                for p in strings(&args[arg]) {
                    if rule["tree"] == true {
                        paths.push(format!("{}/**", p.trim_end_matches('/')));
                    }
                    paths.push(p);
                }
            } else if let Some(join) = rule.get("join") {
                let root = join["root_fixed"]
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| {
                        join["root"]
                            .as_str()
                            .and_then(|k| args[k].as_str())
                            .map(str::to_owned)
                    })
                    .unwrap_or_else(|| "/".into());
                let leaves = if let Some(k) = join["list"].as_str().or_else(|| join["arg"].as_str())
                {
                    strings(&args[k])
                } else {
                    strings(&join["fixed"])
                };
                for leaf in leaves {
                    paths.push(format!(
                        "{}/{}",
                        root.trim_end_matches('/'),
                        leaf.trim_start_matches('/')
                    ));
                }
            } else if let (Some(list), Some(field)) =
                (rule["list"].as_str(), rule["field"].as_str())
            {
                for item in array(&args[list]) {
                    paths.extend(strings(&item[field]));
                }
            } else if let Some(tree) = rule.get("source_tree") {
                if args.get("files").is_none() {
                    if let Some(source) = tree["source"].as_str().and_then(|k| args[k].as_str()) {
                        let source_path = Path::new(source);
                        let source_path = if source_path.is_absolute() {
                            source_path.to_path_buf()
                        } else {
                            self.module_dir.join(source_path)
                        };
                        let target = tree["root"]
                            .as_str()
                            .and_then(|k| args[k].as_str())
                            .unwrap_or("/");
                        for file in files(&source_path)? {
                            paths.push(format!(
                                "{}/{}",
                                target.trim_end_matches('/'),
                                file.display()
                            ));
                        }
                    }
                }
            } else if rule["files_root"] == true {
                if args.get("files").is_none() {
                    if let Some(root) = self.manifest["files_root"].as_str() {
                        for file in files(&self.module_dir.join(root))? {
                            paths.push(format!("/{}", file.display()));
                        }
                    }
                }
            } else if let Some(fixed) = rule["fixed"].as_str() {
                if rule["when"]
                    .as_str()
                    .map(|k| !args[k].is_null())
                    .unwrap_or(true)
                {
                    paths.push(fixed.to_owned());
                }
            }
            for path in paths {
                let path = normalize(&path)?;
                self.paths
                    .push(json!({"path": path, "module": self.module, "step": id, "tool": label}));
            }
        }
        for rule in array(&perm["touches"]["operations"]) {
            let kind = rule["kind"].as_str().unwrap_or("");
            let values = if kind == "package-upgrade" {
                vec!["*".to_owned()]
            } else if let Some(arg) = rule["arg"].as_str() {
                strings(&args[arg])
            } else {
                strings(&rule["fixed"])
            };
            for value in values {
                self.operations
                    .push(json!({"kind": kind, "match": value, "module": self.module, "step": id}));
            }
        }
        Ok(())
    }
}

fn sort_rows(rows: &mut Vec<Value>, keys: &[&str]) {
    rows.sort_by(|a, b| {
        for key in keys {
            let order = a[*key].as_str().cmp(&b[*key].as_str());
            if !order.is_eq() {
                return order;
            }
        }
        a.to_string().cmp(&b.to_string())
    });
    rows.dedup();
}

fn build(root: &Path, profile_id: &str, registry: &Value, clobbered: &Value) -> Result<Vec<u8>> {
    let profile = read_json(&root.join("profiles").join(profile_id).join("index.json"))?;
    let base = profile["extends"].as_str();
    let mut paths = Vec::new();
    let mut operations = Vec::new();
    for (module, from_base) in module_list(root, &profile)? {
        let owner = if from_base {
            base.unwrap_or(profile_id)
        } else {
            profile_id
        };
        let local = root
            .join("profiles")
            .join(owner)
            .join("modules")
            .join(&module);
        let module_dir = if local.join("manifest.json").is_file() {
            local
        } else {
            root.join("shared/modules").join(&module)
        };
        let mut manifest = read_json(&module_dir.join("manifest.json"))
            .map_err(|e| format!("module={module} step=<load>: {e}"))?;
        apply_profile_input(&mut manifest, &module_dir, profile_id, base)
            .map_err(|e| format!("module={module} step=<load>: {e}"))?;
        let mut constants = manifest["constants"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        if !manifest["login_shell"].is_null() {
            constants.insert("login_shell".into(), manifest["login_shell"].clone());
        }
        let mut pool = Pool {
            registry,
            module: &module,
            module_dir: &module_dir,
            manifest: &manifest,
            constants: &constants,
            paths: Vec::new(),
            operations: Vec::new(),
        };
        for step in array(&manifest["ladder"]) {
            pool.step(step, None)?;
        }
        paths.extend(pool.paths);
        operations.extend(pool.operations);
    }
    let mut interactable = Vec::new();
    let mut hotfix = Vec::new();
    for row in paths {
        let path = row["path"].as_str().unwrap_or("");
        let config = ["/etc", "/home", "/root"].iter().any(|prefix| {
            path == *prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|s| s.starts_with('/'))
        }) || path.contains("config_deploy:interactable");
        if config {
            interactable.push(row);
        } else {
            hotfix.push(row);
        }
    }
    let mut own = Vec::new();
    for row in array(clobbered) {
        let path = normalize(row["path"].as_str().ok_or("clobbered-path-missing")?)?;
        own.push(json!({"path":path,"module":null,"step":null,"tool":null,"note":row["note"]}));
    }
    sort_rows(&mut interactable, &["path", "module", "step"]);
    sort_rows(&mut hotfix, &["path", "module", "step"]);
    sort_rows(&mut own, &["path", "module", "step"]);
    sort_rows(&mut operations, &["kind", "match", "module", "step"]);
    let value = json!({"schema":"harmonia.touch.resolved.v1", "profile":profile_id, "interactable":interactable, "hotfix":hotfix, "clobbered":own, "operations":operations});
    let mut bytes = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn generate(component: &str) {
    for path in [
        "profiles",
        "shared/modules",
        "src/tools/index.json",
        "schema/harmonia.touch.v1.json",
        "schema/touch/resolved",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=HARMONIA_WRITE_RESOLVED");
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let run = || -> Result<()> {
        let registry = read_json(&root.join("src/tools/index.json"))?;
        let schema = read_json(&root.join("schema/harmonia.touch.v1.json"))?;
        let mut profiles = fs::read_dir(root.join("profiles"))
            .map_err(|e| e.to_string())?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| e.to_string())?;
        profiles.sort_by_key(|e| e.file_name());
        for dir in profiles {
            if !dir.path().join("index.json").is_file() {
                continue;
            }
            let profile = dir
                .file_name()
                .into_string()
                .map_err(|_| "profile-name-not-utf8")?;
            let result = build(&root, &profile, &registry, &schema["clobbered"]).and_then(|bytes| {
                let output = root.join("schema/touch/resolved").join(format!("{profile}.json"));
                if env::var("HARMONIA_WRITE_RESOLVED").as_deref() == Ok("1") {
                    fs::create_dir_all(output.parent().unwrap()).map_err(|e| e.to_string())?;
                    fs::write(&output, bytes).map_err(|e| e.to_string())?;
                } else if fs::read(&output).ok().as_deref() != Some(bytes.as_slice()) {
                    return Err(format!("touch-resolved-stale {profile}; regenerate with HARMONIA_WRITE_RESOLVED=1 HARMONIA_COMPONENT=harmonia cargo build --release --locked"));
                }
                Ok(())
            });
            if let Err(e) = result {
                let message = format!("profile={profile} {e}");
                if component == "harmonia-monad" {
                    println!("cargo:warning={message}");
                } else {
                    return Err(message);
                }
            }
        }
        Ok(())
    };
    if let Err(e) = run() {
        if component == "harmonia-monad" {
            println!("cargo:warning={e}");
        } else {
            panic!("{e}");
        }
    }
}
