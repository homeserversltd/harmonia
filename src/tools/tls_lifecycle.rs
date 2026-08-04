use super::{ToolArg, ToolArgKind, ToolContract, ToolPermutation};
use crate::module_dispatch::ModuleExecution;
use crate::tools::comparison::{self, DiffDecision};
use crate::write_json;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const NAME: &str = "tls-lifecycle";
pub const DESCRIPTION: &str = "Native TLS leaf lifecycle primitive: observe, compare, locally create CSR, sign, validate, atomically promote, and receipt.";
pub const PERMUTATIONS: &[ToolPermutation] = &[ToolPermutation::new(
    "converge",
    "converge one locally keyed TLS leaf through the declared household signer",
    &[
        ToolArg::required("key_dir", ToolArgKind::String),
        ToolArg::required("key_path", ToolArgKind::String),
        ToolArg::required("csr_path", ToolArgKind::String),
        ToolArg::required("leaf_path", ToolArgKind::String),
        ToolArg::required("chain_path", ToolArgKind::String),
        ToolArg::required("root_path", ToolArgKind::String),
        ToolArg::required("signer_url", ToolArgKind::String),
        ToolArg::required("identity", ToolArgKind::String),
        ToolArg::required("san_dns", ToolArgKind::String),
        ToolArg::required("san_ip", ToolArgKind::String),
        ToolArg::optional("attendance_file", ToolArgKind::String),
        ToolArg::optional("renew_before_secs", ToolArgKind::Integer),
    ],
)];
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION, PERMUTATIONS);

#[derive(Clone)]
struct Spec {
    key_dir: PathBuf,
    key: PathBuf,
    csr: PathBuf,
    leaf: PathBuf,
    chain: PathBuf,
    root: PathBuf,
    signer: String,
    identity: String,
    dns: String,
    ip: String,
    attendance: Option<PathBuf>,
    renew_before: u64,
}

#[derive(Clone)]
struct Observation {
    key: bool,
    root: bool,
    leaf: bool,
    chain: bool,
    verify: bool,
    unexpired: bool,
}

fn text(args: &BTreeMap<String, Value>, name: &str) -> Result<String, String> {
    args.get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| format!("tls-lifecycle-missing-{name}"))
}

pub(crate) fn validate_ladder_args(args: &BTreeMap<String, Value>) -> Result<(), String> {
    let _ = spec(args)?;
    Ok(())
}

fn contained_path(
    args: &BTreeMap<String, Value>,
    name: &str,
    root: &Path,
) -> Result<PathBuf, String> {
    let path = PathBuf::from(text(args, name)?);
    if !path.starts_with(root) {
        return Err(format!("tls-lifecycle-{name}-outside-key-dir"));
    }
    Ok(path)
}

fn spec(args: &BTreeMap<String, Value>) -> Result<Spec, String> {
    let signer = text(args, "signer_url")?;
    if !signer.starts_with("https://") && !signer.starts_with("http://") {
        return Err("tls-lifecycle-signer-url-invalid".into());
    }
    let identity = text(args, "identity")?;
    if identity != "console.home.arpa" {
        return Err("tls-lifecycle-identity-refused".into());
    }
    let dns = text(args, "san_dns")?;
    let ip = text(args, "san_ip")?;
    if dns != identity || ip != "192.168.123.19" {
        return Err("tls-lifecycle-san-refused".into());
    }
    let key_dir = PathBuf::from(text(args, "key_dir")?);
    Ok(Spec {
        key: contained_path(args, "key_path", &key_dir)?,
        csr: contained_path(args, "csr_path", &key_dir)?,
        leaf: contained_path(args, "leaf_path", &key_dir)?,
        chain: contained_path(args, "chain_path", &key_dir)?,
        root: PathBuf::from(text(args, "root_path")?),
        signer,
        identity,
        dns,
        ip,
        attendance: args
            .get("attendance_file")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
        renew_before: args
            .get("renew_before_secs")
            .and_then(Value::as_u64)
            .unwrap_or(2_592_000),
        key_dir,
    })
}

fn run(
    program: &str,
    args: &[String],
    stdin: Option<&[u8]>,
) -> Result<(bool, String, String), String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("tls-lifecycle-command-unavailable-{program}: {error}"))?;
    if let Some(body) = stdin {
        child
            .stdin
            .take()
            .ok_or("tls-lifecycle-stdin-unavailable")?
            .write_all(body)
            .map_err(|error| format!("tls-lifecycle-stdin-write-failed: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

fn observe(spec: &Spec) -> Observation {
    let leaf = spec.leaf.is_file();
    let root = spec.root.is_file();
    let chain = spec.chain.is_file();
    let key = spec.key.is_file();
    let verify = leaf
        && root
        && run(
            "openssl",
            &vec![
                "verify".into(),
                "-CAfile".into(),
                spec.root.display().to_string(),
                spec.leaf.display().to_string(),
            ],
            None,
        )
        .map(|result| result.0)
        .unwrap_or(false);
    let unexpired = verify
        && run(
            "openssl",
            &vec![
                "x509".into(),
                "-checkend".into(),
                spec.renew_before.to_string(),
                "-noout".into(),
                "-in".into(),
                spec.leaf.display().to_string(),
            ],
            None,
        )
        .map(|result| result.0)
        .unwrap_or(false);
    Observation {
        key,
        root,
        leaf,
        chain,
        verify,
        unexpired,
    }
}

fn observed_state(observation: &Observation) -> Value {
    json!({
        "key": observation.key,
        "root": observation.root,
        "leaf": observation.leaf,
        "chain": observation.chain,
        "chain_to_installed_house_root": observation.verify,
        "unexpired": observation.unexpired,
    })
}

fn desired_state(spec: &Spec) -> Value {
    json!({
        "identity": spec.identity,
        "san_dns": spec.dns,
        "san_ip": spec.ip,
        "valid_unexpired_leaf": true,
        "chain_to_installed_house_root": true,
        "renew_before_secs": spec.renew_before,
    })
}

fn sign_request_shape(spec: &Spec) -> Value {
    json!({
        "method": "POST",
        "url": spec.signer,
        "content_type": "application/json",
        "required_header": "x-caduceus-attendance",
        "body": { "csrPem": "<fresh-local-csr-pem>" },
    })
}

fn atomically_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path.parent().ok_or("tls-lifecycle-path-parent-missing")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let staged = parent.join(format!(
        ".{}.next",
        path.file_name()
            .and_then(|value| value.to_str())
            .ok_or("tls-lifecycle-path-invalid")?
    ));
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(mode)
        .open(&staged)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fs::set_permissions(&staged, fs::Permissions::from_mode(mode))
        .map_err(|error| error.to_string())?;
    fs::rename(staged, path).map_err(|error| error.to_string())?;
    Ok(())
}

fn fingerprint(path: &Path) -> Result<String, String> {
    let (ok, stdout, stderr) = run(
        "openssl",
        &vec![
            "x509".into(),
            "-in".into(),
            path.display().to_string(),
            "-noout".into(),
            "-fingerprint".into(),
            "-sha256".into(),
        ],
        None,
    )?;
    if ok {
        Ok(stdout.trim().to_string())
    } else {
        Err(format!("tls-lifecycle-fingerprint-failed {stderr}"))
    }
}

fn not_after(path: &Path) -> Result<String, String> {
    let (ok, stdout, stderr) = run(
        "openssl",
        &vec![
            "x509".into(),
            "-in".into(),
            path.display().to_string(),
            "-noout".into(),
            "-enddate".into(),
        ],
        None,
    )?;
    if ok {
        Ok(stdout.trim().to_string())
    } else {
        Err(format!("tls-lifecycle-expiry-failed {stderr}"))
    }
}

fn retain_prior(path: &Path) -> Result<PathBuf, String> {
    let prior = path.with_extension("pem.previous");
    if path.exists() {
        fs::rename(path, &prior)
            .map_err(|error| format!("tls-lifecycle-rollback-retain-failed {error}"))?;
    }
    Ok(prior)
}

fn act(spec: &Spec, before: &Observation) -> Result<(bool, Value), String> {
    fs::create_dir_all(&spec.key_dir).map_err(|error| error.to_string())?;
    fs::set_permissions(&spec.key_dir, fs::Permissions::from_mode(0o750))
        .map_err(|error| error.to_string())?;
    if !spec.key.is_file() {
        let (ok, _, stderr) = run(
            "openssl",
            &vec![
                "genrsa".into(),
                "-out".into(),
                spec.key.display().to_string(),
                "2048".into(),
            ],
            None,
        )?;
        if !ok {
            return Err(format!("tls-lifecycle-key-create-failed {stderr}"));
        }
        fs::set_permissions(&spec.key, fs::Permissions::from_mode(0o640))
            .map_err(|error| error.to_string())?;
    }
    let config = spec.key_dir.join("console-csr.cnf");
    atomically_write(
        &config,
        format!(
            "[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=ext\n[dn]\nCN={}\n[ext]\nsubjectAltName=DNS:{},IP:{}\n",
            spec.identity, spec.dns, spec.ip
        ).as_bytes(),
        0o600,
    )?;
    let (ok, _, stderr) = run(
        "openssl",
        &vec![
            "req".into(),
            "-new".into(),
            "-key".into(),
            spec.key.display().to_string(),
            "-out".into(),
            spec.csr.display().to_string(),
            "-config".into(),
            config.display().to_string(),
        ],
        None,
    )?;
    if !ok {
        return Err(format!("tls-lifecycle-csr-create-failed {stderr}"));
    }
    fs::set_permissions(&spec.csr, fs::Permissions::from_mode(0o640))
        .map_err(|error| error.to_string())?;
    let csr = fs::read_to_string(&spec.csr).map_err(|error| error.to_string())?;
    let mut curl = vec![
        "--fail-with-body".into(),
        "--silent".into(),
        "--show-error".into(),
        "--max-time".into(),
        "20".into(),
        "-X".into(),
        "POST".into(),
        "-H".into(),
        "content-type: application/json".into(),
    ];
    if let Some(attendance) = &spec.attendance {
        let token = fs::read_to_string(attendance)
            .map_err(|error| format!("tls-lifecycle-attendance-read-failed {error}"))?;
        curl.extend([
            "-H".into(),
            format!("x-caduceus-attendance: {}", token.trim()),
        ]);
    }
    curl.extend(["--data-binary".into(), "@-".into(), spec.signer.clone()]);
    let body = serde_json::to_vec(&json!({ "csrPem": csr })).map_err(|error| error.to_string())?;
    let (ok, response_body, stderr) = run("curl", &curl, Some(&body))?;
    if !ok {
        return Err(format!("tls-lifecycle-signer-refused {stderr}"));
    }
    let response: Value = serde_json::from_str(&response_body)
        .map_err(|error| format!("tls-lifecycle-signer-response-invalid {error}"))?;
    let leaf = response
        .get("leaf_pem")
        .and_then(Value::as_str)
        .ok_or("tls-lifecycle-signer-leaf-missing")?;
    let ca = response
        .get("ca_pem")
        .and_then(Value::as_str)
        .ok_or("tls-lifecycle-signer-ca-missing")?;
    let staged_leaf = spec.key_dir.join("leaf.validation.pem");
    let staged_ca = spec.key_dir.join("ca.validation.pem");
    atomically_write(&staged_leaf, leaf.as_bytes(), 0o640)?;
    atomically_write(&staged_ca, ca.as_bytes(), 0o644)?;
    let root_fingerprint = fingerprint(&spec.root)?;
    if fingerprint(&staged_ca)? != root_fingerprint {
        return Err("tls-lifecycle-root-fingerprint-mismatch".into());
    }
    let (verified, _, verify_stderr) = run(
        "openssl",
        &vec![
            "verify".into(),
            "-CAfile".into(),
            spec.root.display().to_string(),
            staged_leaf.display().to_string(),
        ],
        None,
    )?;
    if !verified {
        return Err(format!(
            "tls-lifecycle-returned-leaf-invalid {verify_stderr}"
        ));
    }
    let prior_leaf = retain_prior(&spec.leaf)?;
    let prior_chain = retain_prior(&spec.chain)?;
    atomically_write(&spec.leaf, leaf.as_bytes(), 0o640)?;
    atomically_write(&spec.chain, format!("{leaf}{ca}").as_bytes(), 0o644)?;
    let _ = fs::remove_file(staged_leaf);
    let _ = fs::remove_file(staged_ca);
    let _ = fs::remove_file(config);
    Ok((
        true,
        json!({
            "schema": "harmonia.tls_lifecycle.receipt.v1",
            "observed_state": observed_state(before),
            "desired_state": desired_state(spec),
            "diff_decision": "different",
            "movement": "promoted",
            "changed": true,
            "trust_changed": false,
            "sign_request": sign_request_shape(spec),
            "key_path": spec.key,
            "csr_path": spec.csr,
            "leaf_path": spec.leaf,
            "chain_path": spec.chain,
            "previous_leaf_path": prior_leaf,
            "previous_chain_path": prior_chain,
            "root_fingerprint": root_fingerprint,
            "leaf_fingerprint": fingerprint(&spec.leaf)?,
            "expiry": not_after(&spec.leaf)?,
        }),
    ))
}

pub(crate) fn execute_ladder_step(
    args: &BTreeMap<String, Value>,
    receipt_dir: &Path,
    apply: bool,
) -> Result<ModuleExecution, String> {
    let spec = spec(args)?;
    let run = comparison::execute(
        || Ok::<_, String>(observe(&spec)),
        |observation| {
            if observation.key
                && observation.root
                && observation.leaf
                && observation.chain
                && observation.verify
                && observation.unexpired
            {
                DiffDecision::Empty
            } else {
                DiffDecision::Different
            }
        },
        |_, observation| {
            if apply {
                act(&spec, observation)
            } else {
                Ok((
                    false,
                    json!({
                        "schema": "harmonia.tls_lifecycle.receipt.v1",
                        "observed_state": observed_state(observation),
                        "desired_state": desired_state(&spec),
                        "diff_decision": "different",
                        "movement": "planned",
                        "changed": false,
                        "trust_changed": false,
                        "sign_request": sign_request_shape(&spec),
                        "key_path": spec.key,
                        "csr_path": spec.csr,
                        "leaf_path": spec.leaf,
                        "chain_path": spec.chain,
                    }),
                ))
            }
        },
    )?;
    let (changed, receipt) = match run {
        comparison::ComparisonRun::Current { observation, .. } => (
            false,
            json!({
                "schema": "harmonia.tls_lifecycle.receipt.v1",
                "observed_state": observed_state(&observation),
                "desired_state": desired_state(&spec),
                "diff_decision": "empty",
                "movement": "unreachable",
                "changed": false,
                "trust_changed": false,
                "key_path": spec.key,
                "leaf_path": spec.leaf,
                "chain_path": spec.chain,
            }),
        ),
        comparison::ComparisonRun::Moved { movement, .. } => movement,
    };
    write_json(&receipt_dir.join("tls-lifecycle.json"), &receipt)?;
    Ok(ModuleExecution {
        ok: true,
        changed,
        operation_count: 1,
        first_missing_signal: None,
    })
}
