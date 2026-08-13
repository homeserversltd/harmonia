use crate::tools::comparison::{self, ComparisonRun, DiffDecision};
use serde_json::json;
use std::cell::Cell;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::thread;

pub(crate) fn run(invocation: Option<crate::atoms::r#do::InvocationKey>) -> Result<(), String> {
    let invocation =
        invocation.ok_or_else(|| "stillness-bench-invocation-key-missing".to_string())?;
    let root = std::env::temp_dir().join(format!(
        "harmonia-stillness-bench-{}",
        crate::run_id_from_stamp()
    ));
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;

    let caduceus = caduceus_bench(&root)?;
    let venv = venv_bench(&root, invocation)?;
    let never = never_converge_bench()?;
    let receipt = json!({
        "schema": "harmonia.stillness-bench.v1",
        "ok": true,
        "caduceus": caduceus,
        "venv": venv,
        "never_converge": never,
    });
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|error| error.to_string())?
    );
    fs::remove_dir_all(&root).map_err(|error| error.to_string())?;
    Ok(())
}

fn caduceus_bench(root: &Path) -> Result<serde_json::Value, String> {
    let dir = root.join("caduceus");
    fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    let artifact = dir.join("target/release/caduceus");
    let install = dir.join("usr/local/bin/caduceus");
    fs::create_dir_all(artifact.parent().unwrap()).map_err(|error| error.to_string())?;
    fs::write(&artifact, b"caduceus-bench-artifact-v1\n").map_err(|error| error.to_string())?;
    let source_sha = "0123456789abcdef0123456789abcdef01234567".to_string();
    let run1 = crate::tools::service_runtime::bench_binary_install(
        &dir.join("run1"),
        &artifact,
        &install,
    )?;
    let health1 = serve_health_once(&source_sha, |url| {
        crate::tools::service_runtime::bench_health_identity(
            &dir.join("run1"),
            url,
            source_sha.clone(),
        )
    })?;
    let run2 = crate::tools::service_runtime::bench_binary_install(
        &dir.join("run2"),
        &artifact,
        &install,
    )?;
    let health2 = serve_health_once(&source_sha, |url| {
        crate::tools::service_runtime::bench_health_identity(
            &dir.join("run2"),
            url,
            source_sha.clone(),
        )
    })?;
    if !run1.ok || !run1.changed || !health1.ok || run2.changed || !run2.ok || !health2.ok {
        return Err("caduceus-shaped-bench-failed".to_string());
    }
    Ok(json!({
        "run1": {"ok": run1.ok, "changed": run1.changed, "operations": 1, "health_build_sha": source_sha, "source_sha": source_sha},
        "run2": {"ok": run2.ok, "changed": run2.changed, "operations": 0, "health_build_sha": source_sha, "source_sha": source_sha}
    }))
}

fn serve_health_once<T>(
    source_sha: &str,
    run: impl FnOnce(String) -> Result<T, String>,
) -> Result<T, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let body = json!({"ok": true, "build_sha": source_sha}).to_string();
    let server = thread::spawn(move || -> Result<(), String> {
        let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
        let mut request = [0_u8; 2048];
        let _ = stream
            .read(&mut request)
            .map_err(|error| error.to_string())?;
        let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
        stream
            .write_all(response.as_bytes())
            .map_err(|error| error.to_string())
    });
    let result = run(format!("http://{address}/health"));
    server
        .join()
        .map_err(|_| "health-bench-server-panicked".to_string())??;
    result
}

fn venv_bench(
    root: &Path,
    invocation: crate::atoms::r#do::InvocationKey,
) -> Result<serde_json::Value, String> {
    let dir = root.join("venv");
    let source = dir.join("source");
    let venv = dir.join("venv");
    let receipts = dir.join("receipts");
    fs::create_dir_all(&source).map_err(|error| error.to_string())?;
    let request = crate::build_venv::Request {
        venv: &venv,
        source_root: &source,
        source_patterns: &[],
        python: Path::new("/usr/bin/python3"),
        receipt_dir: &receipts,
        receipt_name: "venv-bench.json",
        timeout_secs: 30,
    };
    let run1 = crate::build_venv::run(&request, true, Some(invocation))?;
    let run2 = crate::build_venv::run(&request, true, Some(invocation))?;
    if !run1.ok || !run1.changed || !run2.ok || run2.changed {
        return Err("venv-double-run-bench-failed".to_string());
    }
    Ok(json!({
        "run1": {"ok": run1.ok, "changed": run1.changed, "message": run1.message},
        "run2": {"ok": run2.ok, "changed": run2.changed, "message": run2.message}
    }))
}

fn never_converge_bench() -> Result<serde_json::Value, String> {
    let acted = Cell::new(false);
    let result = comparison::execute(
        "forced-never-converge",
        || Ok::<bool, String>(acted.get()),
        |_| DiffDecision::Different,
        |_, _| {
            acted.set(true);
            Ok::<(), String>(())
        },
    );
    match result {
        Err(signal) if signal == "forced-never-converge-act-did-not-converge" => Ok(json!({
            "ok": false,
            "acted": acted.get(),
            "signal": signal
        })),
        Ok(ComparisonRun::Current { .. }) | Ok(ComparisonRun::Moved { .. }) => {
            Err("never-converge-bench-did-not-fail".to_string())
        }
        Err(signal) => Err(format!("never-converge-bench-wrong-signal {signal}")),
    }
}
