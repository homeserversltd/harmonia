use std::env;
use std::io::Write;
use std::process::{Command, Stdio};

fn command_stdout(command: &str, args: &[&str]) -> Option<Vec<u8>> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let mut stdout = String::from_utf8(output.stdout).ok()?.into_bytes();
    while stdout.last() == Some(&b'\n') {
        stdout.pop();
    }
    Some(stdout)
}

fn compute_build_env_sha() -> Option<String> {
    let rustc_output = command_stdout("rustc", &["-Vv"])?;
    let cargo_output = command_stdout("cargo", &["-V"])?;

    let mut input = Vec::new();
    input.extend_from_slice(&rustc_output);
    input.push(b'\n');
    input.extend_from_slice(&cargo_output);
    input.push(b'\n');
    input.extend_from_slice(b"x86_64-unknown-linux-gnu\n");

    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.wait();
        return None;
    };
    if stdin.write_all(&input).is_err() {
        let _ = child.wait();
        return None;
    }
    drop(stdin);

    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let token = stdout.split_whitespace().next()?;
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some(token.to_string())
}

fn compute_rustc_version() -> String {
    let Some(output) = command_stdout("rustc", &["-Vv"]) else {
        return "unset".to_string();
    };
    let Ok(output) = String::from_utf8(output) else {
        return "unset".to_string();
    };
    let mut releases = output
        .lines()
        .filter_map(|line| line.strip_prefix("release:").map(str::trim));
    let Some(version) = releases.next() else {
        return "unset".to_string();
    };
    if releases.next().is_some()
        || version.split('.').count() != 3
        || version.split('.').any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        "unset".to_string()
    } else {
        version.to_string()
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=HARMONIA_COMPONENT");
    let component = env::var("HARMONIA_COMPONENT").unwrap_or_else(|_| "harmonia".to_string());
    println!("cargo:rustc-env=HARMONIA_COMPONENT={component}");

    println!("cargo:rerun-if-env-changed=HARMONIA_BUILD_ENV_SHA");
    match env::var("HARMONIA_BUILD_ENV_SHA") {
        Ok(value) => {
            assert!(
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "HARMONIA_BUILD_ENV_SHA must be exactly 64 lowercase hexadecimal characters"
            );
            println!("cargo:rustc-env=HARMONIA_BUILD_ENV_SHA={value}");
        }
        Err(_) => {
            let value = compute_build_env_sha().unwrap_or_else(|| "unset".to_string());
            println!("cargo:rustc-env=HARMONIA_BUILD_ENV_SHA={value}");
        }
    }
    println!(
        "cargo:rustc-env=HARMONIA_BUILD_RUSTC_VERSION={}",
        compute_rustc_version()
    );
}
