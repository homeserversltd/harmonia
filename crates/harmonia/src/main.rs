use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
struct Profile {
    id: String,
    family: String,
    modules: Vec<String>,
}

fn main() {
    if let Err(err) = run(env::args().skip(1).collect()) {
        eprintln!("harmonia_error={}", err);
        process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("explain") => explain(),
        Some("inspect-profile") => {
            let path = args
                .get(1)
                .ok_or("inspect-profile requires <profile-index-json>")?;
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            println!("schema=harmonia.profile.inspect.v1");
            println!("ok=true");
            println!("profile_id={}", profile.id);
            println!("profile_family={}", profile.family);
            println!("module_count={}", profile.modules.len());
            println!("modules={}", profile.modules.join(","));
            Ok(())
        }
        Some("plan-run") => {
            let path = args
                .get(1)
                .ok_or("plan-run requires <profile-index-json>")?;
            let receipt_dir =
                receipt_dir_arg(&args).unwrap_or_else(|| PathBuf::from("target/harmonia-receipts"));
            let profile = load_profile(Path::new(path)).map_err(|e| e.to_string())?;
            write_plan_receipts(&profile, &receipt_dir).map_err(|e| e.to_string())?;
            println!("schema=harmonia.plan_run.v1");
            println!("ok=true");
            println!("profile_id={}", profile.id);
            println!("receipt_dir={}", receipt_dir.display());
            println!("mutation=false");
            Ok(())
        }
        _ => usage(),
    }
}

fn explain() -> Result<(), String> {
    println!("schema=harmonia.explain.v1");
    println!("ok=true");
    println!("name=harmonia");
    println!("version={}", VERSION);
    println!("covenant=Rust-only Chrysalis update suite/toolchain");
    println!("shell=bootstrap-only");
    println!("python_helper_lane=false");
    println!("profiles=homeserver,homeconsole,tv");
    println!("homeconsole_equals_arch_console=true");
    Ok(())
}

fn usage() -> Result<(), String> {
    println!("harmonia {}", VERSION);
    println!("usage:");
    println!("  harmonia explain");
    println!("  harmonia inspect-profile <profiles/<id>/index.json>");
    println!("  harmonia plan-run <profiles/<id>/index.json> [--receipt-dir <path>]");
    Ok(())
}

fn receipt_dir_arg(args: &[String]) -> Option<PathBuf> {
    args.windows(2)
        .find(|pair| pair[0] == "--receipt-dir")
        .map(|pair| PathBuf::from(&pair[1]))
}

fn load_profile(path: &Path) -> io::Result<Profile> {
    let text = fs::read_to_string(path)?;
    let id = extract_string(&text, "id").unwrap_or_else(|| "unknown".to_string());
    let family = extract_string(&text, "family").unwrap_or_else(|| id.clone());
    let modules = extract_string_array(&text, "modules");
    Ok(Profile {
        id,
        family,
        modules,
    })
}

fn extract_string(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let start = text.find(&needle)?;
    let after_key = &text[start + needle.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let rest = after_colon.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_string_array(text: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{}\"", key);
    let Some(start) = text.find(&needle) else {
        return Vec::new();
    };
    let after_key = &text[start + needle.len()..];
    let Some(colon) = after_key.find(':') else {
        return Vec::new();
    };
    let after_colon = after_key[colon + 1..].trim_start();
    let Some(rest) = after_colon.strip_prefix('[') else {
        return Vec::new();
    };
    let Some(end) = rest.find(']') else {
        return Vec::new();
    };
    rest[..end]
        .split(',')
        .filter_map(|item| {
            let t = item.trim();
            let t = t.strip_prefix('"')?.strip_suffix('"')?;
            Some(t.to_string())
        })
        .collect()
}

fn write_plan_receipts(profile: &Profile, receipt_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(receipt_dir)?;
    let mut events = File::create(receipt_dir.join("events.jsonl"))?;
    writeln!(
        events,
        "{{\"event\":\"plan-start\",\"profile\":\"{}\",\"ok\":true}}",
        profile.id
    )?;
    for module in &profile.modules {
        writeln!(
            events,
            "{{\"event\":\"module-planned\",\"module\":\"{}\",\"ok\":true}}",
            module
        )?;
    }
    let mut run = File::create(receipt_dir.join("run.json"))?;
    writeln!(run, "{{")?;
    writeln!(run, "  \"schema\": \"harmonia.run.v1\",")?;
    writeln!(run, "  \"ok\": true,")?;
    writeln!(run, "  \"mutation\": false,")?;
    writeln!(run, "  \"profile_id\": \"{}\",", profile.id)?;
    writeln!(run, "  \"profile_family\": \"{}\",", profile.family)?;
    writeln!(run, "  \"module_count\": {}", profile.modules.len())?;
    writeln!(run, "}}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_profile_fields() {
        let text =
            r#"{"id":"homeconsole","family":"arch-console","modules":["identity","packages"]}"#;
        assert_eq!(extract_string(text, "id").unwrap(), "homeconsole");
        assert_eq!(extract_string(text, "family").unwrap(), "arch-console");
        assert_eq!(
            extract_string_array(text, "modules"),
            vec!["identity", "packages"]
        );
    }
}
