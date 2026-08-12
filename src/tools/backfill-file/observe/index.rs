use super::*;
use serde_json::{json, Map, Value};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub(super) fn file(
    path: &Path,
    declared_bytes: &[u8],
    declared_mode: Option<u32>,
    ownership: DeclaredOwnership,
    backup_path: Option<&Path>,
) -> Result<BackfillFileObservation, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!(
                "backfill-file-metadata-failed {}: {error}",
                path.display()
            ))
        }
    };
    let kind = crate::atoms::ask::path_kind(path)?;
    let existed = kind.is_some();
    let backup_exists = backup_path
        .map(crate::atoms::ask::path_kind)
        .transpose()?
        .flatten()
        .is_some();
    let regular = matches!(kind, Some(crate::atoms::ask::PathKind::RegularFile));
    let bytes_equal = regular && crate::atoms::ask::file(path)?.bytes == declared_bytes;
    let mode = if regular {
        crate::atoms::ask::file_mode(path).ok()
    } else {
        None
    };
    #[cfg(unix)]
    let (uid, gid) = metadata
        .as_ref()
        .map(|metadata| (Some(metadata.uid()), Some(metadata.gid())))
        .unwrap_or((None, None));
    #[cfg(not(unix))]
    let (uid, gid) = (None, None);
    Ok(BackfillFileObservation {
        existed,
        backup_exists,
        regular,
        bytes_equal,
        mode,
        mode_equal: regular && declared_mode.map_or(true, |wanted| mode == Some(wanted)),
        uid,
        gid,
        owner_equal: regular && ownership.uid.map_or(true, |wanted| uid == Some(wanted)),
        group_equal: regular && ownership.gid.map_or(true, |wanted| gid == Some(wanted)),
    })
}

pub(super) fn predicate(
    predicate: Option<&Value>,
    payload: Option<&Value>,
) -> Result<(bool, Value), String> {
    let family = predicate
        .and_then(Value::as_object)
        .and_then(|o| o.get("family"))
        .and_then(Value::as_str)
        .unwrap_or("Always");
    let args = predicate
        .and_then(Value::as_object)
        .and_then(|o| o.get("args"))
        .and_then(Value::as_object);
    let path_arg = |name: &str| {
        args.and_then(|a| a.get(name))
            .and_then(Value::as_str)
            .or_else(|| {
                payload
                    .and_then(Value::as_object)
                    .and_then(|a| a.get("target_path"))
                    .and_then(Value::as_str)
            })
            .ok_or_else(|| format!("hotfix-{family}-target-path-missing"))
    };
    match family {
        "Always" => Ok((true, json!({"family":"Always","condition":"always"}))),
        "FileAbsent" => {
            let path = path_arg("target_path")?;
            let absent = crate::atoms::ask::path_kind(Path::new(path))?.is_none();
            Ok((
                absent,
                json!({"family":family,"target_path":path,"condition":if absent{"absent"}else{"present"}}),
            ))
        }
        "FileMatchesExactly" => {
            let path = path_arg("target_path")?;
            let expected = args
                .and_then(|a| a.get("sha256"))
                .and_then(Value::as_str)
                .ok_or_else(|| "hotfix-file-matches-sha256-missing".to_string())?;
            if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("hotfix-file-matches-sha256-invalid".into());
            }
            let expected = expected.to_ascii_lowercase();
            let actual = crate::atoms::ask::file_if_present(Path::new(path))?
                .map(|o| o.sha256.to_ascii_lowercase());
            let matches = actual.as_deref() == Some(expected.as_str());
            Ok((
                matches,
                json!({"family":family,"target_path":path,"expected_sha256":expected,"actual_sha256":actual,"condition":if matches{"matches"}else{"different-or-absent"}}),
            ))
        }
        "VersionBelow" => {
            let args = args.ok_or_else(|| "hotfix-version-below-args-missing".to_string())?;
            let path =
                required_string(args, "version_path", "hotfix-version-below-witness-missing")?;
            let minimum = required_string(args, "minimum", "hotfix-version-below-minimum-missing")?;
            let observed = crate::atoms::ask::file_if_present(Path::new(path))?
                .map(|o| String::from_utf8_lossy(&o.bytes).trim().to_string())
                .unwrap_or_default();
            let below = version_below(&observed, minimum);
            Ok((
                below,
                json!({"family":family,"version_path":path,"observed_version":observed,"minimum":minimum,"condition":if below{"below"}else{"current-or-newer"}}),
            ))
        }
        other => Err(format!("hotfix-predicate-unsupported {other}")),
    }
}
fn version_below(observed: &str, minimum: &str) -> bool {
    let parse = |v: &str| {
        v.split('.')
            .map(|p| p.parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()
    };
    match (parse(observed), parse(minimum)) {
        (Some(a), Some(b)) => {
            let n = a.len().max(b.len());
            (0..n)
                .find_map(|i| {
                    let x = *a.get(i).unwrap_or(&0);
                    let y = *b.get(i).unwrap_or(&0);
                    (x != y).then_some(x < y)
                })
                .unwrap_or(false)
        }
        _ => observed < minimum,
    }
}
fn required_string<'a>(o: &'a Map<String, Value>, n: &str, e: &str) -> Result<&'a str, String> {
    o.get(n)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| e.to_string())
}
