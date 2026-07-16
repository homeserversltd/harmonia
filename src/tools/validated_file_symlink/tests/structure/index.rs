//! Architecture regression tests for the recursive transaction band.

use std::fs;
use std::path::{Path, PathBuf};

fn line_count(path: &Path) -> usize {
    fs::read_to_string(path).unwrap().lines().count()
}

fn assert_band(path: &Path) {
    assert!(
        path.join("index.rs").is_file(),
        "missing index.rs: {}",
        path.display()
    );
    assert!(
        path.join("index.json").is_file(),
        "missing index.json: {}",
        path.display()
    );
    assert!(
        path.join("README.md").is_file(),
        "missing README.md: {}",
        path.display()
    );
    let declaration: serde_json::Value =
        serde_json::from_slice(&fs::read(path.join("index.json")).unwrap()).unwrap();
    let children = declaration["children"]
        .as_array()
        .unwrap_or_else(|| panic!("children array missing: {}", path.display()));
    let declared: Vec<String> = children
        .iter()
        .map(|child| child.as_str().expect("child must be a string").to_owned())
        .collect();
    let spine = fs::read_to_string(path.join("index.rs")).unwrap();
    let wired: Vec<String> = spine
        .lines()
        .filter(|line| line.contains("include!(") || line.contains("#[path = "))
        .filter_map(|line| {
            let (_, quoted) = line.split_once('"')?;
            let (marker, _) = quoted.split_once('"')?;
            marker
                .contains('/')
                .then(|| marker.strip_suffix("/index.rs"))
                .flatten()
                .map(str::to_owned)
        })
        .collect();
    assert_eq!(
        wired,
        declared,
        "child spine order drift: {}",
        path.display()
    );
    let actual: Vec<String> = fs::read_dir(path)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().unwrap().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        actual.len(),
        declared.len(),
        "sidecar drift: {}",
        path.display()
    );
    for child in declared {
        assert!(
            actual.iter().any(|actual| actual == &child),
            "undeclared child: {child}"
        );
        assert_band(&path.join(child));
    }
}

fn all_rust(path: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).unwrap().filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            all_rust(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn recursive_band_sidecars_and_line_ceilings_hold() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tools/validated_file_symlink");
    assert_band(&root);
    let hoist = root.with_extension("rs");
    assert!(hoist.is_file());
    assert!(
        line_count(&hoist) <= 150,
        "thin hoist grew: {}",
        hoist.display()
    );
    let mut rust = Vec::new();
    all_rust(&root, &mut rust);
    for source in rust {
        assert!(
            line_count(&source) <= 500,
            "band source grew: {}",
            source.display()
        );
    }
    assert!(
        !root.join("state.json").exists(),
        "transaction band must not own runtime state"
    );
}
