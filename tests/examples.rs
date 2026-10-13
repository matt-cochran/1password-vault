//! Every example configuration loads with this version of opv, so a copied example never
//! starts with a configuration error.

use std::path::{Path, PathBuf};

fn example_configs() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let mut found: Vec<PathBuf> = std::fs::read_dir(&root)
        .expect("examples dir")
        .map(|e| e.expect("entry").path().join("secrets.toml"))
        .filter(|p| p.exists())
        .collect();
    found.sort();
    found
}

#[test]
fn there_is_at_least_one_example_configuration() {
    assert!(!example_configs().is_empty());
}

#[test]
fn every_example_configuration_loads() {
    let failures: Vec<String> = example_configs()
        .iter()
        .filter_map(|p| {
            opv::config::load(p)
                .err()
                .map(|e| format!("{}: {e}", p.display()))
        })
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}
