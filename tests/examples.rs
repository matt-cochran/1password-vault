//! Every example configuration loads with this version of opv, so a copied example never
//! starts with a configuration error. An example may leave the boundary IDs and each
//! target's `state_vault_id` to `opv bootstrap`; it is checked with placeholder IDs.

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

/// The example with placeholder IDs wherever `opv bootstrap` records them: a boundary's
/// `vault_id`/`item_id` and a target's `state_vault_id`, left empty in the file.
fn with_ids(text: &str) -> String {
    let mut doc: toml_edit::DocumentMut = text.parse().expect("example parses as TOML");
    let Some(envs) = doc
        .get_mut("environments")
        .and_then(|e| e.as_table_like_mut())
    else {
        return doc.to_string();
    };
    for (_, env) in envs.iter_mut() {
        let Some(t) = env.as_table_like_mut() else {
            continue;
        };
        if let Some(boundaries) = t.get_mut("boundaries").and_then(|b| b.as_table_like_mut()) {
            for (_, boundary) in boundaries.iter_mut() {
                let Some(b) = boundary.as_table_like_mut() else {
                    continue;
                };
                if b.get("vault_id").and_then(|v| v.as_str()) == Some("") {
                    b.insert("vault_id", toml_edit::value("vexample00000000000000001"));
                }
                if b.get("item_id").and_then(|v| v.as_str()) == Some("") {
                    b.insert("item_id", toml_edit::value("iexample00000000000000001"));
                }
            }
        }
        if let Some(targets) = t.get_mut("targets").and_then(|x| x.as_table_like_mut()) {
            for (_, target) in targets.iter_mut() {
                let Some(t) = target.as_table_like_mut() else {
                    continue;
                };
                if t.get("state_vault_id").and_then(|v| v.as_str()) == Some("") {
                    t.insert(
                        "state_vault_id",
                        toml_edit::value("vstateexample00000000000001"),
                    );
                }
            }
        }
    }
    doc.to_string()
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
            let text = std::fs::read_to_string(p).unwrap();
            opv::config::parse(&with_ids(&text))
                .err()
                .map(|e| format!("{}: {e}", p.display()))
        })
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}
