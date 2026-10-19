//! Every example configuration loads with this version of opv, so a copied example never
//! starts with a configuration error. An example keeps its IDs in `secrets.bindings.toml`
//! beside it (D-G) and may leave the boundary IDs and each target's `state_vault_id` to `opv
//! bootstrap`; it is checked with placeholder IDs for those.

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
/// `vault_id`/`item_id` and a target's `state_vault_id`, not yet recorded. Each
/// placeholder is distinct, as bootstrap's real IDs are, so two vaults never look shared.
fn with_ids(text: &str) -> String {
    let mut next = 0;
    let mut id = |prefix: &str| {
        next += 1;
        format!("{prefix}example{next:016}")
    };
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
                if unrecorded(b.get("vault_id")) {
                    b.insert("vault_id", toml_edit::value(id("v")));
                }
                if unrecorded(b.get("item_id")) {
                    b.insert("item_id", toml_edit::value(id("i")));
                }
            }
        }
        if let Some(targets) = t.get_mut("targets").and_then(|x| x.as_table_like_mut()) {
            for (_, target) in targets.iter_mut() {
                let Some(t) = target.as_table_like_mut() else {
                    continue;
                };
                if unrecorded(t.get("state_vault_id")) {
                    t.insert("state_vault_id", toml_edit::value(id("vstate")));
                }
            }
        }
    }
    doc.to_string()
}

/// An id `opv bootstrap` has not recorded yet: absent, or empty.
fn unrecorded(id: Option<&toml_edit::Item>) -> bool {
    id.and_then(|v| v.as_str()).is_none_or(str::is_empty)
}

/// The example at `path` as opv reads it: the contract with its bindings filled in.
fn read(path: &Path) -> String {
    opv::config::read_merged(path).expect("the example reads")
}

#[test]
fn there_is_at_least_one_example_configuration() {
    assert!(!example_configs().is_empty());
}

#[test]
fn the_overflow_example_places_p_on_two_targets() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/shared-overflow/secrets.toml");
    let text = read(&path);
    let fleet = opv::config::parse(&with_ids(&text)).expect("the overflow example loads");
    let placed = ["shared", "p-overflow"]
        .iter()
        .filter(|target| fleet.delivers("prod", target, "p"))
        .count();
    assert_eq!(placed, 2);
}

#[test]
fn every_example_configuration_loads() {
    let failures: Vec<String> = example_configs()
        .iter()
        .filter_map(|p| {
            opv::config::read_merged(p)
                .and_then(|text| opv::config::parse(&with_ids(&text)))
                .err()
                .map(|e| format!("{}: {e}", p.display()))
        })
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}
