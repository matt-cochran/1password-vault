//! The end-to-end test application (design §13.2): `tests/e2e/app` is a full `opv` project
//! plus the `opv-sim` world that answers for it. These tests prove the fixture loads and
//! that the world parses and answers, so the end-to-end scenarios built on it can rely on
//! `secrets.toml` and `world.json` being sound. No real credential is involved: every value
//! in the world is a marker.
#![cfg(all(unix, feature = "fake"))]

use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Command;

/// The fixture directory, the project and the world in one.
const APP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e/app");

/// FR-4: `contract` resolves every environment, product and key of the project. It reads
/// the configuration only, so no 1Password call is needed.
#[test]
fn contract_loads_the_e2e_app() {
    let out = Command::new(env!("CARGO_BIN_EXE_opv"))
        .arg("--config")
        .arg(Path::new(APP).join("secrets.toml"))
        .args(["contract", "--json"])
        .output()
        .expect("run opv");
    assert!(
        out.status.success(),
        "opv contract failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The world is the simulator's whole state: if `op whoami` answers, `world.json` parsed
/// and the accounts in it are readable. The cheapest `op` call proves it.
#[test]
fn simulator_opens_the_e2e_app_world() {
    let out = Command::new(env!("CARGO_BIN_EXE_opv-sim"))
        .arg0("op")
        .arg("whoami")
        .env("OPV_SIM_WORLD", APP)
        .output()
        .expect("run opv-sim");
    assert!(
        out.status.success(),
        "op whoami against the world failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The committed manifest mirror (`manifest/opv-item.md`).
fn mirror() -> String {
    std::fs::read_to_string(Path::new(APP).join("manifest/opv-item.md")).expect("the mirror")
}

/// The mirror is the notes of the world's manifest item `opv · e2e-app`, byte for byte.
#[test]
fn the_manifest_mirror_is_the_world_items_notes() {
    let world: serde_json::Value = serde_json::from_slice(
        &std::fs::read(Path::new(APP).join("world.json")).expect("the world"),
    )
    .expect("world.json parses");
    let notes = world["op"]["items"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|i| i["title"] == "opv · e2e-app")
        .and_then(|i| i["fields"].as_array())
        .into_iter()
        .flatten()
        .find(|f| f["id"] == "notesPlain")
        .and_then(|f| f["value"].as_str())
        .map(str::to_string);
    assert_eq!(notes, Some(mirror()));
}

/// D-G: the mirror's contract block is `secrets.toml`, which holds no id.
#[test]
fn the_manifest_mirrors_contract_block_is_secrets_toml() {
    let contract = std::fs::read_to_string(Path::new(APP).join("secrets.toml")).unwrap();
    assert_eq!(
        opv::adapters::onepassword_manifest::config_text(&mirror()),
        contract
    );
}

/// D-G: the mirror's `opv-bindings` block is `secrets.bindings.toml`.
#[test]
fn the_manifest_mirrors_bindings_block_is_secrets_bindings_toml() {
    let ids = std::fs::read_to_string(Path::new(APP).join("secrets.bindings.toml")).unwrap();
    assert_eq!(
        opv::adapters::onepassword_manifest::bindings_text(&mirror()),
        Some(ids)
    );
}
