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

/// FR-4: `config describe` resolves every environment, product, key and boundary of the
/// project. It reads the configuration only, so no 1Password call is needed.
#[test]
fn config_describe_loads_the_e2e_app() {
    let out = Command::new(env!("CARGO_BIN_EXE_opv"))
        .arg("--config")
        .arg(Path::new(APP).join("secrets.toml"))
        .args(["config", "describe", "--json"])
        .output()
        .expect("run opv");
    assert!(
        out.status.success(),
        "opv config describe failed: {}",
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
