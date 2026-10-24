//! `opv target op` on the test app's Fly target (#234), reached through the real `opv`
//! binary against `opv-sim flyctl` on the application in `tests/e2e/app`:
//!
//! 1. `opv target op prod --target fly machines` lists the world's Machines: exit 0 and one
//!    line per Machine, id first. The world's `config.env` holds a `test-marker-e2e-` value;
//!    opv projects only id, name, state, region and image (O5), so it reaches neither opv's
//!    stdout nor its stderr (T5).
//! 2. `machine-update --machine <listed id> --image registry.fly.io/e2e-app-prod:v2` lists
//!    the app, then moves that Machine (O4). The world's Machine image changes and the run
//!    exits 0. `prod` sets `confirm_env`, so the write needs `--confirm prod`.
//! 3. An id the world does not list is `policy_refused` (exit 6) after the listing, and the
//!    log holds the listing but no `machine update` (O4, T4).
//! 4. An image of another app is refused in admission, before any `flyctl` call (P6).
//! 5. A CI job's `GITHUB_TOKEN` is in opv's own environment but not in the `flyctl` child's:
//!    a wrapper in front of the simulator records the *names* of the variables it receives
//!    (never a value) and the token name is absent (§5.5).
//!
//! **The flyctl replies.** `opv-sim flyctl` has no recorded `machine list`/`machine update`
//! reply (the owner skipped spikes S2/S3, design §8.1), so the simulator builds both from
//! flyctl's documented JSON. That is why this module asserts on behaviour and writes no
//! snapshot (`SNAPSHOTS` is empty): there is no recorded text to pin.
//!
//! Every world value carries `test-marker-e2e-`; the deploy token is shaped like a Fly token
//! and the world's `fly.tokens` accepts it, so the simulator's token check passes. Nothing
//! here reads `/proc` or needs a Linux-only tool.

use serde_json::{Value, json};

use crate::coverage::{DEV_ACCOUNT, Scenario};

/// The scenario snapshots this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &[];

const SIM: &str = env!("CARGO_BIN_EXE_opv-sim");

/// The Fly target's name and app (`tests/e2e/app/secrets.toml`).
const TARGET: &str = "fly";
const APP: &str = "e2e-app-prod";
/// The deploy credentials item and the token it holds; `world.json`'s `fly.tokens` must
/// accept the token, so the simulator's own check passes.
const CRED_VAULT: &str = "vE2EFLYOPCRED0000000000001";
const CRED_ITEM: &str = "iE2EFLYOPCRED0000000000001";
const DEPLOY_TOKEN: &str = "FlyV1 fm2_test-marker-e2e-fly-op-deploy";
/// Two Machine ids of the documented shape (`^[0-9a-f]{14}$`, P6).
const MACHINE_A: &str = "8edd22dc379d68";
const MACHINE_B: &str = "8edd22dc379d69";
/// The canary inside Machine A's `config.env`; opv must never print it.
const ENV_CANARY: &str = "test-marker-e2e-machine-config-env";
/// The image the update moves to, and an image of another app (`P6`).
const NEW_IMAGE: &str = "registry.fly.io/e2e-app-prod:v2";
const OTHER_IMAGE: &str = "registry.fly.io/other-app:v2";
/// A CI job's token, in opv's own environment only.
const CI_TOKEN: &str = "test-marker-e2e-ci-token";

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// `opv target op prod --target fly machines`.
fn machines() -> Vec<String> {
    args(&["target", "op", "prod", "--target", TARGET, "machines"])
}

/// `opv target op prod --target fly machine-update --machine <id> --image <image>
/// --confirm prod` (`prod` sets `confirm_env`).
fn machine_update(machine: &str, image: &str) -> Vec<String> {
    args(&[
        "target",
        "op",
        "prod",
        "--target",
        TARGET,
        "machine-update",
        "--machine",
        machine,
        "--image",
        image,
        "--confirm",
        "prod",
    ])
}

/// The e2e app with the Fly target's deploy credentials and two Machines in the world.
fn fly_ops() -> Scenario {
    Scenario::new()
        .config(|text| {
            text.replace(
                "[environments.prod.targets.fly]\n",
                &format!(
                    "[environments.prod.targets.fly]\n\
                     deploy_credentials = \"op://{CRED_VAULT}/{CRED_ITEM}\"\n"
                ),
            )
        })
        .world(|w| {
            w["fly"]["tokens"]
                .as_array_mut()
                .expect("tokens")
                .push(json!(DEPLOY_TOKEN));
            w["op"]["vaults"]
                .as_array_mut()
                .expect("vaults")
                .push(json!({
                    "id": CRED_VAULT,
                    "name": "e2e-app · fly · credentials",
                    "account": DEV_ACCOUNT,
                }));
            w["op"]["items"].as_array_mut().expect("items").push(json!({
                "id": CRED_ITEM,
                "title": "e2e-app · fly · deploy",
                "version": 1,
                "vault": {"id": CRED_VAULT, "name": "e2e-app · fly · credentials"},
                "category": "SECURE_NOTE",
                "fields": [
                    {"id": "notesPlain", "type": "STRING", "purpose": "NOTES",
                     "label": "notesPlain", "value": ""},
                    {"id": "FLY_API_TOKEN", "type": "CONCEALED",
                     "label": "FLY_API_TOKEN", "value": DEPLOY_TOKEN},
                ]
            }));
            w["fly"]["apps"][APP]["machines"] = json!([
                {"id": MACHINE_A, "name": "web-a", "state": "started", "region": "iad",
                 "config": {"image": "registry.fly.io/e2e-app-prod:v1",
                            "env": {"CANARY": ENV_CANARY}}},
                {"id": MACHINE_B, "name": "web-b", "state": "stopped", "region": "lhr",
                 "config": {"image": "registry.fly.io/e2e-app-prod:v1", "env": {}}},
            ]);
        })
}

/// The scenario's `calls.log` (argv only).
fn calls(s: &Scenario) -> String {
    std::fs::read_to_string(s.path("world/calls.log")).unwrap_or_default()
}

/// The scenario's world as the simulator left it.
fn world(s: &Scenario) -> Value {
    serde_json::from_str(&std::fs::read_to_string(s.path("world/world.json")).expect("world"))
        .expect("world")
}

/// The image the world holds for Machine `id`.
fn machine_image(s: &Scenario, id: &str) -> String {
    world(s)["fly"]["apps"][APP]["machines"]
        .as_array()
        .expect("machines")
        .iter()
        .find(|m| m["id"] == id)
        .and_then(|m| m["config"]["image"].as_str())
        .unwrap_or_default()
        .to_string()
}

/// `flyctl` in front of the simulator. The operation's child runs under `isolated_env`
/// (§5.5), which drops the harness's `OPV_SIM_WORLD`; the wrapper — the direct child —
/// records the *names* of the environment variables it received (never a value), restores
/// the world, then hands the call to the simulator (linked under its own name so `argv[0]`
/// still says `flyctl`).
fn flyctl_in_world(s: &Scenario) {
    s.install();
    let sim = s.path("sim");
    std::fs::create_dir_all(&sim).expect("sim dir");
    std::os::unix::fs::symlink(SIM, sim.join("flyctl")).expect("sim flyctl");
    let wrapper = s.path("bin/flyctl");
    std::fs::remove_file(&wrapper).expect("simulated flyctl");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nenv | sed 's/=.*//' > '{names}'\n\
             export OPV_SIM_WORLD='{world}'\nexec '{sim}' \"$@\"\n",
            names = s.path("flyctl-env-names.txt").display(),
            world = s.path("world").display(),
            sim = sim.join("flyctl").display(),
        ),
    )
    .expect("fake flyctl");
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// [`fly_ops`] with the world-reconnecting `flyctl` wrapper installed.
fn fly_ops_in_world() -> Scenario {
    let s = fly_ops();
    flyctl_in_world(&s);
    s
}

// --- machines --------------------------------------------------------------------------------

#[test]
fn machines_exits_zero() {
    let run = fly_ops_in_world().opv(&machines());
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
}

#[test]
fn machines_prints_each_world_machine_id() {
    let run = fly_ops_in_world().opv(&machines());
    assert!(
        run.stdout.contains(MACHINE_A) && run.stdout.contains(MACHINE_B),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

#[test]
fn machines_never_prints_a_machine_config_env_value() {
    let run = fly_ops_in_world().opv(&machines());
    assert!(
        !run.stdout.contains(ENV_CANARY) && !run.stderr.contains(ENV_CANARY),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

// --- machine-update --------------------------------------------------------------------------

#[test]
fn machine_update_exits_zero() {
    let run = fly_ops_in_world().opv(&machine_update(MACHINE_A, NEW_IMAGE));
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
}

#[test]
fn machine_update_changes_the_listed_machines_image() {
    let s = fly_ops_in_world();
    let _ = s.opv(&machine_update(MACHINE_A, NEW_IMAGE));
    assert_eq!(machine_image(&s, MACHINE_A), NEW_IMAGE);
}

#[test]
fn machine_update_of_an_unlisted_machine_exits_six() {
    let run = fly_ops_in_world().opv(&machine_update("ffffffffffffff", NEW_IMAGE));
    assert_eq!(run.code, Some(6), "{}{}", run.stdout, run.stderr);
}

#[test]
fn machine_update_of_an_unlisted_machine_makes_no_update_call() {
    let s = fly_ops_in_world();
    let _ = s.opv(&machine_update("ffffffffffffff", NEW_IMAGE));
    assert!(
        !calls(&s).contains("flyctl machine update"),
        "{}",
        calls(&s)
    );
}

#[test]
fn machine_update_with_another_apps_image_exits_six() {
    let run = fly_ops_in_world().opv(&machine_update(MACHINE_A, OTHER_IMAGE));
    assert_eq!(run.code, Some(6), "{}{}", run.stdout, run.stderr);
}

#[test]
fn machine_update_with_another_apps_image_makes_no_flyctl_call() {
    let s = fly_ops_in_world();
    let _ = s.opv(&machine_update(MACHINE_A, OTHER_IMAGE));
    assert!(!calls(&s).contains("flyctl machine"), "{}", calls(&s));
}

// --- child environment -----------------------------------------------------------------------

#[test]
fn a_ci_token_never_reaches_the_flyctl_child() {
    let s = fly_ops_in_world().var("GITHUB_TOKEN", CI_TOKEN);
    let _ = s.opv(&machines());
    let seen = std::fs::read_to_string(s.path("flyctl-env-names.txt")).expect("env names");
    assert!(!seen.lines().any(|n| n == "GITHUB_TOKEN"), "{seen}");
}
