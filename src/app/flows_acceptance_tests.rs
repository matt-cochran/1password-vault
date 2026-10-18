//! Acceptance walkthrough for milestone `flows-accepted` (0.12.0): one in-process sim run
//! from no configuration to a set `local` tier, through the new library entry points, with
//! every `op` reply coming from the shared fake (`FakeOp`). One behavioural assertion per
//! test; the walkthrough itself is shared through [`walkthrough`].
//!
//! The run: a temp checkout holding only a `.env` of names and test values, then
//! (1) `propose setup` from the names, written as `secrets.toml` with `tier = "local"`,
//! (2) `apply` in a person's terminal, (3) the assistant's `import_local` of the `.env`,
//! (4) each declared key's value state from what the fake now holds.

use std::path::{Path, PathBuf};

use crate::adapters::fake_op::FakeOp;
use crate::app::apply::{self, Applied, ApplyOpts};
use crate::app::import_local::import_local;
use crate::app::propose::setup::{self, NAMES_PRODUCT};
use crate::domain::presence::present_in;
use crate::domain::value_state::{ValueState, classify};
use crate::domain::{Fleet, SecretValue};
use crate::error::Error;
use crate::host::FakeEnv;

const ACCOUNT: &str = "ACCOUNTAAA000000000000AAAA";
const PROJECT: &str = "myapp";
const ENV: &str = "local";
/// The marker every test value carries; no rendered output may hold it.
const MARKER: &str = "S7MARKER";

/// The `.env` the walkthrough starts from: names and placeholder-free test values.
fn dotenv() -> String {
    ["DATABASE_URL", "STRIPE_SECRET_KEY", "LOG_LEVEL"]
        .iter()
        .enumerate()
        .map(|(n, name)| format!("{name}=S7MARKER-flows-{}\n", n + 1))
        .collect()
}

/// A checkout after step 1: the `.env` and the proposed `secrets.toml`, nothing applied.
struct Proposed {
    dir: tempfile::TempDir,
    contract: PathBuf,
    dotenv: PathBuf,
    op: FakeOp,
}

/// Everything the full walkthrough produced.
struct Walked {
    world: Proposed,
    applied: Applied,
    /// Every byte the walkthrough rendered to an `out` buffer, in order.
    out: Vec<u8>,
}

/// A fresh temp checkout holding only a private `.env` (no `secrets.toml`).
fn empty_checkout() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".env");
    std::fs::write(&path, dotenv()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (dir, path)
}

/// The proposal's contract text: a first setup's diff is every line added.
fn proposed_text(diff: &str) -> String {
    diff.lines()
        .map(|l| l.strip_prefix('+').unwrap_or(l))
        .map(|l| format!("{l}\n"))
        .collect()
}

/// Step 1: propose the contract from the `.env`'s names and write it as `secrets.toml`, the
/// way `opv propose setup --write` writes a new file, with the environment set to `local`.
fn proposed() -> Proposed {
    let (dir, dotenv) = empty_checkout();
    let p = setup::from_names(&dotenv, ENV, &[], &[]).unwrap();
    let mut text = proposed_text(&p.proposal.diff);
    let header = format!("[environments.{ENV}]\n");
    if !text.contains("tier = ") {
        text = text.replacen(&header, &format!("{header}tier = \"local\"\n"), 1);
    }
    let contract = dir.path().join("secrets.toml");
    crate::app::init::write_config(&contract, &text, false).unwrap();
    Proposed {
        dir,
        contract,
        dotenv,
        op: FakeOp::default(),
    }
}

/// A person at a terminal: not an assistant, stdin and stdout are a TTY.
fn tty() -> FakeEnv {
    FakeEnv::new("linux").tty()
}

/// Step 2 on `w`, in host `env`, accepting the plan.
fn run_apply(
    w: &Proposed,
    env: &dyn crate::host::HostEnv,
    out: &mut Vec<u8>,
) -> Result<Applied, Error> {
    apply::apply(
        &w.op,
        env,
        &w.contract,
        PROJECT,
        ACCOUNT,
        None,
        ApplyOpts::default(),
        &mut |_| true,
        out,
    )
}

/// Steps 1 to 3: propose and write, apply in a person's terminal, then the assistant's
/// local import of the `.env`.
fn walkthrough() -> Walked {
    let world = proposed();
    let mut out = Vec::new();
    let applied = run_apply(&world, &tty(), &mut out).unwrap();
    let fleet = crate::config::load(&world.contract).unwrap();
    import_local(&fleet, ENV, &world.dotenv, &world.op, &mut out).unwrap();
    Walked {
        world,
        applied,
        out,
    }
}

/// The value FakeOp holds for `product/key` in the environment's boundary item, if any.
fn held(op: &FakeOp, fleet: &Fleet, product: &str, key: &str) -> Option<SecretValue> {
    let item_id = &fleet.boundary(ENV, product).ok()?.item_id;
    let item = op.item(item_id);
    item["fields"].as_array()?.iter().find_map(|f| {
        (f["label"] == key && f["section"]["label"] == product)
            .then(|| SecretValue::new(f["value"].as_str().unwrap_or_default().to_string()))
    })
}

/// Step 4: every declared key's value state in the environment, from what FakeOp holds.
fn value_states(w: &Walked) -> Vec<(String, ValueState)> {
    let fleet = crate::config::load(&w.world.contract).unwrap();
    let mut states = Vec::new();
    for (product, spec) in &fleet.products {
        for (key, k) in &spec.keys {
            let value = held(&w.world.op, &fleet, product, key);
            let state = classify(Ok(value.as_ref()), present_in(k, ENV), false, |_| Ok(()));
            states.push((format!("{product}/{key}"), state));
        }
    }
    states
}

fn exists(dir: &Path, name: &str) -> bool {
    dir.join(name).is_file()
}

// The walkthrough ---------------------------------------------------------------------------

#[test]
fn the_proposal_starts_from_a_checkout_with_no_contract() {
    let (dir, _) = empty_checkout();
    assert!(!exists(dir.path(), "secrets.toml"));
}

#[test]
fn the_proposed_contract_loads_before_the_first_apply() {
    let w = proposed();
    assert!(crate::config::load(&w.contract).is_ok());
}

#[test]
fn before_the_first_apply_the_proposed_boundary_is_unbound() {
    let w = proposed();
    let fleet = crate::config::load(&w.contract).unwrap();
    assert_eq!(
        fleet.boundary(ENV, NAMES_PRODUCT).unwrap_err().code_str(),
        "boundary_missing"
    );
}

#[test]
fn the_proposed_contract_declares_every_dotenv_name() {
    let w = proposed();
    // Before an apply the boundary is declared and unbound: the contract loads as it is.
    let fleet = crate::config::load(&w.contract).unwrap();
    let keys: Vec<String> = fleet.products[NAMES_PRODUCT].keys.keys().cloned().collect();
    assert_eq!(keys, ["DATABASE_URL", "LOG_LEVEL", "STRIPE_SECRET_KEY"]);
}

#[test]
fn apply_creates_the_boundary_item() {
    let w = walkthrough();
    assert_eq!(
        w.applied
            .created
            .iter()
            .filter(|c| c.kind == "boundary")
            .count(),
        1
    );
}

#[test]
fn apply_writes_the_bindings_file() {
    let w = walkthrough();
    assert!(exists(w.world.dir.path(), crate::config::bindings::FILE));
}

#[test]
fn apply_writes_the_apply_record() {
    let w = walkthrough();
    let record = crate::config::bindings::read_record(
        &w.world.dir.path().join(crate::config::bindings::APPLIED),
    )
    .unwrap();
    assert!(record.is_some());
}

#[test]
fn import_local_tags_the_item_assistant_imported() {
    let w = walkthrough();
    let fleet = crate::config::load(&w.world.contract).unwrap();
    let item_id = &fleet.environments[ENV].boundaries[NAMES_PRODUCT]
        .as_ref()
        .unwrap()
        .item_id;
    let tagged = w.world.op.item(item_id)["tags"]
        .as_array()
        .is_some_and(|t| {
            t.iter()
                .any(|v| v.as_str() == Some(crate::app::import_local::ASSISTANT_IMPORTED))
        });
    assert!(tagged);
}

#[test]
fn every_declared_key_is_set_after_the_walkthrough() {
    let w = walkthrough();
    let every_key_set: Vec<(String, ValueState)> =
        ["app/DATABASE_URL", "app/LOG_LEVEL", "app/STRIPE_SECRET_KEY"]
            .iter()
            .map(|k| (k.to_string(), ValueState::Set))
            .collect();
    assert_eq!(value_states(&w), every_key_set);
}

// Refusal, value boundary and config check --------------------------------------------------

#[test]
fn an_agent_mode_apply_records_no_op_call() {
    let w = proposed();
    let _ = run_apply(
        &w,
        &FakeEnv::new("linux").var("CLAUDECODE"),
        &mut Vec::new(),
    );
    assert!(w.op.calls.borrow().is_empty());
}

#[test]
fn an_agent_mode_apply_is_refused_person_only() {
    let w = proposed();
    let e = run_apply(
        &w,
        &FakeEnv::new("linux").var("CLAUDECODE"),
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "person_only");
}

#[test]
fn the_walkthrough_output_never_holds_a_value() {
    let w = walkthrough();
    assert!(!String::from_utf8_lossy(&w.out).contains(MARKER));
}

#[test]
fn config_check_passes_right_after_apply() {
    let world = proposed();
    run_apply(&world, &tty(), &mut Vec::new()).unwrap();
    let found = crate::config_store::Found::File {
        store: crate::config_store::FileStore {
            path: world.contract.clone(),
        },
        given: None,
    };
    let res = crate::app::config_cmd::check(&found, &world.contract, &world.op, &mut Vec::new());
    assert!(res.is_ok(), "{res:?}");
}
