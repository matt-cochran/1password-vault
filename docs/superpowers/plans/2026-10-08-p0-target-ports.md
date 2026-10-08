# P0: Target Ports Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move Fly behind `SecretStore` and `Runtime` ports so `app/` and `domain/` stop naming Fly, add `opv plan` / `opv sync`, and change no Fly byte (issue #38).

**Architecture:** Characterization tests first record every `flyctl` argv, stdin byte and stdout line for each Fly scenario. Then the domain types are renamed target-neutral, the ports are added with exactly the operations the current engine uses (P1 adds `read`, `bindings`, `apply`, `check_access` and `await_healthy` when the first cloud consumes them), Fly implements both, and the use cases are rewired through a factory. The golden transcripts must stay identical through every task.

**Tech Stack:** Rust 2024, clap, serde_json, zeroize; tests use `runner::fake::FakeRunner` and `app::testutil`.

**Spec:** `docs/superpowers/specs/2026-10-08-multi-cloud-targets-design.md` (§3, §8, §9); `OVERVIEW.md` FR-12, FR-28, §8 items 27–28.

## Global Constraints

- Fly behaviour is byte-identical: same `flyctl` argv, same stdin, same stdout text, same exit categories (§8 item 27).
- No secret value in argv, env, logs, errors or `Debug` (SR-1, SR-3). Values travel on stdin only.
- Ports are synchronous and take `&dyn CommandRunner`, like the existing adapters (spec §3).
- A port method exists only when a use case calls it (YAGNI); the spec's full signatures are the destination, reached in P1.
- No parallel path: after Task 4, `src/app` and `src/domain` contain no `adapters::fly`, `FlySecret` or `fly_target` (except `app/init.rs`, which writes a Fly config by design and stays Fly-only until a later phase).
- `opv fly plan` / `opv fly sync` keep working and print exactly `opv: "fly plan" is deprecated; use "opv plan" (removed in the next minor release)` (or `sync`) on stderr.
- Tests: atomic scenarios, declarative names, exactly one behavioral assertion each.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test` pass after every task.
- Commits cite requirement IDs and end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. A `Staged`/`Partial` Fly status from an earlier run must still trigger a deploy after `status` becomes `pending: bool` (golden scenario `sync_pending_from_earlier_run`).
2. An environment with no target section must still fail with the exact current "has no fly section" message before any call (golden scenario `status_env_without_target`).
3. The simple profile (FR-20) must produce the same names and the same argv (golden scenario `simple_sync_deploy`).
4. `--json` documents must keep their field names (`fly_name` stays in JSON `schema_version` 1; renaming it is a breaking change deferred to P1's schema bump) (golden scenario `plan_json`).
5. A deprecated `fly` alias must exit with the same code as the new command, including findings (8) and refusal (6) (CLI test in Task 5).

---

### Task 1: Characterization golden tests for Fly (Junior)

**Files:**
- Create: `src/app/characterization_tests.rs`
- Create: `tests/fixtures/characterization/*.txt` (written by the test on first run with `UPDATE_GOLDEN=1`)
- Modify: `src/app/mod.rs` (add `#[cfg(test)] mod characterization_tests;` next to `mod simple_tests;`)
- Modify: `Cargo.toml` (`sha2` dev-dependency)

**Interfaces:**
- Consumes: `app::sync::{run, plan_with, SyncOpts}`, `app::status::run_with`, `app::testutil::*`, `runner::fake::FakeRunner`.
- Produces: `fn transcript(r: &FakeRunner, out: &[u8], res: &Result<(), Error>) -> String` and one golden file per scenario. Later tasks must leave every golden file unchanged.

Transcript format, one block per call then the output, so a diff shows exactly what moved:

```text
$ flyctl secrets import --app mcproductlabs-portfolio-production --stage
<stdin 87 bytes sha256=…>
--- stdout
staged: 1 changed, 0 unchanged
--- result
Ok(())
```

Stdin is recorded as its length and SHA-256 (not the text, so golden files hold no fixture values); `op` calls are recorded by argv only.

- [ ] **Step 1: Write the harness and the scenarios**

```rust
//! Characterization tests (P0, §8 item 27): every Fly scenario's flyctl argv, stdin
//! digest, stdout and result, compared with a golden file. `UPDATE_GOLDEN=1` rewrites them;
//! after Task 1 they must never change during P0.

use sha2::{Digest, Sha256};

use super::sync::{self, SyncOpts};
use super::testutil::*;
use crate::error::Error;
use crate::runner::fake::FakeRunner;

fn transcript(r: &FakeRunner, out: &[u8], res: &Result<(), Error>) -> String {
    let mut s = String::new();
    for c in r.calls.borrow().iter() {
        s.push_str(&format!("$ {} {}\n", c.program, c.args.join(" ")));
        if let Some(i) = &c.stdin {
            s.push_str(&format!("<stdin {} bytes sha256={:x}>\n", i.len(), Sha256::digest(i)));
        }
    }
    s.push_str("--- stdout\n");
    s.push_str(&text_of(out));
    s.push_str("--- result\n");
    s.push_str(&format!("{res:?}\n"));
    s
}

fn golden(name: &str, actual: &str) {
    let path = format!("tests/fixtures/characterization/{name}.txt");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all("tests/fixtures/characterization").unwrap();
        std::fs::write(&path, actual).unwrap();
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(expected, actual, "golden {path} differs");
}

#[test]
fn sync_new_secrets_without_deploy() {
    let r = FakeRunner::new([complete_item(), fly_empty(), ok(), fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")])]);
    let mut out = Vec::new();
    let res = sync::run(&fleet(), "prod", &r, &mut out, &SyncOpts::default());
    golden("sync_new_secrets_without_deploy", &transcript(&r, &out, &res));
}
```

Add one `#[test]` per scenario in the same shape (queue the responses each path needs; read `src/app/sync.rs` and the existing tests in it for the exact response order):

| Test / golden name | Command and flags | Fly state |
|---|---|---|
| `sync_new_secrets_without_deploy` | `sync::run` default | empty |
| `sync_unchanged_with_deploy` | `deploy: true` | both secrets present, same digest A and B |
| `sync_changed_with_deploy` | `deploy: true` | digest differs between A and B |
| `sync_pending_from_earlier_run` | `deploy: true` | unchanged digests, one name `Staged` (`fly_st`) |
| `sync_prune_with_deploy` | `deploy: true, prune: true` | an extra managed name not desired in prod |
| `sync_prune_without_flag` | default | same extra managed name |
| `sync_rotate_immutable` | `rotate: ["allumata/INTEGRATION_ENC_KEY"]` | ENC present |
| `sync_prune_immutable` | `prune: true, prune_immutable: [...]` | an immutable managed name not desired |
| `sync_refused_missing_key` | default, `item_without("allumata","OPENAI_API_KEY")` | empty |
| `plan_text` | `sync::plan_with(.., false)` | one present, one absent |
| `plan_json` | `sync::plan_with(.., true)` | one present, one absent |
| `status_clean` | `status::run_with` | complete |
| `status_env_without_target` | `status::run_with` on `dev` | (no call) |
| `simple_sync_deploy` | simple-profile fleet from `simple_tests.rs` fixtures, `deploy: true` | changed |

Add `sha2 = "0.10"` under `[dev-dependencies]` in `Cargo.toml` (it is not a dependency yet; `cargo deny check` must still pass).

- [ ] **Step 2: Generate the golden files**

Run: `UPDATE_GOLDEN=1 cargo test characterization -- --test-threads=1`
Expected: PASS; 14 files in `tests/fixtures/characterization/`.

- [ ] **Step 3: Verify they pin behaviour**

Run: `cargo test characterization` → PASS. Then grep the golden files for `FIXTUREVALUE` → no match (no values in fixtures).

- [ ] **Step 4: Commit**

```bash
git add src/app/characterization_tests.rs src/app/mod.rs tests/fixtures/characterization
git commit -m "test(p0): characterization golden transcripts for every Fly path (§8 27, #38)"
```

---

### Task 2: Target-neutral domain names (Junior)

**Files:**
- Modify: `src/domain/plan.rs`, `src/domain/model.rs`, `src/domain/mod.rs`, `src/config.rs`, `src/adapters/fly.rs`, every `src/app/*.rs` that uses the renamed items, `tests/*.rs` if they use them.

**Interfaces:**
- Produces (used by Tasks 3–4):

```rust
// domain/plan.rs — replaces FlySecret
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreEntry {
    pub name: String,
    /// The store's version of the value (Fly: its digest), when it reports one.
    pub version: Option<String>,
    /// A change written to the store but not yet live (Fly: status Staged or Partial).
    pub pending: bool,
}

// domain/model.rs
pub enum Target { Fly(FlyTarget) }
impl Environment {
    pub fn target(&self) -> Option<&Target>;               // replaces direct `.fly` reads
    pub fn target_name(&self, product: &str, key: &str) -> Option<String>; // was fly_name
}
impl Fleet {
    pub fn target(&self, env: &str) -> Result<(&Environment, &Target), Error>; // was fly_target; same error text
    pub fn target_name(&self, env: &str, product: &str, key: &str) -> String;   // was fly_name
    pub fn try_target_name(&self, env: &str, product: &str, key: &str) -> Result<String, Error>;
}
impl Target { pub fn label(&self) -> &'static str; } // "Fly"
```

- Renames: `FlySecret` → `StoreEntry` (`digest` → `version`; `status: Option<String>` → `pending: bool`, computed in `adapters::fly::list` as `matches!(status, Some("Staged" | "Partial"))`); `fly_name` → `target_name`; `fly_target` → `target`; `unmanaged_on_fly` → `unmanaged_on_target`. `Environment.fly` stays as the parsed field (config shape unchanged) but `app/` reads it only through `target()`.
- The JSON field `fly_name` and every printed string stay exactly as they are (Review Focus 4).

- [ ] **Step 1:** Apply the renames above with the compiler as the guide (`cargo build` until clean).
- [ ] **Step 2:** In `src/app/sync.rs`, replace the `Staged`/`Partial` status filter with `.filter(|s| s.pending)`.
- [ ] **Step 3:** Run `cargo test` → PASS, including all 14 characterization goldens unchanged (`git status tests/fixtures/characterization` clean).
- [ ] **Step 4:** Run `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` → clean.
- [ ] **Step 5: Commit** `refactor(p0): target-neutral domain names; Fly status becomes pending (FR-12, #38)`

---

### Task 3: Ports and the Fly adapter (manager)

**Files:**
- Create: `src/ports.rs`
- Modify: `src/lib.rs` (add `pub mod ports;`), `src/adapters/fly.rs`, `src/adapters/mod.rs`
- Test: in `src/adapters/fly.rs` tests module

**Interfaces:**
- Produces:

```rust
// src/ports.rs
//! Target ports (FR-12, FR-28). Core logic reaches a target only through these.
//! P0 carries the operations the current engine uses; P1 adds read, bindings, apply,
//! check_access and await_healthy (spec §3).

use crate::domain::{SecretValue, StoreEntry};
use crate::error::Error;

pub trait SecretStore {
    /// Display name in output ("Fly").
    fn label(&self) -> &'static str;
    /// Every entry: name, version, pending. Never values.
    fn list(&self) -> Result<Vec<StoreEntry>, Error>;
    /// The first rule this store would refuse for (name, value), with its fixed reason.
    fn refusal(&self, name: &str, value: &SecretValue) -> Option<(&'static str, &'static str)>;
    /// Refuses the whole batch before any write (names the key and rule, never the value).
    fn validate(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error>;
    /// Writes the batch as pending (values on stdin). One call for Fly.
    fn write(&self, batch: &[(String, &SecretValue)]) -> Result<(), Error>;
    /// Removes names as pending.
    fn remove(&self, names: &[String]) -> Result<(), Error>;
}

pub trait Runtime {
    /// Makes pending store changes live.
    fn deploy(&self) -> Result<(), Error>;
}
```

```rust
// src/adapters/mod.rs
pub fn open<'a>(target: &'a Target, r: &'a dyn CommandRunner)
    -> (Box<dyn SecretStore + 'a>, Box<dyn Runtime + 'a>);
// src/adapters/fly.rs
pub struct Fly<'a> { pub runner: &'a dyn CommandRunner, pub app: &'a str }
impl SecretStore for Fly<'_> { /* list → list(), refusal → entry_refusal_reason, validate → validate_import, write → stage, remove → unset_staged */ }
impl Runtime for Fly<'_> { /* deploy → deploy() */ }
```

- [ ] **Step 1: Write the failing test** in `adapters/fly.rs` tests:

```rust
#[test]
fn fly_store_write_is_one_staged_import() {
    let r = FakeRunner::new([Output::success(Vec::new())]);
    let v = SecretValue::from("sk-proj-FIXTUREVALUE".to_string());
    Fly { runner: &r, app: "app" }.write(&[("A".into(), &v)]).unwrap();
    assert_eq!(argvs(&r), ["flyctl secrets import --app app --stage"]);
}
```

(Use the module's existing helpers for `argvs`/`SecretValue` construction if they differ.)

- [ ] **Step 2:** Run `cargo test fly_store_write_is_one_staged_import` → FAIL (no `Fly`).
- [ ] **Step 3:** Add `src/ports.rs`, the `Fly` struct with both impls delegating to the existing free functions, and `adapters::open` (`match target { Target::Fly(t) => { let f = Fly { runner: r, app: &t.app }; (Box::new(f), Box::new(Fly { runner: r, app: &t.app })) } }`).
- [ ] **Step 4:** `cargo test` → PASS; goldens unchanged.
- [ ] **Step 5: Commit** `feat(p0): SecretStore and Runtime ports; Fly implements both (FR-12, FR-28, #38)`

---

### Task 4: Use cases through the ports (manager)

**Files:**
- Modify: `src/app/mod.rs` (`read_and_plan`), `src/app/sync.rs`, `src/app/status.rs`, `src/app/explain.rs`, `src/app/doctor.rs`, `src/adapters/fly.rs`, `src/adapters/mod.rs`

**Interfaces:**
- Consumes: Task 2 names, Task 3 ports and `adapters::open`.
- Produces:
  - `read_and_plan(fleet, env_name, r, store: Option<&dyn SecretStore>, rotate, prune_immutable) -> Result<(SyncPlan, Vec<StoreEntry>), Error>`; `target_check` is `&|n, v| store.refusal(n, v)`.
  - `sync::run` / `sync::plan_with` / `status::run_with` open the target with `adapters::open` and use only the ports.
  - `adapters::doctor_checks(kind: &Target, r, host) -> Vec<(&'static str, Result<Check, Error>)>` moves the flyctl version and auth checks (and their texts) out of `doctor.rs` into `adapters/fly.rs`; `doctor.rs` keeps the "skip" lines and calls it.
  - `explain` prints `{label lower} name:` from `Target::label` — `fly name:` for Fly, unchanged.

- [ ] **Step 1: Write the failing guard test** in `src/app/mod.rs` tests:

```rust
#[test]
fn app_and_domain_name_no_fly_adapter() {
    let mut hits = Vec::new();
    for dir in ["src/app", "src/domain"] {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.ends_with("init.rs") || p.ends_with("characterization_tests.rs") { continue; }
            let s = std::fs::read_to_string(&p).unwrap();
            if s.contains("adapters::fly") || s.contains("fly::") { hits.push(p); }
        }
    }
    assert!(hits.is_empty(), "Fly named in core: {hits:?}");
}
```

- [ ] **Step 2:** `cargo test app_and_domain_name_no_fly_adapter` → FAIL listing `mod.rs`, `sync.rs`, `doctor.rs`.
- [ ] **Step 3:** Rewire `read_and_plan`, `sync::run` (`store.list()` for A and B, `store.validate`, `store.write`, `store.remove`, `runtime.deploy`), `plan_with`, `status::run_with`, `explain` and `doctor` as specified. Keep every output string literally identical.
- [ ] **Step 4:** `cargo test` → PASS: guard test green and all 14 goldens unchanged (`git status tests/fixtures/characterization` clean).
- [ ] **Step 5:** clippy and fmt clean.
- [ ] **Step 6: Commit** `refactor(p0): use cases reach Fly only through the ports (FR-12, §8 27, #38)`

---

### Task 5: `opv plan` / `opv sync` and deprecated `fly` aliases (Junior)

**Files:**
- Modify: `src/main.rs`, `tests/cli.rs`, `README.md`, `CLAUDE.md`, `OVERVIEW.md` (§5 already lists the commands; no change unless wording is wrong)

**Interfaces:**
- Consumes: `app::sync::{run, plan_with, SyncOpts}` unchanged.
- Produces: top-level `Cmd::Plan { env, json }` and `Cmd::Sync { env, deploy, prune, rotate, prune_immutable }` with the same help text as `FlyCmd` today (target-neutral wording: "the environment's target" instead of "Fly app"); `Cmd::Fly(FlyCmd)` stays, marked `hide = true` in help, and its arms print the deprecation line then call the same functions.

- [ ] **Step 1: Write failing CLI tests** in `tests/cli.rs`, following the file's existing helpers (one assertion each):
  - `plan_is_a_top_level_command` — `opv plan --help` exits 0.
  - `fly_plan_prints_deprecation_warning` — `opv fly plan prod` with the existing fake setup: stderr contains `"fly plan" is deprecated; use "opv plan"`.
  - `fly_sync_alias_keeps_exit_code` — a refused `fly sync` exits 6, same as `sync`.
- [ ] **Step 2:** `cargo test --test cli` → the three new tests FAIL.
- [ ] **Step 3:** Implement in `main.rs`; update the help epilogue examples (`opv plan staging`, `opv sync staging --deploy`) and the `doctor`/`init` "Next step" strings only where they print `fly plan`/`fly sync` — **except** inside the characterization goldens' commands; if a golden's stdout contains `fly plan`/`fly sync` text, leave that text unchanged in P0 and note it in the report.
- [ ] **Step 4:** Update `README.md` and `CLAUDE.md` command lists to `plan`/`sync`, mentioning the deprecated aliases once.
- [ ] **Step 5:** `cargo test` → PASS; goldens unchanged; clippy and fmt clean.
- [ ] **Step 6: Commit** `feat(cli): opv plan and opv sync; fly plan/sync deprecated (FR-28, §8 28, #38)`

---

## After Task 5

Open PR `feat/p0-target-ports` → `dev` with "Closes #38", the golden-diff evidence (`git diff --stat dev -- tests/fixtures/characterization` shows only additions from Task 1), and a fleet staging `opv sync` dry run noted as a manual check before promotion.
