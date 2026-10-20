//! Regression scenarios for #150, #153, #157, #160, #183, #184, #188 and #201 (design §13.5): the
//! real `opv` binary against `opv-sim`, on the test application in `tests/e2e/app`. Each
//! scenario copies the app's world and configuration into a scratch directory, changes the
//! world where the issue needs it (an account signed out, a vault moved to the other
//! account), and asserts once on opv's public output: the exit code, the JSON `error.code`,
//! or whether a file exists.
//!
//! The world signs in two accounts on one sign-in address: the project's account (A, `dev`)
//! and another (B, `ops`). Every op failure reply is a recording under
//! `tests/fixtures/op/failures/` (README there), played back by the simulator.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const APP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e/app");
/// The project's account (A): it holds every vault of the app.
const PROJECT: &str = "AE2EDEVACCOUNT000000000001";
/// The other account on the same sign-in address (B).
const OTHER: &str = "AE2EOPSACCOUNT000000000002";

/// A scratch HOME, project and world, and the simulator installed under every tool name.
struct Scenario {
    root: tempfile::TempDir,
}

impl Scenario {
    /// The app's world, changed by `edit`, with the project's account in its `.opv`.
    fn new(edit: impl FnOnce(&mut Value)) -> Self {
        Self::in_dir(tempfile::tempdir().unwrap(), edit)
    }

    fn in_dir(root: tempfile::TempDir, edit: impl FnOnce(&mut Value)) -> Self {
        let s = Self { root };
        for dir in ["world", "home", "project"] {
            std::fs::create_dir_all(s.root.path().join(dir)).unwrap();
        }
        let mut world: Value = serde_json::from_str(
            &std::fs::read_to_string(Path::new(APP).join("world.json")).unwrap(),
        )
        .unwrap();
        edit(&mut world);
        std::fs::write(s.world().join("world.json"), world.to_string()).unwrap();
        std::fs::write(s.world().join("faults.toml"), "").unwrap();
        std::fs::copy(
            Path::new(APP).join("secrets.toml"),
            s.project().join("secrets.toml"),
        )
        .unwrap();
        std::fs::copy(
            Path::new(APP).join("secrets.bindings.toml"),
            s.project().join("secrets.bindings.toml"),
        )
        .unwrap();
        std::fs::write(
            s.project().join(".opv"),
            format!("account = \"{PROJECT}\"\n"),
        )
        .unwrap();
        let installed = Command::new(env!("CARGO_BIN_EXE_opv-sim"))
            .arg("install")
            .arg(s.bin())
            .env("OPV_SIM_WORLD", s.world())
            .status()
            .unwrap();
        assert!(installed.success());
        s
    }

    fn world(&self) -> PathBuf {
        self.root.path().join("world")
    }

    fn project(&self) -> PathBuf {
        self.root.path().join("project")
    }

    fn bin(&self) -> PathBuf {
        self.root.path().join("bin")
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.bin().display())
    }

    /// The simulator's world as it stands now.
    fn world_now(&self) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.world().join("world.json")).unwrap())
            .unwrap()
    }

    /// `opv <args>` in the project, against the simulator only.
    fn opv(&self, args: &[&str]) -> Output {
        self.opv_with(args, &[])
    }

    /// [`Self::opv`] with extra environment variables.
    fn opv_with(&self, args: &[&str], vars: &[(&str, &str)]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_opv"))
            .args(args)
            .current_dir(self.project())
            .env_clear()
            .env("OP_BIOMETRIC_UNLOCK_ENABLED", "false")
            .env("PATH", self.path())
            .env("HOME", self.home())
            .env("OPV_NO_SKILL", "1")
            .env("OPV_SIM_WORLD", self.world())
            .envs(vars.iter().copied())
            .output()
            .unwrap()
    }

    /// `opv login <args>` in `dir`. Login needs a terminal, so it runs under `script`
    /// (util-linux); `None` when this machine has no `script`. `Some` holds login's exit
    /// code (`script -e` returns its child's).
    #[cfg(target_os = "linux")]
    fn login_in(&self, dir: &Path, args: &[&str]) -> Option<i32> {
        let mut line = format!(
            "env -i PATH={} HOME={} OPV_NO_SKILL=1 OPV_SIM_WORLD={} {} login",
            self.path(),
            self.home().display(),
            self.world().display(),
            env!("CARGO_BIN_EXE_opv"),
        );
        for a in args {
            line.push(' ');
            line.push_str(a);
        }
        let out = Command::new("script")
            .args(["-qec", &line, "/dev/null"])
            .current_dir(dir)
            .stdin(std::process::Stdio::null())
            .output()
            .ok()?;
        Some(out.status.code().unwrap_or(-1))
    }
}

/// Set `field` of the world's vault `id`.
fn set_vault(world: &mut Value, id: &str, field: &str, value: &str) {
    for vault in world["op"]["vaults"].as_array_mut().unwrap() {
        if vault["id"] == id {
            vault[field] = value.into();
        }
    }
}

/// Sign each account of the world in or out, as `signed_in` says for its ID.
fn sign_in(world: &mut Value, signed_in: impl Fn(&str) -> bool) {
    for account in world["op"]["accounts"].as_array_mut().unwrap() {
        let id = account["id"].as_str().unwrap().to_string();
        account["signed_in"] = signed_in(&id).into();
    }
}

fn document(out: &Output) -> Value {
    serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .next()
        .and_then(Result::ok)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------------------
// #150: a write matches the plan a person saw, and the unconfirmed run writes nothing.
// ---------------------------------------------------------------------------------------

/// The targets this scenario writes (the world has no Kubernetes Deployment to restart).
const TARGETS: &[&str] = &["--target", "fly", "--target", "gh"];

/// `target/name` of every name the world's Fly app and GitHub repository have staged or set.
fn written(world: &Value) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for app in world["fly"]["apps"].as_object().into_iter().flatten() {
        for s in app.1["secrets"].as_array().into_iter().flatten() {
            if s["status"] == "Staged" {
                names.insert(format!("fly/{}", s["name"].as_str().unwrap_or_default()));
            }
        }
    }
    for repo in world["github"]["repos"].as_object().into_iter().flatten() {
        let mut scopes = vec![repo.1.clone()];
        scopes.extend(
            repo.1["environments"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|e| e.1.clone()),
        );
        for scope in scopes {
            for list in ["secrets", "variables"] {
                for name in scope[list].as_object().into_iter().flatten() {
                    names.insert(format!("gh/{}", name.0));
                }
            }
        }
    }
    names
}

/// `target/name` of every row the plan would write.
fn planned(plan: &Value) -> BTreeSet<String> {
    plan["rows"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["action"] == "would_stage")
        .map(|r| {
            format!(
                "{}/{}",
                r["target"].as_str().unwrap_or_default(),
                r["target_name"].as_str().unwrap_or_default()
            )
        })
        .collect()
}

#[test]
fn issue_150_sync_without_confirm_writes_nothing_and_the_confirmed_write_is_the_plan() {
    let s = Scenario::new(|_| {});
    let before = s.world_now();
    let mut unconfirmed = vec!["sync", "prod", "--json"];
    unconfirmed.extend(TARGETS);
    s.opv(&unconfirmed);
    let after_unconfirmed = s.world_now();
    let mut plan = vec!["plan", "prod", "--json"];
    plan.extend(TARGETS);
    let shown = planned(&document(&s.opv(&plan)));
    let mut confirmed = vec!["sync", "prod", "--confirm", "prod", "--json"];
    confirmed.extend(TARGETS);
    s.opv(&confirmed);
    assert_eq!(
        (after_unconfirmed == before, written(&s.world_now())),
        (true, shown)
    );
}

// ---------------------------------------------------------------------------------------
// #153: a vault in the other account, a foreign OP_SESSION_*, and no `.opv` outside a project.
// ---------------------------------------------------------------------------------------

/// (a) A value vault held by the other account is a configuration error that names that
/// account, not a missing item.
#[test]
fn issue_153_a_value_vault_in_the_other_account_names_that_account() {
    let s = Scenario::new(|w| set_vault(w, "vE2EWEBDEV0000000000000001", "account", OTHER));
    let error = document(&s.opv(&["config", "export", "dev", "--json"]))["error"].clone();
    assert!(
        error["code"] != "item_not_found" && error.to_string().contains(OTHER),
        "{error}"
    );
}

/// (b) An `OP_SESSION_*` for the other account, which is also op's default account here, is
/// never used for the project's account: every call names the project's account, so the
/// check reads the project's vaults.
#[test]
fn issue_153_a_session_variable_for_the_other_account_is_not_used_for_the_project() {
    let s = Scenario::new(|w| w["op"]["default_account"] = OTHER.into());
    let session = format!("OP_SESSION_{OTHER}");
    let out = s.opv_with(
        &["config", "export", "dev", "--json"],
        &[(session.as_str(), "test-marker-e2e-ops-session")],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// A scratch directory with no `.opv` and no `.git` in it or above it (a stray `/tmp/.opv`
/// on one machine would otherwise put every temporary directory "in a project").
#[cfg(target_os = "linux")]
fn outside_any_project() -> tempfile::TempDir {
    let clean = |d: &Path| {
        d.ancestors()
            .all(|a| !a.join(".opv").exists() && !a.join(".git").exists())
    };
    [std::env::temp_dir(), "/var/tmp".into(), "/dev/shm".into()]
        .into_iter()
        .filter(|base| base.is_dir() && clean(base))
        .find_map(|base| tempfile::tempdir_in(base).ok())
        .expect("a temporary directory with no .opv or .git above it")
}

/// (c) A one-off `opv login --account <id> -- <command>` outside any project records no
/// account: no `.opv` is written.
#[cfg(target_os = "linux")]
#[test]
fn issue_153_login_outside_any_project_writes_no_opv_file() {
    let s = Scenario::in_dir(outside_any_project(), |_| {});
    let outside = s.root.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    if s.login_in(&outside, &["--account", PROJECT, "--", "true"])
        .is_none()
    {
        return; // no `script` on this machine: nothing to run the terminal under
    }
    assert!(!outside.join(".opv").exists());
}

// ---------------------------------------------------------------------------------------
// #157: access diagnoses a sign-in and a vault outside the account.
// ---------------------------------------------------------------------------------------

/// (a) Signed out of every account, `opv access` asks for a sign-in.
#[test]
fn issue_157_access_while_signed_out_is_op_not_signed_in() {
    let s = Scenario::new(|w| sign_in(w, |_| false));
    let doc = document(&s.opv(&["access", "prod", "--json"]));
    assert_eq!(doc["error"]["code"], "op_not_signed_in");
}

/// (b) One state vault held by the other account: access reports that vault as not in the
/// account and still checks every other vault.
#[test]
fn issue_157_access_reports_the_vault_outside_the_account_and_checks_the_others() {
    let s = Scenario::new(|w| set_vault(w, "vE2ESTATEFLY00000000000001", "account", OTHER));
    let doc = document(&s.opv(&["access", "prod", "--json"]));
    let states: BTreeMap<String, String> = doc["environments"][0]["report"]["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| {
            (
                c["grant"]["vault_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                c["state"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let expected: BTreeMap<String, String> = [
        ("vE2ESHAREDPROD0000000000001", "missing"),
        ("vE2ESTATEFLY00000000000001", "not_in_account"),
        ("vE2ESTATEGH000000000000001", "missing"),
        ("vE2ESTATEK8S00000000000001", "missing"),
        ("vE2EWEBPROD000000000000001", "missing"),
    ]
    .into_iter()
    .map(|(v, s)| (v.to_string(), s.to_string()))
    .collect();
    assert_eq!(states, expected);
}

// ---------------------------------------------------------------------------------------
// #160: login to B while A's session on the same sign-in address is live.
// ---------------------------------------------------------------------------------------

/// `opv login --account B` with only A signed in: op's `whoami --account B` says "no active
/// session found" (recording 11), and op's own sign-in for B succeeds with A's session
/// live (recording 13), so login signs in to B and runs its command.
#[cfg(target_os = "linux")]
#[test]
fn issue_160_login_to_b_while_a_is_signed_in_signs_in_to_b() {
    let s = Scenario::new(|w| sign_in(w, |id| id == PROJECT));
    let Some(code) = s.login_in(&s.project(), &["--account", OTHER, "--", "true"]) else {
        return; // no `script` on this machine: nothing to run the terminal under
    };
    assert_eq!(code, 0);
}

// ---------------------------------------------------------------------------------------
// C8: `mcp install --client all` keeps the client it already registered when a later one
// fails, instead of losing that record (R53, X20).
// ---------------------------------------------------------------------------------------

/// With codex's file holding a conflicting entry, claude is registered first; the failure
/// must still name claude as already registered.
#[test]
fn mcp_install_all_names_the_client_registered_before_a_later_client_failed() {
    let s = Scenario::new(|_| {});
    let codex = s.root.path().join("codex");
    std::fs::create_dir_all(&codex).unwrap();
    std::fs::write(
        codex.join("config.toml"),
        "[mcp_servers.opv]\ncommand = \"/elsewhere/opv-mcp\"\nargs = []\n",
    )
    .unwrap();
    let out = s.opv_with(
        &["mcp", "install", "--client", "all", "--json"],
        &[("CODEX_HOME", codex.to_str().unwrap())],
    );
    assert_eq!(
        document(&out)["error"]["subject"]["done"],
        serde_json::json!(["claude"])
    );
}

/// #160: `op signin --force --account B` is played from recording 13 and starts B's
/// session, so the simulated machine holds B signed in afterwards.
#[cfg(target_os = "linux")]
#[test]
fn issue_160_signin_to_b_leaves_b_signed_in_on_the_simulated_machine() {
    let s = Scenario::new(|w| sign_in(w, |id| id == PROJECT));
    if s.login_in(&s.project(), &["--account", OTHER, "--", "true"])
        .is_none()
    {
        return; // no `script` on this machine: nothing to run the terminal under
    }
    let accounts = s.world_now()["op"]["accounts"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        accounts
            .iter()
            .find(|a| a["id"] == OTHER)
            .is_some_and(|a| a["signed_in"] == true)
    );
}

/// #160: recording 13 only covers `op signin` while another account's session is live. With
/// none, real op prompts, which the simulator does not model.
#[test]
fn issue_160_signin_without_another_live_session_is_unsupported() {
    let s = Scenario::new(|w| sign_in(w, |_| false));
    let out = Command::new(s.bin().join("op"))
        .args(["signin", "--force", "--account", OTHER])
        .env("OPV_SIM_WORLD", s.world())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(87));
}

// ---------------------------------------------------------------------------------------
// #183: `--project` names the project of a structural proposal and of its apply.
// ---------------------------------------------------------------------------------------

/// #183: the structure proposed under `--project` steps to the apply under the same name,
/// whose plan id is only valid for it.
#[test]
fn issue_183_a_structure_proposed_with_a_project_steps_to_its_apply_with_it() {
    let s = Scenario::new(|_| {});
    let out = s.opv(&[
        "propose",
        "structure",
        "--project",
        "mcproductlabs-infra",
        "--json",
    ]);
    assert!(
        document(&out)["next"]["command"]
            .as_str()
            .is_some_and(|c| c.ends_with(" --project mcproductlabs-infra")),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

// ---------------------------------------------------------------------------------------
// #184: a generated configuration's proposal goes to its generator, then the structure.
// ---------------------------------------------------------------------------------------

/// #184: the read-only proposal on a generated configuration never steps to the `--write`
/// that would be refused.
#[test]
fn issue_184_a_proposal_on_a_generated_config_never_offers_write_next() {
    let s = Scenario::new(|_| {});
    let path = s.project().join("secrets.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("# generated by gen-config\n{text}")).unwrap();
    let out = s.opv(&["propose", "env", "staging", "--json"]);
    assert_eq!(
        document(&out)["next"]["command"],
        "opv propose structure",
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

// ---------------------------------------------------------------------------------------
// #188: `config export <env>` with several products exports each one's config values.
// ---------------------------------------------------------------------------------------

/// A second runnable product, `api`, with one config key in the web boundary's dev item.
const API_PRODUCT: &str = r#"
[products.api]
boundary = "web"

[products.api.keys.API_MODE]
kind = "config"
environments = ["dev"]
"#;

/// The app plus [`API_PRODUCT`], its `API_MODE` field filled in the dev web item.
fn with_api_product() -> Scenario {
    let s = Scenario::new(|w| {
        for i in w["op"]["items"].as_array_mut().unwrap() {
            if i["id"] == "iE2EWEBDEV0000000000000001" {
                i["fields"].as_array_mut().unwrap().push(serde_json::json!({
                    "id": "api_api_mode",
                    "section": {"id": "api", "label": "api"},
                    "type": "STRING",
                    "label": "API_MODE",
                    "value": "strict"
                }));
            }
        }
    });
    let file = s.project().join("secrets.toml");
    let toml = std::fs::read_to_string(&file).unwrap() + API_PRODUCT;
    std::fs::write(&file, toml).unwrap();
    s
}

#[test]
fn issue_188_config_export_with_several_products_exports_each() {
    let s = with_api_product();
    let doc = document(&s.opv(&["config", "export", "dev", "--json"]));
    let products: Vec<String> = doc
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    assert_eq!(products, ["api", "web"], "{doc}");
}

// ---------------------------------------------------------------------------------------
// #201: a person's attestation of a held immutable key is proposed, never assumed.
// ---------------------------------------------------------------------------------------

/// #201: an attestation proposal on a placement no sync has recorded (the app's Fly target
/// has no delivery items) is refused naming the key and the target, through the same
/// intent document `opv_propose` takes. The full record-then-mint path needs a terminal
/// and recorded delivery items, and is covered on the library's world
/// (`src/app/attest_tests.rs`).
#[test]
fn issue_201_an_attestation_on_an_unrecorded_placement_is_refused() {
    let s = Scenario::new(|_| {});
    let file = s.project().join("secrets.toml");
    let toml = std::fs::read_to_string(&file).unwrap().replace(
        "roles = [\"serve\"]\n\n# The migrating",
        "roles = [\"serve\"]\nimmutable = true\n\n# The migrating",
    );
    std::fs::write(&file, toml).unwrap();
    std::fs::write(
        s.project().join("attest.json"),
        r#"{"kind": "attest", "env": "prod", "target": "fly", "keys": ["web/SESSION_SECRET"]}"#,
    )
    .unwrap();
    let out = s.opv(&["propose", "--intent", "attest.json", "--json"]);
    let message = document(&out)["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        message.contains("attestation of web/SESSION_SECRET on prod/fly"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
