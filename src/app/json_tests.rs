//! The `--json` contract (A1, A5, A6): one golden document per command for its success
//! and its failure shape, framed exactly as `main` frames stdout ([`crate::json::finish`]).
//! `UPDATE_GOLDEN=1` rewrites them in `tests/fixtures/json/`. Every fixture value carries
//! [`MARKER`]; no golden may contain it (SR-1).

use super::sync::{self, SyncOpts};
use super::testutil::*;
use super::{local, skeleton, status};
use crate::error::Error;
use crate::runner::fake::FakeRunner;

/// stdout as `main` prints it for `--json`: the command's body, framed with its result,
/// whose steps render against `rerun`, the command line.
pub(crate) fn framed(body: &[u8], res: &Result<(), Error>, rerun: &str) -> String {
    let words: Vec<String> = rerun.split_whitespace().map(str::to_string).collect();
    let inv = crate::cause::Invocation::from_cli(&words);
    String::from_utf8(crate::json::finish_with(
        body,
        res.as_ref().map(|_| ()),
        false,
        &inv,
        false,
    ))
    .unwrap()
}

/// `framed` with the temporary directory `dir` replaced by `<dir>` and the rest of each such
/// path written with `/`, so one golden serves every platform. The directory is replaced in
/// both its raw and its JSON-escaped spelling (`C:\\Users\\...` inside a JSON string).
pub(crate) fn without_dir(framed: &str, dir: &std::path::Path) -> String {
    let raw = dir.display().to_string();
    let quoted = serde_json::to_string(&raw).expect("a string");
    let escaped = &quoted[1..quoted.len() - 1];
    let s = framed.replace(escaped, "<dir>").replace(&raw, "<dir>");
    // The rest of the path, up to the end of its JSON string: separators become `/`.
    let mut out = String::with_capacity(s.len());
    let mut rest = s.as_str();
    while let Some(at) = rest.find("<dir>") {
        let (before, tail) = rest.split_at(at + "<dir>".len());
        out.push_str(before);
        let end = tail.find('"').unwrap_or(tail.len());
        out.push_str(&tail[..end].replace("\\\\", "/").replace('\\', "/"));
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// `framed` without the `checks` entry named `name`. `doctor` runs the `op local run` check
/// off Windows only (a Windows `op.exe` reached from WSL is what it detects, #54), so the
/// doctor goldens leave it out on every platform; its own tests cover it.
pub(crate) fn without_check(framed: &str, name: &str) -> String {
    let mut doc: serde_json::Value = serde_json::from_str(framed).expect("one JSON document");
    if let Some(checks) = doc["checks"].as_array_mut() {
        checks.retain(|c| c["name"] != name);
    }
    serde_json::to_string(&doc).unwrap()
}

/// Compare `actual` (one JSON line) with `tests/fixtures/json/<name>.json`, pretty-printed
/// so a diff shows the field that moved.
pub(crate) fn golden(name: &str, actual: &str) {
    let doc: serde_json::Value = serde_json::from_str(actual).expect("one JSON document");
    let pretty = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    assert_no_values(&pretty);
    let path = format!("tests/fixtures/json/{name}.json");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all("tests/fixtures/json").unwrap();
        std::fs::write(&path, &pretty).unwrap();
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(expected, pretty, "golden {path} differs");
}

#[test]
fn a_windows_temp_path_is_normalized_in_its_json_escaped_form() {
    let dir = std::path::Path::new(r"C:\Users\RUNNER~1\AppData\Local\Temp\.tmpAB12");
    let framed = serde_json::json!({ "path": dir.join("secrets.toml").display().to_string() })
        .to_string()
        .replace('/', "\\\\");
    assert_eq!(
        without_dir(&framed, dir),
        r#"{"path":"<dir>/secrets.toml"}"#
    );
}

fn status_json(item: crate::runner::Output) -> String {
    let r = FakeRunner::new([item, fly(&[(OPENAI_FLY, "d1")])]);
    let mut out = Vec::new();
    let res = status::run_with(&fleet(), "prod", &r, &mut out, true);
    framed(&out, &res, "opv status prod --json")
}

#[test]
fn status_success() {
    golden("status_success", &status_json(complete_item()));
}

#[test]
fn status_findings() {
    golden(
        "status_findings",
        &status_json(item_without("allumata", "OPENAI_API_KEY")),
    );
}

#[test]
fn status_unknown_environment() {
    let r = FakeRunner::new([]);
    let mut out = Vec::new();
    let res = status::run_with(&fleet(), "qa", &r, &mut out, true);
    golden(
        "status_unknown_env",
        &framed(&out, &res, "opv status qa --json"),
    );
}

#[test]
fn status_overview_run_only_environment() {
    let f = fleet_with("[environments.dev]\n");
    // dev (run-only) declares no key, so it has no boundary to read (FR-57); then prod and
    // staging, item and list.
    let r = FakeRunner::new([
        complete_item(),
        fly(&[(OPENAI_FLY, "d1")]),
        complete_item(),
        fly_empty(),
    ]);
    let mut out = Vec::new();
    let res = status::overview(&f, None, &r, &mut out, true);
    golden("status_overview", &framed(&out, &res, "opv status --json"));
}

fn plan_json(item: crate::runner::Output) -> String {
    let r = FakeRunner::new([item, fly(&[(OPENAI_FLY, "d1")])]);
    let mut out = Vec::new();
    let res = sync::plan_scoped(&fleet(), "prod", None, &r, &mut out, true);
    framed(&out, &res, "opv plan prod --json")
}

#[test]
fn plan_success() {
    golden("plan_success", &plan_json(complete_item()));
}

/// The fixture fleet with `fly.config = "secrets"` on its prod Fly target.
fn config_secrets_fleet() -> crate::domain::Fleet {
    let text = std::fs::read_to_string("tests/fixtures/secrets.toml")
        .unwrap()
        .replace(
            "fly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"\nstate_vault_id = \"sprd\"",
            "fly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"\nfly.config = \"secrets\"\nstate_vault_id = \"sprd\"",
        );
    crate::config::parse(&text).unwrap()
}

#[test]
fn a_config_row_on_a_secrets_fly_target_reports_via_fly_secret() {
    let fleet = config_secrets_fleet();
    let r = FakeRunner::new([complete_item(), fly(&[(OPENAI_FLY, "d1")])]);
    let mut out = Vec::new();
    let _ = sync::plan_scoped(&fleet, "prod", None, &r, &mut out, true);
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let row = doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == "SIGNUP_POLICY")
        .unwrap();
    assert_eq!(row["via"], serde_json::json!("Fly secret"));
}

#[test]
fn plan_findings() {
    golden(
        "plan_findings",
        &plan_json(item_without("allumata", "OPENAI_API_KEY")),
    );
}

fn check_json(item: crate::runner::Output) -> String {
    let r = FakeRunner::new([item]);
    let mut out = Vec::new();
    let res = local::check(&fleet(), "prod", Some("allumata"), &r, &mut out, true);
    framed(&out, &res, "opv check prod --product allumata --json")
}

#[test]
fn check_success() {
    golden("check_success", &check_json(complete_item()));
}

#[test]
fn check_findings() {
    golden(
        "check_findings",
        &check_json(item_without("allumata", "OPENAI_API_KEY")),
    );
}

fn sync_json(r: &FakeRunner) -> String {
    let opts = SyncOpts {
        json: true,
        ..SyncOpts::default()
    };
    let mut out = Vec::new();
    let res = sync::run(&fleet(), "prod", r, &mut out, &opts);
    framed(&out, &res, "opv sync prod --json")
}

#[test]
fn sync_success() {
    let [st, rel] = fly_preflight_ok();
    let r = FakeRunner::new([
        complete_item(),
        fly_empty(),
        st,
        rel,
        ok(),
        fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]),
    ]);
    r.responses
        .borrow_mut()
        .extend(delivery_not_recorded(complete_item()).map(Ok));
    golden("sync_success", &sync_json(&r));
}

#[test]
fn sync_refused() {
    let r = FakeRunner::new([item_without("allumata", "OPENAI_API_KEY"), fly_empty()]);
    golden("sync_refused", &sync_json(&r));
}

#[test]
fn sync_confirm_required() {
    let mut f = fleet();
    f.environments.get_mut("prod").unwrap().confirm_env = true;
    let opts = SyncOpts {
        json: true,
        deploy: true,
        ..SyncOpts::default()
    };
    let mut out = Vec::new();
    // H12: the read-only part runs first; the guard refuses right before the first write.
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    let res = sync::run(&f, "prod", &r, &mut out, &opts);
    // The handoff is rendered from the process's own command line (R61), which a unit test
    // does not have: the golden keeps the shape and leaves the command out.
    let mut doc: serde_json::Value =
        serde_json::from_str(&framed(&out, &res, "opv sync prod --deploy --json")).unwrap();
    doc["next"] = "<the command as typed> --confirm prod".into();
    doc["error"]["next"] = "<the command as typed> --confirm prod".into();
    golden("sync_confirm_required", &doc.to_string());
}

fn explain_json(key: &str) -> String {
    let mut out = Vec::new();
    let res = crate::app::testutil::explain(&fleet(), key, Some("prod"), &mut out, true);
    framed(&out, &res, "opv explain --json")
}

#[test]
fn explain_success() {
    golden("explain_success", &explain_json("allumata/OPENAI_API_KEY"));
}

#[test]
fn explain_undeclared_key() {
    golden("explain_undeclared", &explain_json("allumata/OPENAI_KEY"));
}

#[test]
fn skeleton_success() {
    let r = FakeRunner::new([item_without("allumata", "OPENAI_API_KEY"), ok()]);
    let mut out = Vec::new();
    let res = skeleton::run_as(&fleet(), "prod", &r, &mut out, true);
    golden(
        "skeleton_success",
        &framed(&out, &res, "opv item skeleton prod --json"),
    );
}

#[test]
fn skeleton_unknown_environment() {
    let mut out = Vec::new();
    let res = skeleton::run_as(&fleet(), "qa", &FakeRunner::new([]), &mut out, true);
    golden(
        "skeleton_unknown_env",
        &framed(&out, &res, "opv item skeleton qa --json"),
    );
}

// ---- The schema covers every field (A4): links (H1), changes (H8), shared keys (FR-45),
// tidy (FR-43) ----------------------------------------------------------------------------

/// The fields `opv schema` lists for document `doc`, without `?` (optional) or a
/// `: [...]` shape suffix, in order.
pub(crate) fn documented(doc: &str) -> Vec<String> {
    let schema = crate::schema::describe(&clap::Command::new("opv"), "0");
    schema["documents"][doc]
        .as_array()
        .unwrap_or_else(|| panic!("no document {doc:?} in the schema"))
        .iter()
        .map(|f| {
            let f = f.as_str().unwrap();
            let f = f.split(':').next().unwrap();
            let f = f.split(" (").next().unwrap();
            f.trim_end_matches('?').trim().to_string()
        })
        .collect()
}

/// The top-level fields of `doc` outside the frame (A1) that the schema does not list.
pub(crate) fn undocumented(doc: &serde_json::Value, name: &str) -> Vec<String> {
    let listed = documented(name);
    let frame = ["schema_version", "ok", "exit_code", "next", "do", "error"];
    doc.as_object()
        .unwrap()
        .keys()
        .filter(|k| !frame.contains(&k.as_str()) && !listed.contains(k))
        .cloned()
        .collect()
}

/// The e2e app's prod targets (Fly, Kubernetes, GitHub) with one config and one secret
/// field, so `json_rows` can be driven per provider.
fn e2e_fleet() -> crate::domain::Fleet {
    crate::config::load("tests/e2e/app/secrets.toml").unwrap()
}

fn e2e_field(key: &str, kind: crate::domain::Kind) -> crate::domain::ItemField {
    crate::domain::ItemField {
        section: "shared".into(),
        label: key.into(),
        kind,
        value: crate::domain::SecretValue::new("on".into()),
        concealed: false,
    }
}

fn e2e_row(key: &str, kind: crate::domain::Kind, target: &str) -> super::JsonRow {
    let fleet = e2e_fleet();
    let plan = crate::domain::build_plan(
        &fleet,
        "prod",
        vec![e2e_field(key, kind)],
        &[],
        &std::collections::BTreeSet::new(),
        &|_| None,
    );
    let channels = fleet.environments["prod"].targets[target].config.channels();
    let part = super::JsonPart {
        target,
        plan: &plan,
        pinned: None,
        rotate: None,
        vars: None,
    };
    super::json_rows(
        &fleet,
        &part,
        &|_: &str, _: &str| None,
        None,
        Some(&channels),
    )
    .into_iter()
    .find(|r| r.key == key)
    .unwrap()
}

/// A config row on GitHub names its channel `via: "GitHub variable"` (design §6.7).
#[test]
fn a_github_config_rows_via_names_its_channel() {
    assert_eq!(
        e2e_row("FEATURE_FLAGS", crate::domain::Kind::Config, "gh").via,
        Some("GitHub variable")
    );
}

/// A config row on Kubernetes (`config = env`) names its channel `via: "env"` (design §6.7).
#[test]
fn a_kubernetes_config_rows_via_is_env() {
    assert_eq!(
        e2e_row("FEATURE_FLAGS", crate::domain::Kind::Config, "k8s").via,
        Some("env")
    );
}

/// A secret row's `channel` reads `secret` (design §6.7).
#[test]
fn a_secret_rows_channel_reads_secret() {
    assert_eq!(
        e2e_row("DATABASE_URL", crate::domain::Kind::Secret, "gh").channel,
        "secret"
    );
}

/// A fleet with two file keys (one plain, one `pem_private_key`) on the Fly target; the
/// `json_rows` tests pass the target's channels in by hand.
fn file_fleet() -> crate::domain::Fleet {
    crate::config::parse(
        "[environments.prod]\n\
         boundaries.p = { vault_id = \"v\", item_id = \"i\" }\n\
         [environments.prod.targets.fly]\n\
         fly.app = \"app\"\n\
         fly.secret_name = \"{KEY}\"\n\
         state_vault_id = \"s\"\n\
         [products.p.local]\n\
         secrets_dir_env = \"P_SECRETS_DIR\"\n\
         [products.p.keys.PRIVATE_KEY]\n\
         kind = \"secret\"\n\
         environments = [\"prod\"]\n\
         file = \"github-app/private-key\"\n\
         [products.p.keys.PRIVATE_KEY_T]\n\
         kind = \"secret\"\n\
         environments = [\"prod\"]\n\
         file = \"github-app/private-key-t\"\n\
         rules = { transform = \"pem_private_key\" }\n",
    )
    .unwrap()
}

fn native_channels() -> crate::provider::Channels {
    crate::provider::Channels {
        secret: crate::provider::Channel::RuntimeEnv,
        config: crate::provider::Channel::RuntimeEnv,
        files: crate::provider::FileCapability::Native {
            dir: "/etc/secrets",
        },
    }
}

fn fly_channels() -> crate::provider::Channels {
    crate::provider::Channels {
        secret: crate::provider::Channel::Store {
            label: "Fly secrets",
        },
        config: crate::provider::Channel::Store {
            label: "Fly secrets",
        },
        files: crate::provider::FileCapability::ViaApp {
            note: "the app writes env to files (Journeeze's shim)",
        },
    }
}

fn file_field(key: &str) -> crate::domain::ItemField {
    crate::domain::ItemField {
        section: "shared".into(),
        label: key.into(),
        kind: crate::domain::Kind::Secret,
        value: crate::domain::SecretValue::new("x".into()),
        concealed: true,
    }
}

fn file_json_row(key: &str, channels: &crate::provider::Channels) -> super::JsonRow {
    let fleet = file_fleet();
    let plan = crate::domain::build_plan(
        &fleet,
        "prod",
        vec![file_field(key)],
        &[],
        &std::collections::BTreeSet::new(),
        &|_| None,
    );
    let part = super::JsonPart {
        target: "fly",
        plan: &plan,
        pinned: None,
        rotate: None,
        vars: None,
    };
    super::json_rows(
        &fleet,
        &part,
        &|_, k| Some(k.to_string()),
        None,
        Some(channels),
    )
    .into_iter()
    .find(|r| r.key == key)
    .unwrap()
}

/// M4 (§4.5/§6.7): on a Native target a file key is delivered as the file itself.
#[test]
fn a_native_file_row_is_delivered_as_a_verbatim_file() {
    let row = file_json_row("PRIVATE_KEY", &native_channels());
    assert_eq!(
        (row.delivered_as, row.form.as_deref(), row.path.as_deref()),
        (
            Some("file"),
            Some("verbatim"),
            Some("github-app/private-key")
        )
    );
}

/// M4 (§4.5/§6.7): where the app writes the file from the environment, the row names the
/// transform's one-line form.
#[test]
fn a_fly_file_row_is_delivered_as_env_with_the_transform() {
    let row = file_json_row("PRIVATE_KEY_T", &fly_channels());
    assert_eq!(
        (row.delivered_as, row.form.as_deref()),
        (Some("env"), Some("pem_private_key"))
    );
}

/// M4 (§4.5): the text row names the form too: `file (verbatim)` on a Native target.
#[test]
fn a_native_file_cell_names_the_verbatim_file() {
    let fleet = file_fleet();
    let row = crate::domain::Row {
        product: "p".into(),
        key: "PRIVATE_KEY".into(),
        kind: crate::domain::Kind::Secret,
        state: crate::domain::KeyState::Ready,
        target: crate::domain::TargetState::Absent,
        guidance: String::new(),
        source: None,
        shared_by: Vec::new(),
    };
    let spec = &fleet.products["p"].keys["PRIVATE_KEY"];
    assert_eq!(
        super::target_cell(&row, "new", &native_channels(), Some(spec)),
        "new · file (verbatim)"
    );
}

/// M4 (§4.2): the plumbing names every delivered file key by its rendered name.
#[test]
fn file_mounts_names_every_delivered_file_key() {
    let fleet = file_fleet();
    assert_eq!(
        super::file_mounts(&fleet, "prod", "fly").unwrap(),
        std::collections::BTreeMap::from([
            (
                "PRIVATE_KEY".to_string(),
                crate::domain::runtime::FileMount {
                    product: "p".into(),
                    path: "github-app/private-key".into(),
                },
            ),
            (
                "PRIVATE_KEY_T".to_string(),
                crate::domain::runtime::FileMount {
                    product: "p".into(),
                    path: "github-app/private-key-t".into(),
                },
            ),
        ])
    );
}

/// M4 (§1.3): a target that does not honour file destinations warns, once per file key.
#[test]
fn a_target_without_file_support_warns_for_a_file_key() {
    let fleet = file_fleet();
    let plan = crate::domain::build_plan(
        &fleet,
        "prod",
        vec![file_field("PRIVATE_KEY")],
        &[],
        &std::collections::BTreeSet::new(),
        &|_| None,
    );
    let none = crate::provider::Channels {
        secret: crate::provider::Channel::RuntimeEnv,
        config: crate::provider::Channel::RuntimeEnv,
        files: crate::provider::FileCapability::None,
    };
    assert_eq!(
        super::file_destination_lines(&fleet, "prod", "fly", &none, &plan),
        vec![
            "prod/fly: warning: p/PRIVATE_KEY file destination not honoured on fly".to_string(),
            "prod/fly: warning: p/PRIVATE_KEY_T file destination not honoured on fly".to_string(),
        ]
    );
}

/// M4 (§1.3): a target that delivers files through the app notes how, once per file key.
#[test]
fn a_via_app_file_destination_is_noted_for_a_file_key() {
    let fleet = file_fleet();
    let plan = crate::domain::build_plan(
        &fleet,
        "prod",
        vec![file_field("PRIVATE_KEY")],
        &[],
        &std::collections::BTreeSet::new(),
        &|_| None,
    );
    assert_eq!(
        super::file_destination_lines(&fleet, "prod", "fly", &fly_channels(), &plan),
        vec![
            "prod/fly: note: p/PRIVATE_KEY file via the app (the app writes env to files (Journeeze's shim))"
                .to_string(),
            "prod/fly: note: p/PRIVATE_KEY_T file via the app (the app writes env to files (Journeeze's shim))"
                .to_string(),
        ]
    );
}

#[test]
fn the_schema_lists_every_row_field_in_order() {
    let row = crate::domain::Row {
        product: "allumata".into(),
        key: "OPENAI_API_KEY".into(),
        kind: crate::domain::Kind::Secret,
        state: crate::domain::KeyState::Ready,
        target: crate::domain::TargetState::Present,
        guidance: String::new(),
        source: Some(("api".into(), "OPENAI_API_KEY".into())),
        shared_by: Vec::new(),
    };
    let full = super::JsonRow {
        binding: Some("current"),
        pending_deploy: Some(false),
        drift: Some(false),
        chain: Some("a → b".into()),
        open_url: Some("https://start.1password.com/open/i".into()),
        via: Some("env"),
        delivered_as: Some("env"),
        form: Some("file".to_string()),
        path: Some("/app/config".into()),
        ..super::JsonRow::new(&row, Some("NAME".into()), Some("present"), None)
    };
    let v = serde_json::to_value(&full).unwrap();
    let keys: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, documented("row"));
}

#[test]
fn the_schema_lists_every_field_of_every_golden_document() {
    let mut missing = Vec::new();
    for entry in std::fs::read_dir("tests/fixtures/json").unwrap() {
        let path = entry.unwrap().path();
        let file = path.file_stem().unwrap().to_str().unwrap().to_string();
        let name = match file.split('_').next().unwrap() {
            "status" if file == "status_overview" => "status_overview",
            "skeleton" => "item skeleton",
            other => other,
        };
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for f in undocumented(&doc, name) {
            missing.push(format!("{file}: {f}"));
        }
    }
    assert!(missing.is_empty(), "{missing:?}");
}
