//! Output contract (UX1): run summary and `sync --json` (P2, NR-18), `Next:` steps (P1,
//! NR-19), `confirm_env` (P10, NR-20), `plan` naming its actions (P11), `--product` on
//! status, plan and sync (P12, P20, NR-16), `product/KEY (NAME)` names (P19), `status`
//! without an environment (P22) and provider-neutral wording (P4). One behavioural
//! assertion per test.

use serde_json::Value;

use super::status;
use super::sync::{self, SyncOpts, drift_line};
use super::testutil::*;
use crate::config;
use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const WEB_TOKEN: &str = "FLEET__WEB__TOKEN";
const WEB_OLD: &str = "FLEET__WEB__OLD";

/// The fixture with `confirm_env = true` on prod.
fn guarded() -> Fleet {
    let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
    config::parse(&text.replace(
        "modes.allumata.payments = \"off\"",
        "modes.allumata.payments = \"off\"\nconfirm_env = true",
    ))
    .unwrap()
}

/// The fixture plus a second product, `web`: TOKEN (prod) and OLD (staging only).
fn two_products() -> Fleet {
    fleet_with(
        "[products.web.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
         [products.web.keys.OLD]\nkind = \"secret\"\nenvironments = [\"staging\"]\n",
    )
}

fn with_web_token() -> Output {
    let mut fs = complete_fields();
    fs.push(secret("web", "TOKEN", "tok-FIXTUREVALUE"));
    item(&fs)
}

/// item, list A, the two preflight reads, import, list B, then spare answers.
fn fly_run(item: Output, a: Output, b: Output) -> FakeRunner {
    let [st, rel] = fly_preflight_ok();
    FakeRunner::new([item, a, st, rel, ok(), b, ok(), ok(), ok()])
}

fn new_secrets() -> FakeRunner {
    fly_run(
        complete_item(),
        fly_empty(),
        fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]),
    )
}

fn unchanged() -> FakeRunner {
    let same = || fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]);
    fly_run(complete_item(), same(), same())
}

fn sync_out(fleet: &Fleet, r: &FakeRunner, o: &SyncOpts) -> (Result<(), Error>, String) {
    let mut out = Vec::new();
    let res = sync::run(fleet, "prod", r, &mut out, o);
    (res, text_of(&out))
}

fn deploy() -> SyncOpts {
    SyncOpts {
        deploy: true,
        ..SyncOpts::default()
    }
}

fn json() -> SyncOpts {
    SyncOpts {
        json: true,
        ..SyncOpts::default()
    }
}

fn product(p: &str) -> SyncOpts {
    SyncOpts {
        product: Some(p.into()),
        ..SyncOpts::default()
    }
}

fn last_line(out: &str) -> &str {
    out.lines().last().unwrap_or_default()
}

// ---- P2 / NR-18: run summary ----------------------------------------------------------

#[test]
fn sync_summary_counts_every_outcome() {
    let (_, out) = sync_out(&fleet(), &new_secrets(), &SyncOpts::default());
    assert!(
        out.contains(
            "summary: written 2 · unchanged 0 · held 0 · deployed no · pending 2 · pruned 0 · kept 0 · skipped 1\n"
        ),
        "{out}"
    );
}

#[test]
fn sync_with_pending_names_the_deploy_command_last() {
    let (_, out) = sync_out(&fleet(), &new_secrets(), &SyncOpts::default());
    assert_eq!(last_line(&out), "Next: opv sync prod --deploy", "{out}");
}

#[test]
fn sync_with_nothing_pending_ends_with_the_summary() {
    let (_, out) = sync_out(&fleet(), &unchanged(), &deploy());
    assert!(last_line(&out).starts_with("summary: "), "{out}");
}

#[test]
fn deployed_sync_says_so_in_the_summary() {
    let (_, out) = sync_out(&fleet(), &new_secrets(), &deploy());
    assert!(out.contains("· deployed yes ·"), "{out}");
}

#[test]
fn kept_prune_candidates_name_the_prune_command() {
    let a = || fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2"), (STRIPE_FLY, "d3")]);
    let r = fly_run(complete_item(), a(), a());
    let (_, out) = sync_out(&fleet(), &r, &deploy());
    assert_eq!(
        last_line(&out),
        "Next: opv sync prod --deploy --prune",
        "{out}"
    );
}

// ---- P2: sync --json ------------------------------------------------------------------

fn json_doc(r: &FakeRunner) -> Value {
    let (_, out) = sync_out(&fleet(), r, &json());
    serde_json::from_str(&out).expect("one JSON document")
}

#[test]
fn sync_json_is_one_versioned_document() {
    assert_eq!(json_doc(&new_secrets())["schema_version"], 1);
}

#[test]
fn sync_json_names_written_keys_by_target_name() {
    assert_eq!(
        json_doc(&new_secrets())["written_names"],
        serde_json::json!([ENC_FLY, OPENAI_FLY])
    );
}

#[test]
fn sync_json_names_the_next_command() {
    assert_eq!(json_doc(&new_secrets())["next"], "opv sync prod --deploy");
}

#[test]
fn sync_json_names_the_provider() {
    assert_eq!(json_doc(&new_secrets())["provider"], "fly");
}

#[test]
fn sync_json_holds_no_value() {
    let (_, out) = sync_out(&fleet(), &new_secrets(), &json());
    assert_no_values(&out);
}

// ---- P10 / NR-20: confirm_env ---------------------------------------------------------

#[test]
fn confirm_env_requires_flag() {
    let r = FakeRunner::new([]);
    let (res, _) = sync_out(&guarded(), &r, &deploy());
    assert_eq!(res.unwrap_err().exit_code(), 6);
}

#[test]
fn confirm_env_refusal_names_the_exact_command() {
    let r = FakeRunner::new([]);
    let o = SyncOpts {
        prune: true,
        ..deploy()
    };
    let (res, _) = sync_out(&guarded(), &r, &o);
    assert_eq!(
        res.unwrap_err().next_step(),
        Some("opv sync prod --deploy --prune --confirm prod")
    );
}

#[test]
fn confirm_env_refuses_before_any_call() {
    let r = FakeRunner::new([]);
    let _ = sync_out(&guarded(), &r, &deploy());
    assert!(r.calls.borrow().is_empty());
}

#[test]
fn confirm_env_with_the_flag_syncs() {
    let o = SyncOpts {
        confirm: Some("prod".into()),
        ..SyncOpts::default()
    };
    let (res, _) = sync_out(&guarded(), &new_secrets(), &o);
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn confirm_naming_another_environment_is_refused() {
    let o = SyncOpts {
        confirm: Some("staging".into()),
        ..SyncOpts::default()
    };
    let (res, _) = sync_out(&fleet(), &FakeRunner::new([]), &o);
    assert!(matches!(res, Err(Error::Policy(m)) if m.contains("--confirm staging does not match")));
}

#[test]
fn guarded_sync_next_step_keeps_the_confirm_flag() {
    let o = SyncOpts {
        confirm: Some("prod".into()),
        ..SyncOpts::default()
    };
    let (_, out) = sync_out(&guarded(), &new_secrets(), &o);
    assert_eq!(
        last_line(&out),
        "Next: opv sync prod --deploy --confirm prod",
        "{out}"
    );
}

#[test]
fn confirm_env_must_be_a_boolean() {
    let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
    let bad = text.replace(
        "modes.allumata.payments = \"off\"",
        "modes.allumata.payments = \"off\"\nconfirm_env = \"yes\"",
    );
    assert!(matches!(config::parse(&bad), Err(Error::Config(_))));
}

// ---- NR-20: prune names before acting -------------------------------------------------

#[test]
fn prune_lists_names_before_acting() {
    let a = || fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2"), (STRIPE_FLY, "d3")]);
    let r = fly_run(complete_item(), a(), a());
    let o = SyncOpts {
        prune: true,
        ..SyncOpts::default()
    };
    let (_, out) = sync_out(&fleet(), &r, &o);
    let will = out.find("will prune: allumata/STRIPE_SECRET_KEY");
    let did = out.find("pruned: allumata/STRIPE_SECRET_KEY");
    assert!(will.is_some() && will < did, "{out}");
}

// ---- P19: product/KEY (NAME) ----------------------------------------------------------

#[test]
fn sync_names_keys_as_product_key_then_target_name() {
    let (_, out) = sync_out(&fleet(), &new_secrets(), &SyncOpts::default());
    assert!(
        out.contains(&format!(
            "written: allumata/INTEGRATION_ENC_KEY ({ENC_FLY}), "
        )),
        "{out}"
    );
}

// ---- P20: sync --product --------------------------------------------------------------

#[test]
fn sync_product_stages_only_that_products_names() {
    let r = fly_run(
        with_web_token(),
        fly_empty(),
        fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]),
    );
    sync_out(&two_products(), &r, &product("allumata"))
        .0
        .unwrap();
    assert!(!import_stdin(&r).unwrap().contains(WEB_TOKEN));
}

#[test]
fn sync_product_is_not_blocked_by_another_products_missing_key() {
    let r = new_secrets();
    let (res, _) = sync_out(&two_products(), &r, &product("allumata"));
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn sync_product_prunes_only_that_products_names() {
    let a = || {
        fly(&[
            (OPENAI_FLY, "d1"),
            (ENC_FLY, "d2"),
            (STRIPE_FLY, "d3"),
            (WEB_OLD, "d4"),
        ])
    };
    let r = fly_run(with_web_token(), a(), a());
    let o = SyncOpts {
        prune: true,
        ..product("allumata")
    };
    sync_out(&two_products(), &r, &o).0.unwrap();
    assert!(!r.argv_contains(WEB_OLD), "{:?}", argvs(&r));
}

#[test]
fn sync_product_names_other_products_pending_changes() {
    let a = || {
        fly_st(&[
            (OPENAI_FLY, "d1", "Deployed"),
            (ENC_FLY, "d2", "Deployed"),
            (WEB_TOKEN, "d5", "Staged"),
        ])
    };
    let r = fly_run(with_web_token(), a(), a());
    let (_, out) = sync_out(&two_products(), &r, &product("allumata"));
    assert!(
        out.contains(&format!(
            "pending for other products: web/TOKEN ({WEB_TOKEN}); a deploy restarts the app \
             with them too"
        )),
        "{out}"
    );
}

#[test]
fn sync_product_next_step_keeps_the_product() {
    let (_, out) = sync_out(&two_products(), &new_secrets(), &product("allumata"));
    assert_eq!(
        last_line(&out),
        "Next: opv sync prod --deploy --product allumata",
        "{out}"
    );
}

#[test]
fn sync_product_under_the_simple_profile_is_a_config_error() {
    let simple = config::load("tests/fixtures/simple.toml").unwrap();
    let mut out = Vec::new();
    let res = sync::run(
        &simple,
        "prod",
        &FakeRunner::new([]),
        &mut out,
        &product("x"),
    );
    assert!(matches!(res, Err(Error::Config(m)) if m.contains("simple profile")));
}

#[test]
fn undefined_product_is_a_config_error_naming_the_choices() {
    let (res, _) = sync_out(&fleet(), &FakeRunner::new([]), &product("nope"));
    assert!(matches!(res, Err(Error::Config(m)) if m.contains("choose one of: allumata")));
}

// ---- P11: plan names what it would do ---------------------------------------------------

fn plan_out(fleet: &Fleet, r: &FakeRunner, product: Option<&str>) -> (Result<(), Error>, String) {
    let mut out = Vec::new();
    let res = sync::plan_scoped(fleet, "prod", product, r, &mut out, false);
    (res, text_of(&out))
}

fn prunable() -> Output {
    fly(&[(OPENAI_FLY, "d1"), (STRIPE_FLY, "d3")])
}

#[test]
fn plan_starts_with_a_count_summary() {
    let (_, out) = plan_out(
        &fleet(),
        &FakeRunner::new([complete_item(), fly_empty()]),
        None,
    );
    assert_eq!(
        out.lines().next().unwrap(),
        "prod: 4 keys · 0 findings · 2 to stage · 0 held (immutable) · 0 to prune · 0 \
         unmanaged on Fly (never touched)",
        "{out}"
    );
}

#[test]
fn plan_names_what_it_would_stage() {
    let (_, out) = plan_out(
        &fleet(),
        &FakeRunner::new([complete_item(), fly_empty()]),
        None,
    );
    assert!(
        out.contains(&format!(
            "would stage: allumata/INTEGRATION_ENC_KEY ({ENC_FLY}), allumata/OPENAI_API_KEY \
             ({OPENAI_FLY})\n"
        )),
        "{out}"
    );
}

#[test]
fn plan_names_what_it_would_prune() {
    let (_, out) = plan_out(
        &fleet(),
        &FakeRunner::new([complete_item(), prunable()]),
        None,
    );
    assert!(
        out.contains(&format!(
            "would prune (needs --prune): allumata/STRIPE_SECRET_KEY ({STRIPE_FLY})"
        )),
        "{out}"
    );
}

#[test]
fn plan_ends_with_the_sync_command() {
    let (_, out) = plan_out(
        &fleet(),
        &FakeRunner::new([complete_item(), fly_empty()]),
        None,
    );
    assert_eq!(last_line(&out), "Next: opv sync prod --deploy", "{out}");
}

#[test]
fn plan_with_prune_names_suggests_the_prune_flag() {
    let (_, out) = plan_out(
        &fleet(),
        &FakeRunner::new([complete_item(), prunable()]),
        None,
    );
    assert_eq!(
        last_line(&out),
        "Next: opv sync prod --deploy --prune",
        "{out}"
    );
}

#[test]
fn plan_for_a_guarded_environment_suggests_confirm() {
    let (_, out) = plan_out(
        &guarded(),
        &FakeRunner::new([complete_item(), fly_empty()]),
        None,
    );
    assert_eq!(
        last_line(&out),
        "Next: opv sync prod --deploy --confirm prod",
        "{out}"
    );
}

#[test]
fn plan_findings_next_step_is_plan_again() {
    let r = FakeRunner::new([item_without("allumata", "OPENAI_API_KEY"), fly_empty()]);
    let (res, _) = plan_out(&fleet(), &r, None);
    assert_eq!(
        res.unwrap_err().next_step(),
        Some("fix the keys above in 1Password, then run opv plan prod")
    );
}

// ---- P12 / NR-16: --product on status and plan --------------------------------------

#[test]
fn plan_product_limits_what_it_would_stage() {
    let r = FakeRunner::new([with_web_token(), fly_empty()]);
    let (_, out) = plan_out(&two_products(), &r, Some("web"));
    assert!(
        out.contains(&format!("would stage: web/TOKEN ({WEB_TOKEN})\n")),
        "{out}"
    );
}

fn status_out(fleet: &Fleet, r: &FakeRunner, product: Option<&str>) -> (Result<(), Error>, String) {
    let mut out = Vec::new();
    let res = status::run_scoped(fleet, "prod", product, r, &mut out, false);
    (res, text_of(&out))
}

#[test]
fn status_product_shows_only_its_rows() {
    let r = FakeRunner::new([with_web_token(), fly_empty()]);
    let (_, out) = status_out(&two_products(), &r, Some("web"));
    assert!(!out.contains("allumata"), "{out}");
}

#[test]
fn status_product_ignores_another_products_findings() {
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    let (res, _) = status_out(&two_products(), &r, Some("allumata"));
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn status_product_counts_only_its_findings() {
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    let (res, _) = status_out(&two_products(), &r, Some("web"));
    assert!(matches!(res, Err(Error::Findings(1, _))), "{res:?}");
}

#[test]
fn status_json_names_its_product() {
    let r = FakeRunner::new([with_web_token(), fly_empty()]);
    let mut out = Vec::new();
    status::run_scoped(&two_products(), "prod", Some("web"), &r, &mut out, true).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["product"], "web");
}

#[test]
fn status_product_under_the_simple_profile_is_a_config_error() {
    let simple = config::load("tests/fixtures/simple.toml").unwrap();
    let (res, _) = status_out(&simple, &FakeRunner::new([]), Some("x"));
    assert!(matches!(res, Err(Error::Config(_))), "{res:?}");
}

// ---- P22: status without an environment ---------------------------------------------

/// Staging's and prod's items and lists, in environment name order (prod first).
fn overview_out(fleet: &Fleet, r: &FakeRunner) -> (Result<(), Error>, String) {
    let mut out = Vec::new();
    let res = status::overview(fleet, r, &mut out);
    (res, text_of(&out))
}

fn staging_item() -> Output {
    item(&[
        secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
        text("allumata", "SIGNUP_POLICY", POLICY),
    ])
}

#[test]
fn status_without_env_prints_one_line_per_environment() {
    let r = FakeRunner::new([complete_item(), fly_empty(), staging_item(), fly_empty()]);
    let (_, out) = overview_out(&fleet(), &r);
    assert_eq!(
        out,
        "prod: 4 keys · 3 saved · 1 skipped · 0 findings · 2 not yet on Fly\n\
         staging: 3 keys · 2 saved · 0 skipped · 1 finding · 1 not yet on Fly\n",
    );
}

#[test]
fn status_without_env_marks_an_environment_without_target_run_only() {
    let f = fleet_with("[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n");
    let r = FakeRunner::new([complete_item(), fly_empty(), staging_item(), fly_empty()]);
    let (_, out) = overview_out(&f, &r);
    assert!(out.starts_with("dev: run-only (no target)\n"), "{out}");
}

#[test]
fn status_without_env_exits_8_when_any_environment_has_findings() {
    let r = FakeRunner::new([complete_item(), fly_empty(), staging_item(), fly_empty()]);
    let (res, _) = overview_out(&fleet(), &r);
    assert_eq!(res.unwrap_err().next_step(), Some("opv status staging"));
}

#[test]
fn status_without_env_reports_an_unreadable_environment_and_goes_on() {
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    r.push_unknowns("timeout", crate::runner::READ_ATTEMPTS);
    let (_, out) = overview_out(&fleet(), &r);
    assert!(
        out.lines()
            .nth(1)
            .unwrap()
            .starts_with("staging: not checked ("),
        "{out}"
    );
}

// ---- P4: provider-neutral wording ---------------------------------------------------

#[test]
fn drift_line_names_no_provider_store() {
    assert!(!drift_line("prod", "API_KEY").contains("Key Vault"));
}

#[test]
fn status_json_rows_carry_target_name() {
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    let mut out = Vec::new();
    status::run_with(&fleet(), "prod", &r, &mut out, true).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["rows"][1]["target_name"], OPENAI_FLY);
}

// ---- P1: check guidance is not a next step -------------------------------------------

#[test]
fn check_labels_guidance_as_guidance() {
    let r = FakeRunner::new([item_without("allumata", "OPENAI_API_KEY")]);
    let mut out = Vec::new();
    let _ = super::local::check(&fleet(), "prod", Some("allumata"), &r, &mut out, false);
    assert!(
        text_of(&out).contains("\n  guidance: OpenAI platform / API keys\n"),
        "{}",
        text_of(&out)
    );
}

#[test]
fn check_findings_next_step_is_check_again() {
    let r = FakeRunner::new([item_without("allumata", "OPENAI_API_KEY")]);
    let res = super::local::check(
        &fleet(),
        "prod",
        Some("allumata"),
        &r,
        &mut Vec::new(),
        false,
    );
    assert_eq!(
        res.unwrap_err().next_step(),
        Some("fix the keys above in 1Password, then run opv check prod --product allumata")
    );
}
