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
///
/// The old environment item held both products, so it stays one opt-in boundary group.
fn two_products() -> Fleet {
    let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
    let text = text
        .replace("boundaries.allumata =", "boundaries.core =")
        .replace(
            "[products.allumata.keys.OPENAI_API_KEY]",
            "[products.allumata]\nboundary = \"core\"\n\n[products.allumata.keys.OPENAI_API_KEY]",
        );
    config::parse(&format!(
        "{text}\n[products.web]\nboundary = \"core\"\n\n\
         [products.web.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
         [products.web.keys.OLD]\nkind = \"secret\"\nenvironments = [\"staging\"]\n",
    ))
    .unwrap()
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
    assert!(
        last_line(&out).starts_with("prod/portfolio: summary: "),
        "{out}"
    );
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
    assert_eq!(json_doc(&new_secrets())["targets"][0]["provider"], "fly");
}

#[test]
fn sync_json_holds_no_value() {
    let (_, out) = sync_out(&fleet(), &new_secrets(), &json());
    assert_no_values(&out);
}

// ---- P10 / NR-20: confirm_env ---------------------------------------------------------

#[test]
fn confirm_env_requires_flag() {
    let (res, _) = sync_out(&guarded(), &new_secrets(), &deploy());
    assert_eq!(res.unwrap_err().exit_code(), 6);
}

/// The step is a handoff built from the command as typed, every flag kept (R61); a unit
/// test names the invocation the CLI would have parsed.
#[test]
fn confirm_env_refusal_names_the_exact_command() {
    let o = SyncOpts {
        prune: true,
        ..deploy()
    };
    let (res, _) = sync_out(&guarded(), &new_secrets(), &o);
    assert_eq!(
        catalog_next(&res.unwrap_err(), "opv sync prod --deploy --prune"),
        Some("opv sync prod --deploy --prune --confirm prod".into())
    );
}

/// H12: the guard gates the first write; the read-only checks run before it.
#[test]
fn confirm_env_refuses_before_any_write() {
    let r = new_secrets();
    let _ = sync_out(&guarded(), &r, &deploy());
    assert!(!called(&r, "flyctl", &["secrets", "import"]));
}

/// H12: blocking keys and the missing --confirm are reported by one run.
#[test]
fn guarded_refusal_names_blocking_keys_and_the_confirm_flag() {
    let r = FakeRunner::new([item_without("allumata", "OPENAI_API_KEY"), fly_empty()]);
    let (res, _) = sync_out(&guarded(), &r, &deploy());
    assert!(
        matches!(&res, Err(Error::Policy(m))
            if m.contains("allumata/OPENAI_API_KEY") && m.contains("needs a person's confirmation")),
        "{res:?}"
    );
}

/// H12: a --confirm naming another environment is still refused before any call.
#[test]
fn confirm_mismatch_refuses_before_any_call() {
    let r = FakeRunner::new([]);
    let o = SyncOpts {
        confirm: Some("staging".into()),
        ..deploy()
    };
    let _ = sync_out(&guarded(), &r, &o);
    assert!(r.calls.borrow().is_empty());
}

// ---- H10: usage errors name a runnable, read-only next step -------------------------

#[test]
fn unknown_environment_next_is_status_of_the_closest() {
    let e = fleet().environment("prd").unwrap_err();
    assert_eq!(e.next_step(), Some("opv status prod"));
}

#[test]
fn unknown_environment_without_a_close_name_next_is_the_overview() {
    let e = fleet().environment("nothing-like-it").unwrap_err();
    assert_eq!(e.next_step(), Some("opv status"));
}

#[test]
fn unknown_product_next_checks_the_closest_product() {
    let e = super::local::select(&two_products(), "prod", Some("wb"), true).unwrap_err();
    assert_eq!(e.next_step(), Some("opv check prod --product web"));
}

/// A fleet configuration with one product needs no `--product` (found live: `check`
/// asked to choose from one).
#[test]
fn a_single_product_is_selected_without_the_flag() {
    assert!(super::local::select(&fleet(), "prod", None, true).is_ok());
}

#[test]
fn missing_product_next_checks_the_first_product() {
    let e = super::local::select(&two_products(), "prod", None, true).unwrap_err();
    assert_eq!(e.next_step(), Some("opv check prod --product allumata"));
}

/// R21: the unique close key is substituted, and the write turned into its read.
#[test]
fn undeclared_rotate_next_plans_the_closest_key() {
    let o = SyncOpts {
        rotate: vec!["allumata/INTEGRATION_ENC".into()],
        ..SyncOpts::default()
    };
    let (res, _) = sync_out(&fleet(), &FakeRunner::new([]), &o);
    assert_eq!(
        catalog_next(
            &res.unwrap_err(),
            "opv sync prod --rotate allumata/INTEGRATION_ENC"
        ),
        Some("opv plan prod --rotate allumata/INTEGRATION_ENC_KEY".into())
    );
}

#[test]
fn prune_immutable_without_prune_next_is_the_help() {
    let o = SyncOpts {
        prune_immutable: vec!["allumata/INTEGRATION_ENC_KEY".into()],
        ..SyncOpts::default()
    };
    let (res, _) = sync_out(&fleet(), &FakeRunner::new([]), &o);
    assert_eq!(
        catalog_next(
            &res.unwrap_err(),
            "opv sync prod --prune-immutable allumata/INTEGRATION_ENC_KEY"
        ),
        Some("opv sync --help".into())
    );
}

#[test]
fn explain_of_an_unknown_key_next_carries_the_env() {
    let e = crate::app::testutil::explain(
        &fleet(),
        "allumata/OPENAI_KEY",
        None,
        &mut Vec::new(),
        false,
    )
    .unwrap_err();
    assert_eq!(
        e.next_step(),
        Some("opv explain allumata/OPENAI_API_KEY --env prod")
    );
}

#[test]
fn explain_with_several_environments_next_names_one() {
    let e = crate::app::testutil::explain(
        &fleet(),
        "allumata/SIGNUP_POLICY",
        None,
        &mut Vec::new(),
        false,
    )
    .unwrap_err();
    assert_eq!(
        e.next_step(),
        Some("opv explain allumata/SIGNUP_POLICY --env staging")
    );
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
    assert_eq!(res.unwrap_err().code_str(), "confirm_mismatch");
}

/// 01.12: a mismatched --confirm steps to the read of the environment, never to a sync
/// confirmed for the person.
#[test]
fn confirm_mismatch_next_is_the_plan_not_a_confirmed_sync() {
    let o = SyncOpts {
        confirm: Some("staging".into()),
        deploy: true,
        ..SyncOpts::default()
    };
    let (res, _) = sync_out(&fleet(), &FakeRunner::new([]), &o);
    assert_eq!(
        catalog_next(
            &res.unwrap_err(),
            "opv sync prod --deploy --confirm staging"
        ),
        Some("opv plan prod".into())
    );
}

/// X4: opv never adds --confirm to a step it generates; the guard asks the person again.
#[test]
fn guarded_sync_next_step_never_adds_the_confirm_flag() {
    let o = SyncOpts {
        confirm: Some("prod".into()),
        ..SyncOpts::default()
    };
    let (_, out) = sync_out(&guarded(), &new_secrets(), &o);
    assert_eq!(last_line(&out), "Next: opv sync prod --deploy", "{out}");
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
fn undefined_product_is_an_error_naming_the_choices() {
    let (res, _) = sync_out(&fleet(), &FakeRunner::new([]), &product("nope"));
    assert!(res.is_err_and(|e| e.to_string().contains("(declared: allumata)")));
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
        "prod/portfolio: 4 keys · 0 findings · 2 to stage · 0 held (immutable) · 0 to \
         prune · 0 unmanaged on Fly (never touched)",
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
fn plan_with_prune_names_suggests_the_prune_flag() {
    let (_, out) = plan_out(
        &fleet(),
        &FakeRunner::new([complete_item(), prunable()]),
        None,
    );
    assert!(
        last_line(&out).starts_with("Next: opv sync prod --deploy --prune --expect-plan "),
        "{out}"
    );
}

/// `--expect-plan` stands for a guarded environment's `--confirm` (A7).
#[test]
fn plan_for_a_guarded_environment_needs_no_confirm_with_its_plan_id() {
    let id = fly_plan_id(&guarded());
    let (_, out) = plan_out(
        &guarded(),
        &FakeRunner::new([complete_item(), fly_empty()]),
        None,
    );
    assert_eq!(
        last_line(&out),
        format!("Next: opv sync prod --deploy --expect-plan {id}"),
        "{out}"
    );
}

#[test]
fn plan_findings_next_step_opens_the_first_key() {
    let r = FakeRunner::new([item_without("allumata", "OPENAI_API_KEY"), fly_empty()]);
    let (res, _) = plan_out(&fleet(), &r, None);
    assert_eq!(
        res.unwrap_err().next_step(),
        Some("opv open allumata/OPENAI_API_KEY --env prod")
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

// ---- P22: status without an environment ---------------------------------------------

/// Staging's and prod's items and lists, in environment name order (prod first).
fn overview_out(fleet: &Fleet, r: &FakeRunner) -> (Result<(), Error>, String) {
    let mut out = Vec::new();
    let res = status::overview(fleet, None, r, &mut out, false);
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
        "prod/portfolio: 4 keys · 3 saved · 1 skipped · 0 findings · 2 not yet on Fly\n\
         staging/portfolio: 3 keys · 2 saved · 0 skipped · 1 finding · 1 not yet on Fly\n",
    );
}

#[test]
fn status_without_env_reads_a_run_only_environment() {
    let f = fleet_with(
        "[environments.dev]\nboundaries.allumata = { vault_id = \"vdev\", item_id = \"idev\" }\n\
         [products.allumata.keys.DEV_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
    );
    let r = FakeRunner::new([
        item_without("allumata", "OPENAI_API_KEY"),
        complete_item(),
        fly_empty(),
        staging_item(),
        fly_empty(),
    ]);
    let (_, out) = overview_out(&f, &r);
    assert!(out.starts_with("dev: run-only · "), "{out}");
}

/// H11 (bug 8): a broken run-only environment is a finding, not a green overview.
#[test]
fn status_without_env_counts_run_only_findings() {
    let f = fleet_with(
        "[environments.dev]\nboundaries.allumata = { vault_id = \"vdev\", item_id = \"idev\" }\n\
         [products.allumata.keys.DEV_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
    );
    let r = FakeRunner::new([
        item_without("allumata", "OPENAI_API_KEY"),
        complete_item(),
        fly_empty(),
        complete_item(),
        fly_empty(),
    ]);
    let (res, _) = overview_out(&f, &r);
    assert_eq!(
        values_needed_env(&res.unwrap_err()),
        Some("dev".to_string())
    );
}

/// The environment a `ValuesNeeded` failure is about (the overview's findings, 01.08).
fn values_needed_env(e: &Error) -> Option<String> {
    match e.cause() {
        Some((crate::cause::Cause::ValuesNeeded { env, .. }, _)) => Some(env.to_string()),
        _ => None,
    }
}

/// 01.08: the overview's step opens a key that has a finding, never one of the first
/// declared product (`zz` sorts after `allumata`, whose keys dev does not use).
#[test]
fn status_without_env_opens_the_key_with_the_finding() {
    let f = fleet_with(
        "[environments.dev]\nboundaries.allumata = { vault_id = \"vdev\", item_id = \"idev\" }\n\
         [products.zz]\nboundary = \"allumata\"\n\
         [products.zz.keys.DEV_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
    );
    let r = FakeRunner::new([
        complete_item(),
        complete_item(),
        fly_empty(),
        complete_item(),
        fly_empty(),
    ]);
    let (res, _) = overview_out(&f, &r);
    let inv = crate::cause::Invocation::from_cli(&["opv".to_string(), "status".to_string()]);
    let e = res.unwrap_err();
    let (cause, _) = e.cause().expect("a catalog cause");
    assert_eq!(
        cause.step(&inv).1,
        crate::cause::Next::Run(crate::cause::Cmd {
            command: vec!["open".into()],
            args: vec!["zz/DEV_KEY".into(), "--env".into(), "dev".into()],
        })
    );
}

#[test]
fn status_without_env_scopes_to_a_product() {
    let r = FakeRunner::new([with_web_token(), fly_empty(), with_web_token(), fly_empty()]);
    let mut out = Vec::new();
    let _ = status::overview(&two_products(), Some("web"), &r, &mut out, false);
    assert!(
        text_of(&out).starts_with("prod/portfolio: 1 key · "),
        "{}",
        text_of(&out)
    );
}

#[test]
fn status_without_env_json_lists_every_environment() {
    let f = fleet_with(
        "[environments.dev]\nboundaries.allumata = { vault_id = \"vdev\", item_id = \"idev\" }\n\
         [products.allumata.keys.DEV_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
    );
    let r = FakeRunner::new([
        complete_item(),
        complete_item(),
        fly_empty(),
        complete_item(),
        fly_empty(),
    ]);
    let mut out = Vec::new();
    let _ = status::overview(&f, None, &r, &mut out, true);
    let doc: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["environments"][0]["target"], Value::Null);
}

#[test]
fn status_without_env_exits_8_when_any_environment_has_findings() {
    let r = FakeRunner::new([complete_item(), fly_empty(), staging_item(), fly_empty()]);
    let (res, _) = overview_out(&fleet(), &r);
    assert_eq!(
        values_needed_env(&res.unwrap_err()),
        Some("staging".to_string())
    );
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
fn check_findings_next_step_opens_the_first_key() {
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
        Some("opv open allumata/OPENAI_API_KEY --env prod")
    );
}

// ---- A7 / FR-41: plan ids and --expect-plan (Fly) ---------------------------------------

/// The plan id `opv plan prod --json` reports for the item and an empty Fly app.
fn fly_plan_id(fleet: &Fleet) -> String {
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    let mut out = Vec::new();
    sync::plan_with(fleet, "prod", &r, &mut out, true).unwrap();
    let doc: Value = serde_json::from_slice(&out).unwrap();
    doc["plan_id"].as_str().unwrap().to_string()
}

fn expect(id: &str) -> SyncOpts {
    SyncOpts {
        expect_plan: Some(id.into()),
        receipt: None,
        ..SyncOpts::default()
    }
}

fn imported(r: &FakeRunner) -> bool {
    r.calls
        .borrow()
        .iter()
        .any(|c| c.args.starts_with(&["secrets".into(), "import".into()]))
}

#[test]
fn plan_names_its_plan_id_and_the_flag_that_applies_it() {
    let id = fly_plan_id(&fleet());
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    let (_, out) = plan_out(&fleet(), &r, None);
    assert!(
        out.lines()
            .any(|l| l.starts_with(&format!("plan {id} (1Password item v"))
                && l.contains(&format!("--expect-plan {id}"))),
        "{out}"
    );
}

/// M13: a clean plan ends with the command that applies exactly that plan.
#[test]
fn plan_next_applies_its_plan_id() {
    let id = fly_plan_id(&fleet());
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    let (_, out) = plan_out(&fleet(), &r, None);
    assert_eq!(
        out.lines().last(),
        Some(format!("Next: opv sync prod --deploy --expect-plan {id}").as_str()),
        "{out}"
    );
}

#[test]
fn fly_plan_id_is_stable_across_runs() {
    assert_eq!(fly_plan_id(&fleet()), fly_plan_id(&fleet()));
}

// ---- A7 / FR-16: --rotate plans and applies a replacement ------------------------------

const ENC: &str = "allumata/INTEGRATION_ENC_KEY";

/// The key values of an item already matching its target; ENC is held unless rotated.
fn present() -> Output {
    fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")])
}

/// The plan of `rotate` against an item whose keys are all present and unchanged.
fn plan_rotate_out(rotate: &[&str], json: bool) -> (Result<(), Error>, String) {
    let rotate: Vec<String> = rotate.iter().map(|s| s.to_string()).collect();
    let r = FakeRunner::new([complete_item(), present()]);
    let mut out = Vec::new();
    let res = sync::plan_rotating(&fleet(), "prod", &[], None, &rotate, &r, &mut out, json);
    (res, text_of(&out))
}

fn rotate_plan_id(rotate: &[&str]) -> String {
    let (_, out) = plan_rotate_out(rotate, true);
    serde_json::from_str::<Value>(&out).unwrap()["plan_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn enc_row(out: &str) -> Value {
    let doc: Value = serde_json::from_str(out).unwrap();
    doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == "INTEGRATION_ENC_KEY")
        .cloned()
        .unwrap()
}

#[test]
fn plan_rotate_marks_the_rotated_row_in_json() {
    let (_, out) = plan_rotate_out(&[ENC], true);
    assert_eq!(enc_row(&out)["rotate"], Value::Bool(true), "{out}");
}

#[test]
fn plan_rotate_stages_a_held_immutable_key() {
    let (_, out) = plan_rotate_out(&[ENC], true);
    assert_eq!(
        enc_row(&out)["action"],
        Value::String("would_stage".into()),
        "{out}"
    );
}

#[test]
fn plan_rotate_changes_the_plan_id() {
    assert_ne!(rotate_plan_id(&[]), rotate_plan_id(&[ENC]));
}

#[test]
fn plan_rotate_marks_the_row_on_target_as_rotate() {
    let (_, out) = plan_rotate_out(&[ENC], false);
    assert!(
        out.lines()
            .any(|l| l.contains("INTEGRATION_ENC_KEY") && l.ends_with("rotate")),
        "{out}"
    );
}

#[test]
fn plan_rotate_refuses_a_non_immutable_key() {
    let (res, _) = plan_rotate_out(&["allumata/OPENAI_API_KEY"], false);
    assert!(matches!(res, Err(Error::Config(_))));
}

#[test]
fn sync_with_rotate_and_its_plan_id_writes_the_rotated_key() {
    let id = rotate_plan_id(&[ENC]);
    let r = fly_run(complete_item(), present(), present());
    let o = SyncOpts {
        rotate: vec![ENC.into()],
        ..expect(&id)
    };
    let (res, _) = sync_out(&fleet(), &r, &o);
    assert!(
        res.is_ok() && import_stdin(&r).unwrap_or_default().contains(ENC_FLY),
        "{res:?}"
    );
}

#[test]
fn sync_with_rotate_and_a_plain_plan_id_is_stale() {
    let id = rotate_plan_id(&[]);
    let r = fly_run(complete_item(), present(), present());
    let o = SyncOpts {
        rotate: vec![ENC.into()],
        ..expect(&id)
    };
    let (res, _) = sync_out(&fleet(), &r, &o);
    assert_eq!(res.unwrap_err().code(), crate::error::Code::StalePlan);
}

#[test]
fn sync_with_the_reviewed_fly_plan_id_stages() {
    let r = new_secrets();
    let _ = sync_out(&fleet(), &r, &expect(&fly_plan_id(&fleet())));
    assert!(imported(&r), "{:?}", r.calls.borrow());
}

#[test]
fn sync_with_a_stale_fly_plan_id_stages_nothing() {
    let r = new_secrets();
    let _ = sync_out(&fleet(), &r, &expect("00000000"));
    assert!(!imported(&r));
}

#[test]
fn stale_plan_refusal_next_step_is_the_review() {
    let (res, _) = sync_out(&fleet(), &new_secrets(), &expect("00000000"));
    assert_eq!(
        catalog_next(
            &res.unwrap_err(),
            "opv sync prod --deploy --expect-plan 00000000"
        ),
        Some("opv plan prod".into())
    );
}

/// The item and the Fly listing after a run staged both secrets but never deployed them.
fn staged_not_deployed() -> FakeRunner {
    let staged = || fly_st(&[(OPENAI_FLY, "d1", "Staged"), (ENC_FLY, "d2", "Staged")]);
    let [st, rel] = fly_preflight_ok();
    FakeRunner::new([
        complete_item(),
        staged(),
        st,
        rel,
        ok(),
        staged(),
        ok(),
        ok(),
        ok(),
    ])
}

/// I2: exit 9 is safe to re-run as is. The first run staged the values and its deploy was
/// interrupted; the same `--expect-plan` id still matches and the re-run deploys.
#[test]
fn expect_plan_rerun_after_an_interrupted_deploy_succeeds() {
    let id = fly_plan_id(&fleet());
    let first = new_secrets();
    // Item, list A, two preflight reads, import, list B, then the receipt's `op whoami`
    // (it names no account here, so no receipt is minted); the deploy is cut off.
    first.responses.borrow_mut().truncate(7);
    first.push_unknown("timeout");
    let o = SyncOpts {
        deploy: true,
        ..expect(&id)
    };
    let interrupted = sync_out(&fleet(), &first, &o).0.unwrap_err().exit_code();
    let (res, out) = sync_out(&fleet(), &staged_not_deployed(), &o);
    assert!(
        interrupted == 9 && res.is_ok(),
        "{interrupted} {res:?}\n{out}"
    );
}

#[test]
fn expect_plan_satisfies_confirm_env() {
    let (res, _) = sync_out(
        &guarded(),
        &new_secrets(),
        &expect(&fly_plan_id(&guarded())),
    );
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn expect_plan_with_prune_immutable_is_refused_before_any_call() {
    let r = FakeRunner::new([]);
    let o = SyncOpts {
        prune_immutable: vec!["allumata/INTEGRATION_ENC_KEY".into()],
        ..expect("00000000")
    };
    let (res, _) = sync_out(&fleet(), &r, &o);
    assert!(res.is_err_and(|e| e.exit_code() == 2) && r.calls.borrow().is_empty());
}

/// 01.11: the refusal never hands back the destructive sync, let alone a confirmed one.
#[test]
fn expect_plan_with_prune_immutable_next_is_not_the_sync() {
    let o = SyncOpts {
        prune: true,
        prune_immutable: vec!["allumata/INTEGRATION_ENC_KEY".into()],
        ..expect("00000000")
    };
    let (res, _) = sync_out(&guarded(), &FakeRunner::new([]), &o);
    let typed = "opv sync prod --prune --prune-immutable allumata/INTEGRATION_ENC_KEY \
                 --expect-plan 00000000";
    assert_eq!(
        catalog_next(&res.unwrap_err(), typed),
        Some("opv sync --help".into())
    );
}

// ---- I4: an undeclared --product keeps the command and the environment ---------------

#[test]
fn status_with_an_undeclared_product_suggests_status_of_the_same_env() {
    let r = FakeRunner::new([]);
    let e = status::run_scoped(
        &fleet(),
        "prod",
        Some("allumatta"),
        &r,
        &mut Vec::new(),
        false,
    )
    .unwrap_err();
    assert_eq!(e.next_step(), Some("opv status prod --product allumata"));
}

#[test]
fn sync_with_an_undeclared_product_suggests_its_plan() {
    let (res, _) = sync_out(&fleet(), &FakeRunner::new([]), &product("allumatta"));
    assert_eq!(
        catalog_next(
            &res.unwrap_err(),
            "opv sync prod --deploy --product allumatta"
        ),
        Some("opv plan prod --product allumata".into())
    );
}

/// M4: `check` counts its findings once, on the error line (`opv: 1 finding`).
#[test]
fn check_with_findings_does_not_count_them_on_stdout() {
    let r = FakeRunner::new([item_without("allumata", "OPENAI_API_KEY")]);
    let mut out = Vec::new();
    let _ = super::local::check(&fleet(), "prod", Some("allumata"), &r, &mut out, false);
    assert!(!text_of(&out).contains("finding"), "{}", text_of(&out));
}

/// The Next a cataloged error renders for the command line `line` (a unit test has no CLI
/// invocation of its own).
fn catalog_next(e: &Error, line: &str) -> Option<String> {
    let (cause, _) = e.cause()?;
    let argv: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    let inv = crate::cause::Invocation::from_cli(&argv);
    crate::cause::render::next_text(&cause.step(&inv).1, &inv)
}
