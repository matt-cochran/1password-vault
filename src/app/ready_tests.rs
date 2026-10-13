//! FR-51 readiness receipt: one behavioural outcome per test. No `op` call and no target
//! call: the account report and the rows are built directly.

use super::*;
use crate::adapters::onepassword_manifest::{Account, Discovery};
use crate::app::account;
use crate::domain::rules::Reason;
use crate::domain::{Kind, SIMPLE_PRODUCT};
use crate::error::Code;
use crate::host::Platform;

fn account(id: &str, email: &str, address: &str, shorthand: &str, user: &str) -> Account {
    Account {
        account_uuid: id.into(),
        url: format!("https://{address}/"),
        email: email.into(),
        user_uuid: user.into(),
        shorthand: shorthand.into(),
    }
}

fn owner() -> Account {
    account(
        "AAAA0000000000000000000001",
        "owner@example.com",
        "my-team.1password.com",
        "my-team",
        "USER0000000000000000000001",
    )
}

/// A realistic FR-49 report: one listed account, selected as `only` and signed in.
fn account_report() -> account::Report {
    let signed_in = |_: &str| Some(true);
    account::report(&account::Inputs {
        discovery: Discovery::Listed(vec![owner()]),
        signed_in: &signed_in,
        flag: None,
        env: None,
        pointer: None,
        manifest: None,
        platform: Platform::Linux,
    })
}

fn row(product: &str, key: &str, state: KeyState, target: TargetState) -> Row {
    Row {
        product: product.into(),
        key: key.into(),
        kind: Kind::Secret,
        state,
        target,
        guidance: String::new(),
        source: None,
        shared_by: Vec::new(),
    }
}

fn env(name: &str, target: Option<&str>, rows: Vec<Row>) -> EnvInput {
    EnvInput {
        name: name.into(),
        target: target.map(str::to_string),
        rows: Ok(rows),
    }
}

fn inputs<'a>(report: &'a account::Report, envs: Vec<EnvInput>) -> Inputs<'a> {
    Inputs {
        config_source: Some("secrets.toml".into()),
        account: report,
        envs,
        simple: false,
    }
}

/// An FR-49 report whose one account is selected (`only`) but signed out.
fn signed_out_report() -> account::Report {
    let signed_in = |_: &str| Some(false);
    account::report(&account::Inputs {
        discovery: Discovery::Listed(vec![owner()]),
        signed_in: &signed_in,
        flag: None,
        env: None,
        pointer: None,
        manifest: None,
        platform: Platform::Linux,
    })
}

/// An FR-49 report whose discovery failed: `discovery_unavailable`, no selected account.
fn unavailable_report() -> account::Report {
    let signed_in = |_: &str| None;
    account::report(&account::Inputs {
        discovery: Discovery::Unavailable,
        signed_in: &signed_in,
        flag: None,
        env: None,
        pointer: None,
        manifest: None,
        platform: Platform::Linux,
    })
}

fn env_err(name: &str, target: Option<&str>, error: Error) -> EnvInput {
    EnvInput {
        name: name.into(),
        target: target.map(str::to_string),
        rows: Err(error),
    }
}

fn text(r: &Receipt) -> String {
    let mut out = Vec::new();
    render_text(r, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn matrix_counts_keys_saved_and_findings_per_product() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![
            row("api", "A", KeyState::Ready, TargetState::Present),
            row("api", "B", KeyState::Missing, TargetState::Absent),
            row("api", "C", KeyState::WrongKind, TargetState::Absent),
        ],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    let m = &r.matrix[0];
    assert_eq!((m.keys, m.saved, m.findings), (3, 1, 2));
}

#[test]
fn matrix_groups_products_in_first_appearance_order() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![
            row("api", "A", KeyState::Ready, TargetState::Present),
            row("worker", "W", KeyState::Ready, TargetState::Present),
            row("api", "B", KeyState::Ready, TargetState::Present),
        ],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    let products: Vec<&str> = r.matrix.iter().map(|m| m.product.as_str()).collect();
    assert_eq!(products, ["api", "worker"]);
}

#[test]
fn matrix_marks_undelivered_product_as_not_delivered() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row("api", "A", KeyState::Ready, TargetState::NotDelivered)],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert!(!r.matrix[0].delivered);
}

#[test]
fn matrix_marks_run_only_environment_delivered() {
    let report = account_report();
    let envs = vec![env(
        "local",
        None,
        vec![row("api", "A", KeyState::Ready, TargetState::NotDelivered)],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert!(r.matrix[0].delivered);
}

#[test]
fn matrix_has_no_entry_for_an_errored_environment() {
    let report = account_report();
    let envs = vec![
        env(
            "staging",
            Some("Fly"),
            vec![row("api", "A", KeyState::Ready, TargetState::Present)],
        ),
        env_err("prod", Some("Fly"), Error::Source("unreadable".into())),
    ];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(
        r.matrix.iter().filter(|m| m.environment == "prod").count(),
        0
    );
}

#[test]
fn missing_row_maps_to_key_missing_finding() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row(
            "api",
            "STRIPE_KEY",
            KeyState::Missing,
            TargetState::Absent,
        )],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(r.findings[0].code, "key_missing");
}

#[test]
fn failed_rule_row_maps_to_key_failed_rule_finding() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row(
            "api",
            "STRIPE_KEY",
            KeyState::RuleFailed("prefix", Reason::Fixed("expected sk-")),
            TargetState::Absent,
        )],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(r.findings[0].code, "key_failed_rule");
}

#[test]
fn wrong_kind_row_maps_to_key_wrong_kind_finding() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row(
            "api",
            "STRIPE_KEY",
            KeyState::WrongKind,
            TargetState::Absent,
        )],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(r.findings[0].code, "key_wrong_kind");
}

#[test]
fn source_blocked_row_produces_no_finding() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row(
            "worker",
            "DB_URL",
            KeyState::SourceBlocked,
            TargetState::Absent,
        )],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(r.findings.len(), 0);
}

#[test]
fn row_finding_prerequisite_opens_the_product_key_label() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row(
            "api",
            "STRIPE_KEY",
            KeyState::Missing,
            TargetState::Absent,
        )],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(
        r.findings[0].prerequisite,
        "opv open api/STRIPE_KEY --env staging"
    );
}

#[test]
fn row_finding_verify_names_the_product() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row(
            "api",
            "STRIPE_KEY",
            KeyState::Missing,
            TargetState::Absent,
        )],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(r.findings[0].verify, "opv status staging --product api");
}

#[test]
fn row_finding_effect_writes_1password() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row(
            "api",
            "STRIPE_KEY",
            KeyState::Missing,
            TargetState::Absent,
        )],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(r.findings[0].effect, "writes_1password");
}

#[test]
fn simple_profile_finding_label_omits_product() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        None,
        vec![row(
            SIMPLE_PRODUCT,
            "STRIPE_KEY",
            KeyState::Missing,
            TargetState::Absent,
        )],
    )];
    let mut i = inputs(&report, envs);
    i.simple = true;
    let r = receipt(&i, "0.6.0");
    assert_eq!(
        r.findings[0].prerequisite,
        "opv open STRIPE_KEY --env staging"
    );
}

#[test]
fn simple_profile_finding_scope_omits_product() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        None,
        vec![row(
            SIMPLE_PRODUCT,
            "STRIPE_KEY",
            KeyState::Missing,
            TargetState::Absent,
        )],
    )];
    let mut i = inputs(&report, envs);
    i.simple = true;
    let r = receipt(&i, "0.6.0");
    assert_eq!(r.findings[0].scope.product, None);
}

#[test]
fn selected_signed_out_account_finding_scopes_the_selected_account() {
    let report = signed_out_report();
    let r = receipt(&inputs(&report, vec![]), "0.6.0");
    assert_eq!(
        r.findings[0].scope.account.as_deref(),
        Some("AAAA0000000000000000000001")
    );
}

#[test]
fn selected_signed_out_account_finding_blocks_and_signs_in() {
    let report = signed_out_report();
    let r = receipt(&inputs(&report, vec![]), "0.6.0");
    let f = &r.findings[0];
    assert_eq!(
        (
            f.code.as_str(),
            f.blocking,
            f.effect.as_str(),
            f.actor.as_str()
        ),
        ("selected_signed_out", true, "signs_in", "owner")
    );
}

#[test]
fn account_finding_verify_lists_accounts() {
    let report = signed_out_report();
    let r = receipt(&inputs(&report, vec![]), "0.6.0");
    assert_eq!(r.findings[0].verify, "opv account list --json");
}

#[test]
fn discovery_unavailable_account_finding_is_not_blocking() {
    let report = unavailable_report();
    let r = receipt(&inputs(&report, vec![]), "0.6.0");
    assert!(!r.findings[0].blocking);
}

#[test]
fn errored_environment_finding_uses_the_error_code_and_next() {
    let report = account_report();
    let error = Error::Auth("not signed in".into())
        .with_code(Code::OpNotSignedIn)
        .with_next("opv login --account AAAA");
    let envs = vec![env_err("staging", Some("Fly"), error)];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(
        (
            r.findings[0].code.as_str(),
            r.findings[0].prerequisite.as_str()
        ),
        ("op_not_signed_in", "opv login --account AAAA")
    );
}

#[test]
fn errored_environment_finding_signs_in_for_an_auth_code() {
    let report = account_report();
    let error = Error::Auth("not signed in".into()).with_code(Code::OpNotSignedIn);
    let envs = vec![env_err("staging", Some("Fly"), error)];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(r.findings[0].effect, "signs_in");
}

#[test]
fn errored_environment_finding_uses_agent_when_human_not_required() {
    let report = account_report();
    let envs = vec![env_err(
        "staging",
        Some("Fly"),
        Error::Source("unreadable".into()),
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(r.findings[0].actor, "agent");
}

#[test]
fn errored_environment_finding_falls_back_to_status_command() {
    let report = account_report();
    let envs = vec![env_err(
        "staging",
        Some("Fly"),
        Error::Source("unreadable".into()),
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(r.findings[0].prerequisite, "opv status staging");
}

#[test]
fn next_prefers_the_first_blocking_finding() {
    let report = unavailable_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row(
            "api",
            "STRIPE_KEY",
            KeyState::Missing,
            TargetState::Absent,
        )],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(
        r.next.as_ref().map(|n| n.command.as_str()),
        Some("opv open api/STRIPE_KEY --env staging")
    );
}

#[test]
fn next_is_null_without_findings() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row("api", "A", KeyState::Ready, TargetState::Present)],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert!(r.next.is_none());
}

#[test]
fn receipt_id_is_stable_for_equal_inputs() {
    let report = account_report();
    let rows = vec![row("api", "A", KeyState::Ready, TargetState::Present)];
    let one = receipt(
        &inputs(&report, vec![env("staging", Some("Fly"), rows.clone())]),
        "0.6.0",
    );
    let two = receipt(
        &inputs(&report, vec![env("staging", Some("Fly"), rows)]),
        "0.6.0",
    );
    assert_eq!(one.receipt_id, two.receipt_id);
}

#[test]
fn receipt_id_changes_when_a_finding_changes() {
    let report = account_report();
    let ready = receipt(
        &inputs(
            &report,
            vec![env(
                "staging",
                Some("Fly"),
                vec![row("api", "A", KeyState::Ready, TargetState::Present)],
            )],
        ),
        "0.6.0",
    );
    let missing = receipt(
        &inputs(
            &report,
            vec![env(
                "staging",
                Some("Fly"),
                vec![row("api", "A", KeyState::Missing, TargetState::Absent)],
            )],
        ),
        "0.6.0",
    );
    assert_ne!(ready.receipt_id, missing.receipt_id);
}

#[test]
fn text_first_line_reports_blocking_and_finding_counts() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row(
            "api",
            "STRIPE_KEY",
            KeyState::Missing,
            TargetState::Absent,
        )],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert!(text(&r).starts_with("ready: 1 blocking · 1 findings · receipt rcpt-"));
}

#[test]
fn text_grid_shows_saved_over_keys_with_findings() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![
            row("api", "A", KeyState::Ready, TargetState::Present),
            row("api", "B", KeyState::Missing, TargetState::Absent),
        ],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert!(text(&r).contains("1/2 · 1 finding"));
}

#[test]
fn text_grid_marks_an_undelivered_product_with_n_a() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row("api", "A", KeyState::Ready, TargetState::NotDelivered)],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert!(
        text(&r)
            .lines()
            .any(|l| l.starts_with("api") && l.contains("n/a"))
    );
}

#[test]
fn text_grid_marks_a_product_absent_from_an_environment_with_dash() {
    let report = account_report();
    let envs = vec![
        env(
            "staging",
            Some("Fly"),
            vec![row("api", "A", KeyState::Ready, TargetState::Present)],
        ),
        env(
            "prod",
            Some("Fly"),
            vec![row("worker", "W", KeyState::Ready, TargetState::Present)],
        ),
    ];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert!(
        text(&r)
            .lines()
            .any(|l| l.starts_with("api") && l.ends_with('-'))
    );
}

#[test]
fn text_lists_a_finding_line() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row(
            "api",
            "STRIPE_KEY",
            KeyState::Missing,
            TargetState::Absent,
        )],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert!(text(&r).contains(
        "  [owner] key_missing staging api/STRIPE_KEY → opv open api/STRIPE_KEY --env staging"
    ));
}

#[test]
fn text_prints_the_next_line() {
    let report = account_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row(
            "api",
            "STRIPE_KEY",
            KeyState::Missing,
            TargetState::Absent,
        )],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert!(text(&r).contains("Next (owner): opv open api/STRIPE_KEY --env staging"));
}

fn all_keys(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                out.push(k.clone());
                all_keys(val, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                all_keys(item, out);
            }
        }
        _ => {}
    }
}

#[test]
fn serialized_receipt_has_no_secret_named_field() {
    let report = signed_out_report();
    let envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row(
            "api",
            "STRIPE_KEY",
            KeyState::Missing,
            TargetState::Absent,
        )],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    let v = serde_json::to_value(&r).unwrap();
    let mut keys = Vec::new();
    all_keys(&v, &mut keys);
    let forbidden = ["value", "token", "password", "session"];
    assert!(keys.iter().all(|k| !forbidden.contains(&k.as_str())));
}
