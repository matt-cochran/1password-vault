//! FR-51 readiness receipt: one behavioural outcome per test. No `op` call and no target
//! call: the account report and the rows are built directly.

use super::*;
use crate::adapters::onepassword_manifest::{Account, Discovery};
use crate::app::account;
use crate::cause::{
    CallId, Cause, ExitClass, GrantModel, NamedBy, NotFoundState, Observed, Principal,
    ResourceKind, ResourceName, ResourceRef, Right, SessionState, System,
};
use crate::domain::Kind;
use crate::domain::rules::Reason;
use crate::host::Platform;

/// A failed `op` call by the person, as the runner observes one.
fn op_seen() -> Observed {
    Observed::from_failed_call(
        CallId {
            system: System::OnePassword,
            program: "op".into(),
            words: vec!["item".into(), "get".into()],
        },
        ExitClass::Code { code: 1 },
        Principal::Person { account: None },
    )
}

fn op_resource(kind: ResourceKind, name: &str) -> ResourceRef {
    ResourceRef {
        kind,
        name: ResourceName::new(name),
        scope: None,
    }
}

/// An item 1Password does not show (`item_not_found`).
fn item_not_found() -> Error {
    Cause::NotFound {
        system: System::OnePassword,
        resource: op_resource(ResourceKind::Item, "deploy-credentials"),
        named_by: NamedBy::Flag {
            flag: "--item".into(),
        },
        state: NotFoundState::Missing,
        seen: op_seen(),
    }
    .into()
}

/// A vault the person cannot open (`vault_no_access`).
fn vault_no_access() -> Error {
    Cause::MissingRight {
        system: System::OnePassword,
        resource: op_resource(ResourceKind::Vault, "vprd"),
        right: Right::Read,
        grant: GrantModel::VaultPermission,
        env: None,
        target: None,
        seen: op_seen(),
    }
    .into()
}

/// A failure 1Password's diagnosis does not recognise.
fn unrecognized() -> Error {
    Cause::Unrecognized {
        system: System::OnePassword,
        established: Vec::new(),
        env: None,
        target: None,
        seen: op_seen(),
    }
    .into()
}

/// Not signed in to 1Password (`op_not_signed_in`).
fn op_signed_out() -> Error {
    Cause::NotSignedIn {
        system: System::OnePassword,
        account: None,
        state: SessionState::SignedOut,
    }
    .into()
}

/// flyctl is not installed (`dependency_missing`).
fn flyctl_missing() -> Error {
    Cause::ToolMissing {
        tool: "flyctl".into(),
        platform: Platform::Linux,
        shell: crate::host::Shell::Posix,
        ci: false,
    }
    .into()
}

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
        session_vars: Vec::new(),
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
    match target {
        Some(provider) => EnvInput {
            name: name.into(),
            target: Some(vec![TargetInput {
                name: format!("{name}-target"),
                provider: provider.into(),
                locator: format!("{name}-locator"),
                grants_missing: None,
                rows: Ok(rows),
            }]),
            rows: Ok(Vec::new()),
            title: None,
            audience: None,
        },
        None => EnvInput {
            name: name.into(),
            target: None,
            rows: Ok(rows),
            title: None,
            audience: None,
        },
    }
}

fn inputs<'a>(report: &'a account::Report, envs: Vec<EnvInput>) -> Inputs<'a> {
    Inputs {
        config_source: Some("secrets.toml".into()),
        account: report,
        envs,
        personal: Default::default(),
        health: Vec::new(),
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
        session_vars: Vec::new(),
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
        session_vars: Vec::new(),
    })
}

fn env_err(name: &str, target: Option<&str>, error: Error) -> EnvInput {
    match target {
        Some(provider) => EnvInput {
            name: name.into(),
            target: Some(vec![TargetInput {
                name: format!("{name}-target"),
                provider: provider.into(),
                locator: format!("{name}-locator"),
                grants_missing: None,
                rows: Err(error),
            }]),
            rows: Ok(Vec::new()),
            title: None,
            audience: None,
        },
        None => EnvInput {
            name: name.into(),
            target: None,
            rows: Err(error),
            title: None,
            audience: None,
        },
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
        env_err("prod", Some("Fly"), unrecognized()),
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
fn an_agent_holds_a_pending_rule_back_from_the_receipt() {
    let report = account_report();
    let mut envs = vec![env(
        "staging",
        Some("Fly"),
        vec![row(
            "api",
            "STRIPE_KEY",
            KeyState::RuleFailed("prefix", Reason::Fixed("expected sk-")),
            TargetState::Absent,
        )],
    )];
    let gate = RuleGate {
        agent: true,
        pending: &|_, _| true,
    };
    gate_rows(&mut envs, &gate);
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(r.findings[0].code, "rules_pending_review");
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
    assert_eq!(
        r.findings[0].verify,
        "opv status staging --target staging-target --product api"
    );
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
fn an_unreadable_targets_rows_name_that_reason_in_grants_missing() {
    let report = account_report();
    let error = item_not_found();
    let want = error.to_string();
    let envs = vec![env_err("staging", Some("Fly"), error)];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(r.findings[0].message.as_deref(), Some(want.as_str()));
}

#[test]
fn a_grants_missing_finding_next_is_access_with_the_target() {
    let report = account_report();
    let envs = vec![env_err("staging", Some("Fly"), vault_no_access())];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(
        r.findings[0].prerequisite,
        "opv access staging --target staging-target"
    );
}

#[test]
fn a_grants_missing_finding_blocks_with_the_owner() {
    let report = account_report();
    let envs = vec![env_err("staging", Some("Fly"), vault_no_access())];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    let f = &r.findings[0];
    assert_eq!(
        (
            f.code.as_str(),
            f.blocking,
            f.effect.as_str(),
            f.actor.as_str()
        ),
        ("grants_missing", true, "none", "owner")
    );
}

#[test]
fn a_target_that_could_not_be_read_is_reported_grants_missing() {
    let report = account_report();
    let envs = vec![env_err("staging", Some("Fly"), unrecognized())];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    assert_eq!(r.targets[0].state, "grants_missing");
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
    assert!(text(&r).starts_with("ready: 1 blocking · 1 finding · receipt rcpt-"));
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
        "  [owner] key_missing staging staging-target api/STRIPE_KEY → opv open api/STRIPE_KEY --env staging"
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

// FR-55: titles, audience, personal keys ----------------------------------------------

fn titled(name: &str, title: &str) -> EnvInput {
    EnvInput {
        name: name.into(),
        target: None,
        rows: Ok(vec![]),
        title: Some(title.into()),
        audience: None,
    }
}

#[test]
fn the_grid_shows_an_environments_display_name() {
    let account = crate::app::account::credential_report(crate::host::Platform::Linux);
    let mut env = titled("prod-us", "Production (US)");
    env.rows = Ok(vec![crate::domain::Row {
        product: "api".into(),
        key: "K".into(),
        kind: crate::domain::Kind::Secret,
        state: KeyState::Ready,
        target: TargetState::Unknown,
        guidance: String::new(),
        source: None,
        shared_by: Vec::new(),
    }]);
    let r = receipt(
        &Inputs {
            config_source: None,
            account: &account,
            envs: vec![env],
            personal: Default::default(),
            health: Vec::new(),
        },
        "t",
    );
    let mut out = Vec::new();
    render_text(&r, &mut out).unwrap();
    assert!(String::from_utf8(out).unwrap().contains("Production (US)"));
}

#[test]
fn an_environment_for_another_audience_is_not_a_blocking_problem() {
    let account = crate::app::account::credential_report(crate::host::Platform::Linux);
    let mut env = titled("prod", "Production");
    env.audience = Some("devops".into());
    env.rows = Err(vault_no_access());
    let r = receipt(
        &Inputs {
            config_source: None,
            account: &account,
            envs: vec![env],
            personal: Default::default(),
            health: Vec::new(),
        },
        "t",
    );
    assert!(
        r.findings
            .iter()
            .all(|f| f.code == "not_for_you" && !f.blocking)
    );
}

#[test]
fn a_missing_personal_key_is_named_as_yours() {
    let account = crate::app::account::credential_report(crate::host::Platform::Linux);
    let mut env = titled("dev", "Local");
    env.rows = Ok(vec![crate::domain::Row {
        product: "api".into(),
        key: "OPENAI_API_KEY".into(),
        kind: crate::domain::Kind::Secret,
        state: KeyState::Missing,
        target: TargetState::Unknown,
        guidance: String::new(),
        source: None,
        shared_by: Vec::new(),
    }]);
    let r = receipt(
        &Inputs {
            config_source: None,
            account: &account,
            envs: vec![env],
            personal: [("api".to_string(), "OPENAI_API_KEY".to_string())].into(),
            health: Vec::new(),
        },
        "t",
    );
    assert_eq!(r.findings[0].code, "personal_key_missing");
}

// #92: settings health ---------------------------------------------------------------

fn health_finding() -> crate::domain::health::HealthFinding {
    crate::domain::health::HealthFinding {
        code: crate::domain::health::SAME_ACROSS,
        environments: vec!["dev".into(), "prod".into()],
        product: "api".into(),
        key: "DATABASE_URL".into(),
        other: None,
        message: "api/DATABASE_URL has the same value in dev and prod".into(),
    }
}

fn health_receipt() -> Receipt {
    let report = account_report();
    let mut i = inputs(&report, Vec::new());
    i.health = vec![health_finding()];
    receipt(&i, "test")
}

#[test]
fn a_health_finding_is_in_the_receipt_by_its_code() {
    assert_eq!(
        health_receipt().findings[0].code,
        "same_value_across_environments"
    );
}

#[test]
fn a_health_finding_never_blocks() {
    assert!(!health_receipt().findings[0].blocking);
}

#[test]
fn a_health_finding_carries_its_message() {
    assert_eq!(
        health_receipt().findings[0].message.as_deref(),
        Some("api/DATABASE_URL has the same value in dev and prod")
    );
}

#[test]
fn a_health_finding_opens_the_key_in_its_first_environment() {
    assert_eq!(
        health_receipt().findings[0].prerequisite,
        "opv open api/DATABASE_URL --env dev"
    );
}

/// A `same_value_under_two_keys` warning for the health surface tests.
fn health_finding_under_two() -> crate::domain::health::HealthFinding {
    crate::domain::health::HealthFinding {
        code: crate::domain::health::SAME_UNDER_TWO,
        environments: vec!["dev".into()],
        product: "api".into(),
        key: "DATABASE_URL".into(),
        other: Some(("api".into(), "DATABASE_URL_RO".into())),
        message: "api/DATABASE_URL and api/DATABASE_URL_RO hold the same value in dev".into(),
    }
}

/// The receipt for one health finding, read under `host` as the CLI reads it.
fn health_receipt_on(host: crate::host::Host, h: crate::domain::health::HealthFinding) -> Receipt {
    let report = account_report();
    let mut i = inputs(&report, Vec::new());
    i.health = vec![h];
    crate::host::with_test_host(host, || receipt(&i, "test"))
}

fn agent_host() -> crate::host::Host {
    crate::host::Host::from_env(&crate::host::FakeEnv::new("linux").var_val("OPV_AGENT", "1"))
}

fn person_host() -> crate::host::Host {
    crate::host::Host::from_env(&crate::host::FakeEnv::new("linux").shell("/bin/bash").tty())
}

fn ci_host() -> crate::host::Host {
    crate::host::Host::from_env(
        &crate::host::FakeEnv::new("linux")
            .shell("/bin/bash")
            .var("CI"),
    )
}

fn mcp_host() -> crate::host::Host {
    crate::host::Host::from_env(&crate::host::FakeEnv::new("linux").shell("/bin/bash").mcp())
}

#[test]
fn an_mcp_caller_sees_no_cross_tier_health_warning() {
    let r = health_receipt_on(mcp_host(), health_finding());
    assert!(
        r.findings
            .iter()
            .all(|f| f.code != "same_value_across_environments")
    );
}

#[test]
fn agent_mode_hides_same_value_across_environments() {
    let r = health_receipt_on(agent_host(), health_finding());
    assert!(
        r.findings
            .iter()
            .all(|f| f.code != "same_value_across_environments")
    );
}

#[test]
fn agent_mode_hides_same_value_under_two_keys() {
    let r = health_receipt_on(agent_host(), health_finding_under_two());
    assert!(
        r.findings
            .iter()
            .all(|f| f.code != "same_value_under_two_keys")
    );
}

#[test]
fn a_person_at_a_terminal_sees_same_value_across_environments() {
    let r = health_receipt_on(person_host(), health_finding());
    assert!(
        r.findings
            .iter()
            .any(|f| f.code == "same_value_across_environments")
    );
}

#[test]
fn a_person_at_a_terminal_sees_same_value_under_two_keys() {
    let r = health_receipt_on(person_host(), health_finding_under_two());
    assert!(
        r.findings
            .iter()
            .any(|f| f.code == "same_value_under_two_keys")
    );
}

#[test]
fn ci_sees_same_value_across_environments() {
    let r = health_receipt_on(ci_host(), health_finding());
    assert!(
        r.findings
            .iter()
            .any(|f| f.code == "same_value_across_environments")
    );
}

#[test]
fn ci_sees_same_value_under_two_keys() {
    let r = health_receipt_on(ci_host(), health_finding_under_two());
    assert!(
        r.findings
            .iter()
            .any(|f| f.code == "same_value_under_two_keys")
    );
}

#[test]
fn no_health_finding_blocks_readiness() {
    let report = account_report();
    let mut i = inputs(&report, Vec::new());
    i.health = vec![health_finding(), health_finding_under_two()];
    let r = receipt(&i, "test");
    assert!(r.findings.iter().all(|f| !f.blocking));
}

#[test]
fn a_readiness_finding_has_no_message_in_its_json() {
    let report = account_report();
    let r = receipt(
        &inputs(
            &report,
            vec![env(
                "dev",
                None,
                vec![row("api", "X", KeyState::Missing, TargetState::Absent)],
            )],
        ),
        "test",
    );
    assert!(
        serde_json::to_value(&r).unwrap()["findings"][0]
            .get("message")
            .is_none()
    );
}

/// `opv ready --json` on two run-only environments whose items hold the same secret.
fn ready_on_two_items(dev: &str, ci: &str) -> serde_json::Value {
    use crate::adapters::fake_op::FakeOp;
    let op = FakeOp::default();
    let item = |value: &str| {
        serde_json::json!({
            "title": "t", "category": "SECURE_NOTE",
            "sections": [{"id": "app", "label": "app"}],
            "fields": [{"id": "f1", "type": "CONCEALED", "section": {"id": "app", "label": "app"},
                        "label": "DATABASE_URL", "value": value}]
        })
    };
    let dev_id = op.insert("vdev0000000000000000000001", item(dev));
    let ci_id = op.insert("vdev0000000000000000000001", item(ci));
    let fleet = crate::config::parse(&format!(
        "[environments.dev]\n\
         boundaries.app = {{ vault_id = \"vdev0000000000000000000001\", item_id = \"{dev_id}\" }}\n\
         [environments.ci]\n\
         boundaries.app = {{ vault_id = \"vdev0000000000000000000001\", item_id = \"{ci_id}\" }}\n\
         [products.app.keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [\"dev\", \"ci\"]\n"
    ))
    .unwrap();
    let mut out = Vec::new();
    run(&fleet, None, None, &op, true, None, &mut out).unwrap();
    serde_json::from_slice(&out).unwrap()
}

#[test]
fn ready_reports_one_secret_in_two_environments() {
    let doc = ready_on_two_items("pw-HEALTHMARK", "pw-HEALTHMARK");
    assert!(
        doc["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["code"] == "same_value_across_environments")
    );
}

#[test]
fn ready_never_prints_the_compared_value() {
    let doc = ready_on_two_items("pw-HEALTHMARK", "pw-HEALTHMARK");
    assert!(!doc.to_string().contains("HEALTHMARK"));
}

#[test]
fn ready_is_quiet_when_the_environments_differ() {
    let doc = ready_on_two_items("pw-HEALTHMARK-a", "pw-HEALTHMARK-b");
    assert!(
        !doc["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["code"] == "same_value_across_environments")
    );
}

// FR-56: every target ----------------------------------------------------------------

/// A target whose rows were read, with no missing grant.
fn target(name: &str, provider: &str, locator: &str) -> TargetInput {
    TargetInput {
        name: name.into(),
        provider: provider.into(),
        locator: locator.into(),
        grants_missing: None,
        rows: Ok(vec![]),
    }
}

fn target_env(name: &str, targets: Vec<TargetInput>) -> EnvInput {
    EnvInput {
        name: name.into(),
        target: Some(targets),
        rows: Ok(vec![]),
        title: None,
        audience: None,
    }
}

#[test]
fn receipt_lists_every_target_of_an_environment_with_provider_and_locator() {
    let report = account_report();
    let envs = vec![target_env(
        "staging",
        vec![
            target("web", "Fly", "web-app"),
            target("jobs", "Fly", "jobs-app"),
        ],
    )];
    let r = receipt(&inputs(&report, envs), "0.6.0");
    let listed: Vec<(&str, &str, &str)> = r
        .targets
        .iter()
        .map(|t| (t.name.as_str(), t.provider.as_str(), t.locator.as_str()))
        .collect();
    assert_eq!(
        listed,
        [("web", "Fly", "web-app"), ("jobs", "Fly", "jobs-app")]
    );
}

#[test]
fn a_target_whose_state_vault_cannot_be_opened_is_grants_missing() {
    let report = account_report();
    let mut t = target("web", "Fly", "web-app");
    t.grants_missing = Some("state vault vsprd cannot be opened".into());
    let r = receipt(
        &inputs(&report, vec![target_env("staging", vec![t])]),
        "0.6.0",
    );
    assert_eq!(r.targets[0].state, "grants_missing");
}

#[test]
fn a_state_vault_grants_missing_next_is_access_with_the_target() {
    let report = account_report();
    let mut t = target("web", "Fly", "web-app");
    t.grants_missing = Some("state vault vsprd cannot be opened".into());
    let r = receipt(
        &inputs(&report, vec![target_env("staging", vec![t])]),
        "0.6.0",
    );
    assert_eq!(
        r.next.as_ref().map(|n| n.command.as_str()),
        Some("opv access staging --target web")
    );
}

#[test]
fn a_target_whose_every_vault_is_visible_is_ready() {
    let report = account_report();
    let r = receipt(
        &inputs(
            &report,
            vec![target_env("staging", vec![target("web", "Fly", "web-app")])],
        ),
        "0.6.0",
    );
    assert_eq!(r.targets[0].state, "ready");
}

#[test]
fn a_state_vault_the_person_can_see_needs_no_grant() {
    use crate::adapters::fake_op::FakeOp;
    let op = FakeOp::default();
    op.vault_users
        .borrow_mut()
        .insert("vsprd".into(), serde_json::json!([]));
    assert!(state_vault_grants(&op, "vsprd").is_none());
}

#[test]
fn a_state_vault_the_person_cannot_see_names_grants_missing() {
    use crate::adapters::fake_op::FakeOp;
    let op = FakeOp::default();
    assert_eq!(
        state_vault_grants(&op, "vsprd").as_deref(),
        Some("state vault vsprd cannot be opened")
    );
}

/// `opv ready --json` over `fleet`, with `responses` answering the probe calls in order.
fn ready_doc(
    fleet: &crate::domain::Fleet,
    only: Option<&str>,
    responses: impl IntoIterator<Item = crate::runner::Output>,
) -> serde_json::Value {
    use crate::runner::fake::FakeRunner;
    let r = FakeRunner::new(responses);
    let mut out = Vec::new();
    run(fleet, None, only, &r, true, None, &mut out).unwrap();
    serde_json::from_slice(&out).unwrap()
}

#[test]
fn ready_run_reports_a_target_with_every_vault_visible_as_ready() {
    use crate::app::testutil::{complete_item, fly_empty};
    use crate::runner::Output;
    let doc = ready_doc(
        &crate::app::testutil::fleet(),
        Some("prod"),
        [
            crate::app::testutil::whoami(),
            Output::success(Vec::new()),
            complete_item(),
            fly_empty(),
            Output::success(b"[]".to_vec()),
        ],
    );
    assert_eq!(doc["targets"][0]["state"], "ready");
}

#[test]
fn ready_run_reports_a_target_whose_state_vault_cannot_be_opened_as_grants_missing() {
    use crate::app::testutil::{complete_item, fly_empty, whoami};
    use crate::runner::Output;
    let mut responses = vec![
        whoami(),
        Output::success(Vec::new()),
        complete_item(),
        fly_empty(),
    ];
    responses.extend(crate::runner::fake::failed_read(1));
    responses.push(whoami());
    responses.push(Output::failure(1));
    let doc = ready_doc(&crate::app::testutil::fleet(), Some("prod"), responses);
    assert_eq!(doc["targets"][0]["state"], "grants_missing");
}

#[test]
fn ready_run_lists_every_target_of_an_environment_with_provider_and_locator() {
    use crate::app::testutil::{complete_item, fly_empty};
    use crate::runner::Output;
    let fleet = crate::app::testutil::fleet_with(
        "[environments.prod.targets.secondary]\nfly.app = \"secondary-app\"\nfly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"\nstate_vault_id = \"sprd2\"\n",
    );
    let mut responses = vec![crate::app::testutil::whoami(), Output::success(Vec::new())];
    for _ in 0..2 {
        responses.push(complete_item());
        responses.push(fly_empty());
        responses.push(Output::success(b"[]".to_vec()));
    }
    let doc = ready_doc(&fleet, Some("prod"), responses);
    assert_eq!(
        doc["targets"],
        serde_json::json!([
            {"environment": "prod", "name": "portfolio", "provider": "Fly",
             "locator": "app mcproductlabs-portfolio-production", "state": "ready",
             "evidence_write": "not_verified"},
            {"environment": "prod", "name": "secondary", "provider": "Fly",
             "locator": "app secondary-app", "state": "ready",
             "evidence_write": "not_verified"},
        ])
    );
}

/// #134: an open state vault is never presented as proof that delivery evidence can be
/// written.
#[test]
fn a_ready_target_does_not_claim_evidence_can_be_written() {
    use crate::app::testutil::{complete_item, fly_empty};
    use crate::runner::Output;
    let fleet = crate::app::testutil::fleet_with("");
    let responses = vec![
        crate::app::testutil::whoami(),
        Output::success(Vec::new()),
        complete_item(),
        fly_empty(),
        Output::success(b"[]".to_vec()),
    ];
    let doc = ready_doc(&fleet, Some("prod"), responses);
    assert_eq!(doc["targets"][0]["evidence_write"], "not_verified");
}

/// #142: two accounts on one sign-in address is advice, never a readiness blocker.
#[test]
fn a_shared_sign_in_address_does_not_block_readiness() {
    let acct = |id: &str, short: &str| crate::adapters::onepassword_manifest::Account {
        account_uuid: id.into(),
        url: "https://my.1password.com/".into(),
        email: format!("{short}@example.com"),
        user_uuid: format!("U{id}"),
        shorthand: short.into(),
    };
    let account = account::report(&account::Inputs {
        discovery: crate::adapters::onepassword_manifest::Discovery::Listed(vec![
            acct("PERS0000000000000000000001", "my"),
            acct("BUSI0000000000000000000002", "biz"),
        ]),
        signed_in: &|_| Some(true),
        flag: Some("BUSI0000000000000000000002"),
        env: None,
        pointer: None,
        manifest: None,
        platform: crate::host::Platform::Wsl,
        session_vars: Vec::new(),
    });
    let r = receipt(&inputs(&account, vec![]), "0.8.0");
    assert!(
        !r.findings
            .iter()
            .any(|f| f.code == "shared_sign_in_address" && f.blocking)
    );
}

/// #157: a target stopped by a missing sign-in is reported as that, not as a missing grant.
fn signed_out_target_receipt() -> Receipt {
    let report = account_report();
    let error = op_signed_out();
    let envs = vec![env_err("staging", Some("Fly"), error)];
    receipt(&inputs(&report, envs), "0.9.0")
}

#[test]
fn a_target_stopped_by_a_missing_sign_in_reports_op_not_signed_in() {
    assert_eq!(
        signed_out_target_receipt().findings[0].code,
        "op_not_signed_in"
    );
}

#[test]
fn a_target_stopped_by_a_missing_sign_in_names_the_errors_own_step() {
    assert_eq!(
        signed_out_target_receipt().findings[0].prerequisite,
        "opv login"
    );
}

#[test]
fn a_target_stopped_by_a_missing_sign_in_signs_in() {
    assert_eq!(signed_out_target_receipt().findings[0].effect, "signs_in");
}

#[test]
fn a_target_stopped_by_a_missing_cli_is_the_agents_to_fix() {
    let report = account_report();
    let error = flyctl_missing();
    let envs = vec![env_err("staging", Some("Fly"), error)];
    let r = receipt(&inputs(&report, envs), "0.9.0");
    assert_eq!(
        (r.findings[0].code.as_str(), r.findings[0].actor.as_str()),
        ("dependency_missing", "agent")
    );
}

/// The GitHub "environment missing" error: a `Do:` for the owner and no step of its own.
fn owner_setup_receipt() -> Receipt {
    let report = account_report();
    let error = crate::adapters::github::gh::missing_environment_error("o/r", "staging");
    let envs = vec![env_err("staging", Some("GitHub"), error)];
    receipt(&inputs(&report, envs), "0.10.0")
}

/// 07.07 (S1): the owner's action is the prerequisite, never `opv doctor` (which cannot
/// see it: a loop).
#[test]
fn an_owner_setup_finding_never_points_at_doctor() {
    assert!(
        !owner_setup_receipt().findings[0]
            .prerequisite
            .starts_with("opv doctor")
    );
}

/// 07.07 (S1): the error's `Do:` is kept, as the prerequisite.
#[test]
fn an_owner_setup_finding_keeps_the_errors_do() {
    assert!(
        owner_setup_receipt().findings[0]
            .prerequisite
            .contains("repos/o/r/environments/staging")
    );
}

/// 07.07: the owner's step is the owner's.
#[test]
fn an_owner_setup_finding_is_the_owners() {
    assert_eq!(owner_setup_receipt().findings[0].actor, "owner");
}

/// 07.07: a finding whose error has both a Do and a Next shows the Do in `--json`.
#[test]
fn a_finding_keeps_the_errors_do_beside_its_next() {
    let report = account_report();
    let error = vault_no_access();
    let want = error.do_text();
    let envs = vec![env_err("staging", None, error)];
    let r = receipt(&inputs(&report, envs), "0.10.0");
    assert_eq!(r.findings[0].act, want);
}

/// 07.30: a run scoped to one environment claims only that environment.
#[test]
fn a_clean_single_environment_receipt_names_it() {
    let report = account_report();
    let envs = vec![env("staging", Some("Fly"), Vec::new())];
    let r = receipt(&inputs(&report, envs), "0.10.0");
    assert!(text(&r).contains("every declared key in staging is saved and staging was read"));
}

/// #157: a person who can read the state vault but not manage it needs no grant.
#[test]
fn a_state_vault_the_person_can_read_but_not_manage_needs_no_grant() {
    use crate::adapters::fake_op::FakeOp;
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push(("vsprd".into(), "myapp-prod-state".into()));
    assert!(state_vault_grants(&op, "vsprd").is_none());
}

/// #157: signed out, `opv ready` stops with `op_not_signed_in`.
#[test]
fn ready_signed_out_is_op_not_signed_in() {
    use crate::adapters::fake_op::FakeOp;
    let op = FakeOp::default();
    op.signed_in.set(false);
    let e = run(
        &crate::app::testutil::fleet(),
        None,
        Some("prod"),
        &op,
        true,
        None,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "op_not_signed_in");
}

/// #157: the state vault is checked in the environment's own account.
#[test]
fn ready_checks_the_state_vault_in_the_environments_account() {
    use crate::app::testutil::{complete_item, fly_empty, whoami};
    use crate::runner::Output;
    let mut fleet = crate::app::testutil::fleet();
    fleet.environments.get_mut("prod").unwrap().account = Some("work.1password.com".into());
    let r = crate::runner::fake::FakeRunner::new([
        whoami(),
        Output::success(Vec::new()),
        complete_item(),
        fly_empty(),
        Output::success(b"[]".to_vec()),
    ]);
    run(&fleet, None, Some("prod"), &r, true, None, &mut Vec::new()).unwrap();
    let calls = r.calls.borrow();
    let state = calls
        .iter()
        .find(|c| {
            c.args
                .starts_with(&["vault".to_string(), "user".to_string()])
        })
        .unwrap();
    assert!(
        state
            .env
            .contains(&("OP_ACCOUNT".to_string(), "work.1password.com".to_string()))
    );
}
