//! Access analysis (#96): one behavioural outcome per test. Every test observes a public
//! result; names and emails only ever appear as test input, never as expected output.

use super::*;
use serde_json::json;

/// One `op vault user list` entry.
fn entry(ty: &str, state: &str, name: Option<&str>, permissions: &[&str]) -> serde_json::Value {
    let mut value = json!({"type": ty, "state": state, "permissions": permissions});
    if let Some(name) = name {
        value["name"] = json!(name);
    }
    value
}

fn list(entries: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::Value::Array(entries)
}

/// A visible environment with `readers` as its only service accounts.
fn visible(environment: &str, deployed: bool, readers: Vec<Reader>) -> EnvAccess {
    EnvAccess {
        environment: environment.into(),
        vault_id: "v1".into(),
        deployed,
        deployed_tier: false,
        visible: true,
        people: 0,
        guests: 0,
        service_accounts: readers,
        writers: Vec::new(),
    }
}

fn invisible(environment: &str) -> EnvAccess {
    EnvAccess {
        visible: false,
        ..visible(environment, true, Vec::new())
    }
}

fn codes(found: &[AccessFinding]) -> Vec<&str> {
    found.iter().map(|f| f.code).collect()
}

// --- analyse: counts ---------------------------------------------------------------

#[test]
fn an_active_member_is_counted_as_a_person() {
    let users = list(vec![entry("MEMBER", "ACTIVE", Some("Alice"), &[])]);
    assert_eq!(analyse("prod", "v1", true, Some(&users)).people, 1);
}

#[test]
fn an_active_guest_is_counted_as_a_guest() {
    let users = list(vec![entry("GUEST", "ACTIVE", Some("Bob"), &[])]);
    assert_eq!(analyse("prod", "v1", true, Some(&users)).guests, 1);
}

#[test]
fn a_suspended_member_is_not_counted() {
    let users = list(vec![entry("MEMBER", "SUSPENDED", Some("Alice"), &[])]);
    assert_eq!(analyse("prod", "v1", true, Some(&users)).people, 0);
}

#[test]
fn a_suspended_guest_is_not_counted() {
    let users = list(vec![entry("GUEST", "SUSPENDED", Some("Bob"), &[])]);
    assert_eq!(analyse("prod", "v1", true, Some(&users)).guests, 0);
}

#[test]
fn a_suspended_service_account_is_not_listed() {
    let users = list(vec![entry(
        "SERVICE_ACCOUNT",
        "SUSPENDED",
        Some("ci"),
        &["allow_viewing"],
    )]);
    assert!(
        analyse("prod", "v1", true, Some(&users))
            .service_accounts
            .is_empty()
    );
}

#[test]
fn a_member_is_not_listed_as_a_service_account() {
    let users = list(vec![entry("MEMBER", "ACTIVE", Some("Alice"), &[])]);
    assert!(
        analyse("prod", "v1", true, Some(&users))
            .service_accounts
            .is_empty()
    );
}

// --- analyse: service accounts and read_only ---------------------------------------

#[test]
fn an_active_service_account_keeps_its_name() {
    let users = list(vec![entry(
        "SERVICE_ACCOUNT",
        "ACTIVE",
        Some("shop-prod-ci"),
        &["allow_viewing"],
    )]);
    assert_eq!(
        analyse("prod", "v1", true, Some(&users)).service_accounts[0].name,
        "shop-prod-ci"
    );
}

#[test]
fn an_unnamed_service_account_is_named_placeholder() {
    let users = list(vec![entry(
        "SERVICE_ACCOUNT",
        "ACTIVE",
        None,
        &["allow_viewing"],
    )]);
    assert_eq!(
        analyse("prod", "v1", true, Some(&users)).service_accounts[0].name,
        "(unnamed)"
    );
}

#[test]
fn a_viewing_only_service_account_is_read_only() {
    let users = list(vec![entry(
        "SERVICE_ACCOUNT",
        "ACTIVE",
        Some("ci"),
        &["allow_viewing"],
    )]);
    assert!(analyse("prod", "v1", true, Some(&users)).service_accounts[0].read_only);
}

#[test]
fn an_editing_service_account_is_not_read_only() {
    let users = list(vec![entry(
        "SERVICE_ACCOUNT",
        "ACTIVE",
        Some("ci"),
        &["allow_viewing", "allow_editing"],
    )]);
    assert!(!analyse("prod", "v1", true, Some(&users)).service_accounts[0].read_only);
}

#[test]
fn a_managing_service_account_is_not_read_only() {
    let users = list(vec![entry(
        "SERVICE_ACCOUNT",
        "ACTIVE",
        Some("ci"),
        &["allow_viewing", "allow_managing"],
    )]);
    assert!(!analyse("prod", "v1", true, Some(&users)).service_accounts[0].read_only);
}

#[test]
fn a_service_account_without_viewing_is_not_read_only() {
    let users = list(vec![entry(
        "SERVICE_ACCOUNT",
        "ACTIVE",
        Some("ci"),
        &["allow_editing"],
    )]);
    assert!(!analyse("prod", "v1", true, Some(&users)).service_accounts[0].read_only);
}

// --- analyse: visibility -----------------------------------------------------------

#[test]
fn a_read_users_array_makes_the_vault_visible() {
    let users = list(vec![entry("MEMBER", "ACTIVE", Some("Alice"), &[])]);
    assert!(analyse("prod", "v1", true, Some(&users)).visible);
}

#[test]
fn missing_users_makes_the_vault_invisible() {
    assert!(!analyse("prod", "v1", true, None).visible);
}

#[test]
fn not_an_array_makes_the_vault_invisible() {
    let users = json!({"error": "not visible"});
    assert!(!analyse("prod", "v1", true, Some(&users)).visible);
}

#[test]
fn an_invisible_vault_counts_no_people() {
    assert_eq!(analyse("prod", "v1", true, None).people, 0);
}

#[test]
fn an_invisible_vault_counts_no_guests() {
    assert_eq!(analyse("prod", "v1", true, None).guests, 0);
}

#[test]
fn an_invisible_vault_lists_no_service_accounts() {
    assert!(
        analyse("prod", "v1", true, None)
            .service_accounts
            .is_empty()
    );
}

// --- findings: per environment -----------------------------------------------------

#[test]
fn an_invisible_environment_yields_only_access_not_visible() {
    let found = findings(&[invisible("prod")]);
    assert_eq!(codes(&found), ["access_not_visible"]);
}

#[test]
fn access_not_visible_has_no_next_step() {
    let found = findings(&[invisible("prod")]);
    assert!(found[0].next.is_none());
}

#[test]
fn access_not_visible_never_suggests_a_ci_reader() {
    let found = findings(&[invisible("prod")]);
    assert!(!codes(&found).contains(&"no_ci_reader"));
}

#[test]
fn access_not_visible_message_names_the_environment() {
    let found = findings(&[invisible("prod")]);
    assert!(found[0].message.contains("prod"));
}

#[test]
fn a_deployed_environment_without_a_ci_reader_yields_no_ci_reader() {
    let found = findings(&[visible("prod", true, Vec::new())]);
    assert_eq!(codes(&found), ["no_ci_reader"]);
}

#[test]
fn a_local_environment_needs_no_ci_reader() {
    let writers = vec![Reader {
        name: "dev-ci".into(),
        read_only: false,
    }];
    let found = findings(&[visible("dev", false, writers)]);
    assert_eq!(codes(&found), ["ci_reader_can_write"]);
}

#[test]
fn a_read_only_service_account_omits_no_ci_reader() {
    let readers = vec![Reader {
        name: "prod-ci".into(),
        read_only: true,
    }];
    assert!(findings(&[visible("prod", true, readers)]).is_empty());
}

#[test]
fn no_ci_reader_suggests_creating_the_reader_without_showing_its_token() {
    let found = findings(&[visible("prod", true, Vec::new())]);
    assert_eq!(
        found[0].next.as_deref(),
        Some("opv access prod --create --github <owner/repo>")
    );
}

#[test]
fn no_ci_reader_message_names_the_environment() {
    let found = findings(&[visible("prod", true, Vec::new())]);
    assert!(found[0].message.contains("prod"));
}

#[test]
fn a_writable_service_account_yields_ci_reader_can_write() {
    let writers = vec![Reader {
        name: "prod-ci".into(),
        read_only: false,
    }];
    let found = findings(&[visible("prod", true, writers)]);
    assert!(codes(&found).contains(&"ci_reader_can_write"));
}

#[test]
fn a_read_only_service_account_yields_no_ci_reader_can_write() {
    let readers = vec![Reader {
        name: "prod-ci".into(),
        read_only: true,
    }];
    let found = findings(&[visible("prod", true, readers)]);
    assert!(!codes(&found).contains(&"ci_reader_can_write"));
}

#[test]
fn each_writable_service_account_yields_its_own_finding() {
    let writers = vec![
        Reader {
            name: "a".into(),
            read_only: false,
        },
        Reader {
            name: "b".into(),
            read_only: false,
        },
    ];
    let found = findings(&[visible("prod", true, writers)]);
    let writable = found
        .iter()
        .filter(|f| f.code == "ci_reader_can_write")
        .count();
    assert_eq!(writable, 2);
}

#[test]
fn ci_reader_can_write_message_names_the_service_account() {
    let writers = vec![Reader {
        name: "prod-ci".into(),
        read_only: false,
    }];
    let found = findings(&[visible("prod", true, writers)]);
    let message = &found
        .iter()
        .find(|f| f.code == "ci_reader_can_write")
        .unwrap()
        .message;
    assert!(message.contains("prod-ci"));
}

#[test]
fn ci_reader_can_write_message_names_the_environment() {
    let writers = vec![Reader {
        name: "prod-ci".into(),
        read_only: false,
    }];
    let found = findings(&[visible("prod", true, writers)]);
    let message = &found
        .iter()
        .find(|f| f.code == "ci_reader_can_write")
        .unwrap()
        .message;
    assert!(message.contains("prod"));
}

#[test]
fn ci_reader_can_write_has_no_next_step() {
    let writers = vec![Reader {
        name: "prod-ci".into(),
        read_only: false,
    }];
    let found = findings(&[visible("prod", true, writers)]);
    let finding = found
        .iter()
        .find(|f| f.code == "ci_reader_can_write")
        .unwrap();
    assert!(finding.next.is_none());
}

// --- findings: ordering ------------------------------------------------------------

#[test]
fn findings_keep_environments_in_input_order() {
    let mut prod = visible("prod", true, Vec::new());
    prod.service_accounts.push(Reader {
        name: "prod-ci".into(),
        read_only: false,
    });
    let found = findings(&[prod, invisible("staging")]);
    let environments: Vec<&str> = found.iter().map(|f| f.environment.as_str()).collect();
    assert_eq!(environments, ["prod", "prod", "staging"]);
}

#[test]
fn findings_are_ordered_by_code_within_an_environment() {
    let writers = vec![Reader {
        name: "prod-ci".into(),
        read_only: false,
    }];
    let found = findings(&[visible("prod", true, writers)]);
    assert_eq!(codes(&found), ["no_ci_reader", "ci_reader_can_write"]);
}

// --- privacy -----------------------------------------------------------------------

#[test]
fn analysis_serialises_no_member_name() {
    let users = list(vec![entry("MEMBER", "ACTIVE", Some("Alice Smith"), &[])]);
    let shown = serde_json::to_string(&analyse("prod", "v1", true, Some(&users))).unwrap();
    assert!(!shown.contains("Alice"));
}

#[test]
fn analysis_serialises_no_guest_email() {
    let users = list(vec![entry("GUEST", "ACTIVE", Some("bob@example.com"), &[])]);
    let shown = serde_json::to_string(&analyse("prod", "v1", true, Some(&users))).unwrap();
    assert!(!shown.contains("bob@example.com"));
}

#[test]
fn findings_name_no_member() {
    let users = list(vec![entry("MEMBER", "ACTIVE", Some("Alice Smith"), &[])]);
    let env = analyse("prod", "v1", true, Some(&users));
    let shown = serde_json::to_string(&findings(&[env])).unwrap();
    assert!(!shown.contains("Alice"));
}

#[test]
fn two_service_accounts_with_one_name_yield_pending_revoke() {
    let twins = vec![
        Reader {
            name: "shop-prod-ci".into(),
            read_only: true,
        },
        Reader {
            name: "shop-prod-ci".into(),
            read_only: true,
        },
    ];
    let found = findings(&[visible("prod", true, twins)]);
    assert_eq!(codes(&found), ["pending_revoke"]);
}

#[test]
fn pending_revoke_steps_to_verifying_the_new_delivery() {
    let twins = vec![
        Reader {
            name: "shop-prod-ci".into(),
            read_only: true,
        },
        Reader {
            name: "shop-prod-ci".into(),
            read_only: true,
        },
    ];
    let found = findings(&[visible("prod", true, twins)]);
    assert_eq!(found[0].next.as_deref(), Some("opv delivery verify prod"));
}

#[test]
fn distinct_service_account_names_yield_no_pending_revoke() {
    let two = vec![
        Reader {
            name: "shop-prod-ci".into(),
            read_only: true,
        },
        Reader {
            name: "shop-prod-web-deploy".into(),
            read_only: true,
        },
    ];
    let found = findings(&[visible("prod", true, two)]);
    assert!(!codes(&found).contains(&"pending_revoke"));
}

// --- 07.10, 07.35, 07.36: findings name the vault, the environment and who acts ---

fn twins() -> Vec<Reader> {
    vec![
        Reader {
            name: "shop-prod-ci".into(),
            read_only: true,
        },
        Reader {
            name: "shop-prod-ci".into(),
            read_only: true,
        },
    ]
}

#[test]
fn pending_revoke_names_the_vault_apart_from_the_environment() {
    let found = findings(&[visible("prod", true, twins())]);
    assert!(
        found[0].message.contains("vault v1 (environment prod)"),
        "{}",
        found[0].message
    );
}

#[test]
fn a_writing_service_account_is_not_assumed_to_be_the_ci_reader() {
    let writers = vec![Reader {
        name: "sync-bot".into(),
        read_only: false,
    }];
    let found = findings(&[visible("prod", true, writers)]);
    let message = &found
        .iter()
        .find(|f| f.code == "ci_reader_can_write")
        .unwrap()
        .message;
    assert!(
        message.contains("If sync-bot is this project's CI reader, recreate it read-only"),
        "{message}"
    );
}

#[test]
fn access_not_visible_says_who_can_run_the_check() {
    let found = findings(&[invisible("prod")]);
    assert!(
        found[0]
            .message
            .contains("ask a manager of the vault to run opv access prod"),
        "{}",
        found[0].message
    );
}
