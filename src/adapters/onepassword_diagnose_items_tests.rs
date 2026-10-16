//! The item/vault diagnosis (design §5, audit 04.01): recorded op replies and the `Facts`
//! that decide a refusal. One assertion per test, through the public `diagnose_item_call`.

use super::diagnose_item_call;
use crate::adapters::onepassword_diagnose::{Facts, diagnose_with};
use crate::cause::{
    AccountId, CallId, Cause, CreateKind, DiagnoseContext, ExitClass, GrantModel, Observed,
    Principal, Refind, ResourceKind, ResourceName, ResourceRef, Right, System,
};

/// Account A, the project's account in the recordings (`<ACCOUNT_2>`).
const A: &str = "<ACCOUNT_2>";

fn fixture(name: &str) -> String {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/op/failures");
    std::fs::read_to_string(format!("{dir}/{name}")).expect("recording")
}

/// The recorded raw stderr and exit class for `case`.
fn recorded(case: &str) -> (String, ExitClass) {
    let code = fixture(&format!("{case}.exit"))
        .trim()
        .parse::<i32>()
        .expect("recorded exit is a number");
    (fixture(&format!("{case}.stderr")), ExitClass::Code { code })
}

fn observed(words: &str, exit: ExitClass, principal: Principal) -> Observed {
    let call = CallId {
        system: System::OnePassword,
        program: "op".to_string(),
        words: words.split_whitespace().map(str::to_string).collect(),
    };
    Observed::from_failed_call(call, exit, principal)
}

fn person() -> Principal {
    Principal::Person { account: None }
}

fn in_account(account: &str) -> DiagnoseContext {
    DiagnoseContext {
        account: Some(AccountId::new(account)),
        ..DiagnoseContext::default()
    }
}

fn item_ctx() -> DiagnoseContext {
    DiagnoseContext {
        account: Some(AccountId::new(A)),
        resource: Some(ResourceRef {
            kind: ResourceKind::Item,
            name: ResourceName::new("deploy"),
            scope: None,
        }),
        ..DiagnoseContext::default()
    }
}

fn readable_item() -> Facts {
    Facts {
        item_readable: true,
        ..Facts::default()
    }
}

fn readable_vault() -> Facts {
    Facts {
        vault_readable: true,
        ..Facts::default()
    }
}

/// Diagnose recorded `case`, run as `words`, through both strategies with the same call,
/// context and facts, so their causes can be compared.
fn both(case: &str, words: &str, ctx: &DiagnoseContext, facts: &Facts) -> (Cause, Cause) {
    let (stderr, exit) = recorded(case);
    let seen = observed(words, exit, person());
    let item = diagnose_item_call(seen.clone(), &stderr, ctx, facts);
    let session = diagnose_with(seen, &stderr, ctx, facts);
    (item, session)
}

// --- recorded item/vault cases keep the session strategy's cause ----------------------------

#[test]
fn recorded_vault_not_found_keeps_the_session_strategy_cause() {
    let (item, session) = both(
        "08-vault-not-found",
        &format!("vault get ZZZZZZZZZZZZZZZZZZZZZZZZZZ --account {A} --format json"),
        &in_account(A),
        &Facts::default(),
    );
    assert_eq!(item, session);
}

#[test]
fn recorded_item_not_found_keeps_the_session_strategy_cause() {
    let (item, session) = both(
        "09-item-not-found",
        &format!("item get opv-recording-none --vault <VAULT_A> --account {A} --format json"),
        &in_account(A),
        &Facts::default(),
    );
    assert_eq!(item, session);
}

#[test]
fn recorded_vault_of_another_account_keeps_the_session_strategy_cause() {
    let (item, session) = both(
        "14-vault-in-other-account",
        &format!("vault get <VAULT_B> --account {A} --format json"),
        &in_account(A),
        &Facts::default(),
    );
    assert_eq!(item, session);
}

#[test]
fn recorded_vault_user_list_of_another_account_keeps_the_session_strategy_cause() {
    let (item, session) = both(
        "15-vault-user-list-in-other-account",
        &format!("vault user list <VAULT_B> --account {A} --format json"),
        &in_account(A),
        &Facts::default(),
    );
    assert_eq!(item, session);
}

// --- rules the item strategy adds -----------------------------------------------------------

#[test]
fn a_signed_out_item_get_is_op_not_signed_in() {
    let (stderr, exit) = recorded("07-signed-out-item-get");
    let seen = observed(
        &format!("item get opv-recording-none --account {A} --format json"),
        exit,
        person(),
    );
    let cause = diagnose_item_call(seen, &stderr, &in_account(A), &Facts::default());
    assert_eq!(cause.code(), "op_not_signed_in");
}

#[test]
fn a_timed_out_item_create_is_create_outcome_unknown_by_title() {
    let ctx = DiagnoseContext {
        create: Some((CreateKind::Item, "deploy".to_string(), Refind::ByTitle)),
        ..DiagnoseContext::default()
    };
    let seen = observed("item create deploy", ExitClass::TimedOut, person());
    let cause = diagnose_item_call(seen, "", &ctx, &Facts::default());
    assert!(matches!(
        cause,
        Cause::CreateOutcomeUnknown {
            refind: Refind::ByTitle,
            ..
        }
    ));
}

/// B2 (X5): a service account cannot be found by title, so a timed-out create keeps the
/// call site's own check instead of being presented as safe to re-run.
#[test]
fn a_timed_out_service_account_create_keeps_the_contexts_refind() {
    let check = Refind::Check(crate::cause::Cmd {
        command: vec!["access".to_string()],
        args: vec!["prod".to_string()],
    });
    let ctx = DiagnoseContext {
        create: Some((
            CreateKind::ServiceAccount,
            "opv-prod".to_string(),
            check.clone(),
        )),
        ..DiagnoseContext::default()
    };
    let seen = observed(
        "service-account create opv-prod",
        ExitClass::TimedOut,
        person(),
    );
    let cause = diagnose_item_call(seen, "", &ctx, &Facts::default());
    assert!(matches!(cause, Cause::CreateOutcomeUnknown { refind, .. } if refind == check));
}

#[test]
fn a_write_refused_on_a_readable_item_is_missing_write_right() {
    let ctx = DiagnoseContext {
        write: true,
        ..item_ctx()
    };
    let seen = observed(
        &format!("item edit deploy --vault <VAULT_A> --account {A}"),
        ExitClass::Code { code: 1 },
        person(),
    );
    let cause = diagnose_item_call(seen, "", &ctx, &readable_item());
    assert!(matches!(
        cause,
        Cause::MissingRight {
            right: Right::Write,
            grant: GrantModel::VaultPermission,
            ..
        }
    ));
}

#[test]
fn a_write_failure_recording_is_not_item_not_found_when_the_item_is_readable() {
    let ctx = DiagnoseContext {
        write: true,
        ..item_ctx()
    };
    let (stderr, exit) = recorded("09-item-not-found");
    let seen = observed(
        &format!("item edit opv-recording-none --vault <VAULT_A> --account {A}"),
        exit,
        person(),
    );
    let cause = diagnose_item_call(seen, &stderr, &ctx, &readable_item());
    assert!(matches!(
        cause,
        Cause::MissingRight {
            right: Right::Write,
            ..
        }
    ));
}

#[test]
fn a_refused_vault_user_list_on_a_readable_vault_is_missing_manage_right() {
    let seen = observed(
        &format!("vault user list <VAULT_A> --account {A} --format json"),
        ExitClass::Code { code: 1 },
        person(),
    );
    let cause = diagnose_item_call(seen, "", &in_account(A), &readable_vault());
    assert!(matches!(
        cause,
        Cause::MissingRight {
            right: Right::Manage,
            ..
        }
    ));
}

#[test]
fn an_unrecorded_item_get_reply_is_unrecognized() {
    let seen = observed(
        &format!("item get deploy --account {A}"),
        ExitClass::Code { code: 1 },
        person(),
    );
    let cause = diagnose_item_call(
        seen,
        "opv has no recording of this wording",
        &in_account(A),
        &Facts::default(),
    );
    assert_eq!(cause.code(), "unrecognized_failure");
}
