//! Recorded op failures mapped to a cause (design §4.3, §5), and the #160 session probe. One
//! assertion per test.
//!
//! Every reply is a real recording (`tests/fixtures/op/failures`, op 2.40.0): the `.stderr`
//! is the raw reply, the `.exit` what the runner observed, and the call's words are the
//! recorded command from `cases.tsv`. Test code builds the sealed [`Observed`] the runner
//! would hand to the strategy.

use super::{Facts, SessionCheck, VaultSearch, diagnose_with, placed, search_vault, session_for};
use crate::cause::{
    AccountId, AccountRef, AccountSource, CallId, Cause, CreateKind, CredentialProblem,
    CredentialRef, DiagnoseContext, ExitClass, Observed, Principal, Refind, SessionState, System,
    VarName, VaultId,
};
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

/// Account A, the project's account in the recordings (`<ACCOUNT_2>`).
const A: &str = "<ACCOUNT_2>";
/// Account B, the other account on the same sign-in address (`<ACCOUNT_1>`).
const B: &str = "<ACCOUNT_1>";

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

fn service_account_token() -> Principal {
    Principal::ShellToken {
        var: VarName::new("OP_SERVICE_ACCOUNT_TOKEN"),
    }
}

fn in_account(account: &str) -> DiagnoseContext {
    DiagnoseContext {
        account: Some(AccountId::new(account)),
        ..DiagnoseContext::default()
    }
}

fn op_account_set() -> Facts {
    Facts {
        env_overrides: vec![VarName::new("OP_ACCOUNT")],
        ..Facts::default()
    }
}

fn live(account: &str) -> Facts {
    Facts {
        live: Some(AccountId::new(account)),
        ..Facts::default()
    }
}

/// Diagnose recorded `case`, run as `words`, under `principal`, `ctx` and `facts`.
fn diagnosed(
    case: &str,
    words: &str,
    principal: Principal,
    ctx: &DiagnoseContext,
    facts: &Facts,
) -> Cause {
    let (stderr, exit) = recorded(case);
    diagnose_with(observed(words, exit, principal), &stderr, ctx, facts)
}

fn case_02() -> Cause {
    diagnosed(
        "02-account-not-on-machine",
        "whoami --account ZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        person(),
        &DiagnoseContext::default(),
        &Facts::default(),
    )
}

fn case_03() -> Cause {
    diagnosed(
        "03-service-account-token-rejected",
        "whoami",
        service_account_token(),
        &DiagnoseContext::default(),
        &Facts::default(),
    )
}

fn case_04(facts: &Facts) -> Cause {
    diagnosed(
        "04-op-account-overrides-signout-all",
        "signout --all",
        person(),
        &DiagnoseContext::default(),
        facts,
    )
}

fn case_11(facts: &Facts) -> Cause {
    diagnosed(
        "11-b-whoami-under-a-session",
        &format!("whoami --account {B} --format json"),
        person(),
        &in_account(B),
        facts,
    )
}

fn case_12(facts: &Facts) -> Cause {
    diagnosed(
        "12-b-vault-list-under-a-session",
        &format!("vault list --account {B} --format json"),
        person(),
        &in_account(B),
        facts,
    )
}

fn case_14(facts: &Facts) -> Cause {
    diagnosed(
        "14-vault-in-other-account",
        &format!("vault get <VAULT_B> --account {A} --format json"),
        person(),
        &in_account(A),
        facts,
    )
}

fn case_15() -> Cause {
    diagnosed(
        "15-vault-user-list-in-other-account",
        &format!("vault user list <VAULT_B> --account {A} --format json"),
        person(),
        &in_account(A),
        &Facts::default(),
    )
}

// --- one test per recorded case --------------------------------------------------------------

#[test]
fn recording_02_account_not_on_machine_is_account_not_registered() {
    assert_eq!(case_02().code(), "account_not_registered");
}

#[test]
fn recording_03_invalid_service_account_token_is_credential_rejected() {
    assert_eq!(case_03().code(), "credential_rejected");
}

#[test]
fn recording_04_op_account_with_signout_all_is_credential_rejected() {
    assert_eq!(case_04(&op_account_set()).code(), "credential_rejected");
}

#[test]
fn recording_05_signed_out_whoami_is_not_signed_in() {
    let cause = diagnosed(
        "05-signed-out-whoami",
        &format!("whoami --account {A}"),
        person(),
        &in_account(A),
        &Facts::default(),
    );
    assert_eq!(cause.code(), "op_not_signed_in");
}

#[test]
fn recording_06_signed_out_vault_list_is_not_signed_in() {
    let cause = diagnosed(
        "06-signed-out-vault-list",
        &format!("vault list --account {A} --format json"),
        person(),
        &in_account(A),
        &Facts::default(),
    );
    assert_eq!(cause.code(), "op_not_signed_in");
}

#[test]
fn recording_07_signed_out_item_get_is_not_signed_in() {
    let cause = diagnosed(
        "07-signed-out-item-get",
        &format!("item get opv-recording-none --account {A} --format json"),
        person(),
        &in_account(A),
        &Facts::default(),
    );
    assert_eq!(cause.code(), "op_not_signed_in");
}

#[test]
fn recording_08_vault_not_in_the_selected_account_is_ids_not_in_account() {
    let cause = diagnosed(
        "08-vault-not-found",
        &format!("vault get ZZZZZZZZZZZZZZZZZZZZZZZZZZ --account {A} --format json"),
        person(),
        &in_account(A),
        &Facts::default(),
    );
    assert_eq!(cause.code(), "ids_not_in_account");
}

#[test]
fn recording_09_item_not_found_is_item_not_found() {
    let cause = diagnosed(
        "09-item-not-found",
        &format!("item get opv-recording-none --vault <VAULT_A> --account {A} --format json"),
        person(),
        &in_account(A),
        &Facts::default(),
    );
    assert_eq!(cause.code(), "item_not_found");
}

#[test]
fn recording_11_b_whoami_under_a_session_is_not_signed_in() {
    assert_eq!(case_11(&live(A)).code(), "op_not_signed_in");
}

#[test]
fn recording_12_b_vault_list_under_a_session_is_not_signed_in() {
    assert_eq!(case_12(&live(A)).code(), "op_not_signed_in");
}

#[test]
fn recording_14_vault_of_other_account_is_ids_not_in_account() {
    assert_eq!(case_14(&Facts::default()).code(), "ids_not_in_account");
}

#[test]
fn recording_15_vault_user_list_of_other_account_is_ids_not_in_account() {
    assert_eq!(case_15().code(), "ids_not_in_account");
}

// --- one test per rule -----------------------------------------------------------------------

#[test]
fn account_not_on_machine_names_the_account_given_with_the_flag() {
    assert!(matches!(
        case_02(),
        Cause::AccountNotOnMachine { account: AccountRef::Id(id), .. }
            if id.as_str() == "ZZZZZZZZZZZZZZZZZZZZZZZZZZ"
    ));
}

#[test]
fn account_not_on_machine_was_selected_by_the_flag() {
    assert!(matches!(
        case_02(),
        Cause::AccountNotOnMachine {
            selected_by: AccountSource::Flag,
            ..
        }
    ));
}

#[test]
fn rejected_service_account_token_names_its_variable() {
    assert!(matches!(
        case_03(),
        Cause::CredentialRejected {
            credential: CredentialRef::ServiceAccountToken { var },
            ..
        } if var.as_str() == "OP_SERVICE_ACCOUNT_TOKEN"
    ));
}

#[test]
fn flag_conflict_under_op_account_is_overridden_by_op_account() {
    assert!(matches!(
        case_04(&op_account_set()),
        Cause::CredentialRejected {
            problem: CredentialProblem::OverriddenByEnvironment { var },
            ..
        } if var.as_str() == "OP_ACCOUNT"
    ));
}

#[test]
fn flag_conflict_without_op_account_is_unrecognized() {
    assert_eq!(case_04(&Facts::default()).code(), "unrecognized_failure");
}

#[test]
fn no_active_session_without_a_live_session_is_signed_out() {
    assert!(matches!(
        case_11(&Facts::default()),
        Cause::NotSignedIn {
            state: SessionState::SignedOut,
            ..
        }
    ));
}

#[test]
fn no_active_session_with_a_session_for_another_account_names_it() {
    assert!(matches!(
        case_11(&live(A)),
        Cause::NotSignedIn {
            state: SessionState::OtherAccount { live },
            ..
        } if live.as_str() == A
    ));
}

#[test]
fn not_currently_signed_in_with_a_session_for_another_account_names_it() {
    assert!(matches!(
        case_12(&live(A)),
        Cause::NotSignedIn {
            state: SessionState::OtherAccount { live },
            ..
        } if live.as_str() == A
    ));
}

#[test]
fn a_live_session_for_the_asked_account_is_not_another_account() {
    assert!(matches!(
        case_11(&live(B)),
        Cause::NotSignedIn {
            state: SessionState::SignedOut,
            ..
        }
    ));
}

#[test]
fn not_signed_in_names_the_asked_account() {
    assert!(matches!(
        case_11(&live(A)),
        Cause::NotSignedIn { account: Some(account), .. } if account.as_str() == B
    ));
}

#[test]
fn vault_in_other_account_names_the_selected_account() {
    assert!(matches!(
        case_14(&Facts::default()),
        Cause::InOtherAccount { selected, .. } if selected.as_str() == A
    ));
}

#[test]
fn vault_in_other_account_names_the_vault_of_vault_user_list() {
    assert!(matches!(
        case_15(),
        Cause::InOtherAccount { vault, .. } if vault == VaultId::new("<VAULT_B>")
    ));
}

#[test]
fn vault_in_other_account_has_no_owner_before_it_is_located() {
    assert!(matches!(
        case_14(&Facts::default()),
        Cause::InOtherAccount { owning: None, .. }
    ));
}

// --- #153a: the owner of a vault in another account ------------------------------------------

fn located(search: VaultSearch) -> Cause {
    placed(case_14(&Facts::default()), &search)
}

#[test]
fn vault_in_other_account_names_the_account_that_holds_it() {
    assert!(matches!(
        located(VaultSearch::FoundIn(AccountId::new(B))),
        Cause::InOtherAccount { owning: Some(owner), .. } if owner.as_str() == B
    ));
}

#[test]
fn vault_in_other_account_found_leaves_no_account_unasked() {
    assert!(matches!(
        located(VaultSearch::FoundIn(AccountId::new(B))),
        Cause::InOtherAccount { unasked, .. } if unasked.is_empty()
    ));
}

#[test]
fn vault_found_in_another_account_is_marked_searched() {
    assert!(matches!(
        located(VaultSearch::FoundIn(AccountId::new(B))),
        Cause::InOtherAccount { searched: true, .. }
    ));
}

#[test]
fn vault_in_no_account_on_the_machine_is_marked_searched() {
    assert!(matches!(
        located(VaultSearch::Nowhere {
            unasked: Vec::new()
        }),
        Cause::InOtherAccount { searched: true, .. }
    ));
}

#[test]
fn vault_in_no_account_on_the_machine_has_no_account_unasked() {
    assert!(matches!(
        located(VaultSearch::Nowhere {
            unasked: Vec::new()
        }),
        Cause::InOtherAccount { unasked, .. } if unasked.is_empty()
    ));
}

#[test]
fn vault_not_searched_when_op_lists_no_accounts_is_not_marked_searched() {
    assert!(matches!(
        located(VaultSearch::NotSearched),
        Cause::InOtherAccount {
            searched: false,
            ..
        }
    ));
}

#[test]
fn vault_no_askable_account_holds_has_no_owner() {
    assert!(matches!(
        located(VaultSearch::Nowhere {
            unasked: vec![AccountId::new(B)]
        }),
        Cause::InOtherAccount { owning: None, .. }
    ));
}

#[test]
fn vault_no_askable_account_holds_names_the_accounts_not_asked() {
    assert!(matches!(
        located(VaultSearch::Nowhere {
            unasked: vec![AccountId::new(B)]
        }),
        Cause::InOtherAccount { unasked, .. } if unasked == [AccountId::new(B)]
    ));
}

#[test]
fn vault_in_other_account_stays_ids_not_in_account_once_located() {
    assert_eq!(
        located(VaultSearch::FoundIn(AccountId::new(B))).code(),
        "ids_not_in_account"
    );
}

#[test]
fn a_search_op_cannot_list_accounts_for_is_not_searched() {
    let r = FakeRunner::new([Output::failure(1)]);
    assert_eq!(
        search_vault(&r, &VaultId::new("<VAULT_B>"), &AccountId::new(A)),
        VaultSearch::NotSearched
    );
}

#[test]
fn vault_with_no_account_selected_is_not_found() {
    let cause = diagnosed(
        "14-vault-in-other-account",
        "vault get <VAULT_B> --format json",
        person(),
        &DiagnoseContext::default(),
        &Facts::default(),
    );
    assert_eq!(cause.code(), "resource_not_found");
}

#[test]
fn item_not_found_names_the_item_of_item_get() {
    let cause = diagnosed(
        "09-item-not-found",
        &format!("item get opv-recording-none --vault <VAULT_A> --account {A} --format json"),
        person(),
        &in_account(A),
        &Facts::default(),
    );
    assert!(matches!(
        cause,
        Cause::NotFound { resource, .. } if resource.name.as_str() == "opv-recording-none"
    ));
}

#[test]
fn timed_out_create_is_create_outcome_unknown() {
    let ctx = DiagnoseContext {
        create: Some((CreateKind::Item, "deploy".to_string(), Refind::ByTitle)),
        ..DiagnoseContext::default()
    };
    let seen = observed("item create", ExitClass::TimedOut, person());
    assert_eq!(
        diagnose_with(seen, "", &ctx, &Facts::default()).code(),
        "create_outcome_unknown"
    );
}

#[test]
fn timed_out_write_is_outcome_unknown() {
    let ctx = DiagnoseContext {
        write: true,
        ..DiagnoseContext::default()
    };
    let seen = observed("item edit", ExitClass::TimedOut, person());
    assert_eq!(
        diagnose_with(seen, "", &ctx, &Facts::default()).code(),
        "outcome_unknown"
    );
}

#[test]
fn timed_out_read_is_provider_unavailable() {
    let seen = observed("vault list", ExitClass::TimedOut, person());
    assert_eq!(
        diagnose_with(seen, "", &DiagnoseContext::default(), &Facts::default()).code(),
        "provider_unavailable"
    );
}

#[test]
fn signalled_read_is_provider_unavailable() {
    let seen = observed("vault list", ExitClass::Signal { signal: 15 }, person());
    assert_eq!(
        diagnose_with(seen, "", &DiagnoseContext::default(), &Facts::default()).code(),
        "provider_unavailable"
    );
}

#[test]
fn a_timeout_wins_over_a_recorded_phrase() {
    let (stderr, _) = recorded("05-signed-out-whoami");
    let seen = observed("whoami", ExitClass::TimedOut, person());
    assert_eq!(
        diagnose_with(
            seen,
            &stderr,
            &DiagnoseContext::default(),
            &Facts::default()
        )
        .code(),
        "provider_unavailable"
    );
}

#[test]
fn an_empty_reply_is_unrecognized() {
    let seen = observed("vault list", ExitClass::Code { code: 1 }, person());
    assert_eq!(
        diagnose_with(seen, "", &DiagnoseContext::default(), &Facts::default()).code(),
        "unrecognized_failure"
    );
}

#[test]
fn unrecognized_records_the_live_session() {
    let seen = observed("vault list", ExitClass::Code { code: 1 }, person());
    assert!(matches!(
        diagnose_with(seen, "", &DiagnoseContext::default(), &live(A)),
        Cause::Unrecognized { established, .. }
            if established.iter().any(|f| f.contains(A))
    ));
}

// --- the #160 probe --------------------------------------------------------------------------

/// The recorded `whoami` reply with its account marker made an ID again: the markers stand
/// for 1Password account IDs (letters and digits), which is all the probe accepts.
fn whoami_of_a() -> Output {
    Output::success(fixture("10-whoami-a.stdout").replace(A, "ACCOUNT2"))
}

fn account_b() -> AccountId {
    AccountId::new("ACCOUNT1")
}

/// `whoami --account B` fails with the recorded case 11 reply, then `whoami` is `reply`.
fn b_under(reply: Output) -> FakeRunner {
    let r = FakeRunner::default();
    r.push_with_stderr(
        Output::failure(1),
        &fixture("11-b-whoami-under-a-session.stderr").replace(B, "ACCOUNT1"),
    );
    r.push_with_stderr(reply, "");
    r
}

#[test]
fn probe_finds_the_live_session_of_another_account() {
    let r = b_under(whoami_of_a());
    assert_eq!(
        session_for(&r, &account_b()),
        SessionCheck::OtherAccountLive {
            live: AccountId::new("ACCOUNT2")
        }
    );
}

#[test]
fn probe_with_no_session_at_all_is_not_signed_in() {
    let r = b_under(Output::failure(1));
    assert_eq!(session_for(&r, &account_b()), SessionCheck::NotSignedIn);
}

#[test]
fn probe_asks_for_the_account_with_whoami() {
    let r = b_under(whoami_of_a());
    session_for(&r, &account_b());
    assert_eq!(
        r.calls.borrow()[0].args,
        ["whoami", "--account", "ACCOUNT1", "--format", "json"]
    );
}

#[test]
fn probe_asks_plain_whoami_with_op_account_emptied() {
    let r = b_under(whoami_of_a());
    session_for(&r, &account_b());
    assert_eq!(
        r.calls.borrow()[1].env,
        [("OP_ACCOUNT".to_string(), String::new())]
    );
}

#[test]
fn probe_sends_no_stdin() {
    let r = b_under(whoami_of_a());
    session_for(&r, &account_b());
    assert!(r.calls.borrow().iter().all(|c| c.stdin.is_none()));
}

#[test]
fn probe_signed_in_to_the_account_is_signed_in() {
    let r = FakeRunner::new([whoami_of_a()]);
    assert_eq!(
        session_for(&r, &AccountId::new("ACCOUNT2")),
        SessionCheck::SignedIn
    );
}

#[test]
fn probe_not_currently_signed_in_is_not_signed_in() {
    let r = FakeRunner::default();
    r.push_with_stderr(
        Output::failure(1),
        &fixture("12-b-vault-list-under-a-session.stderr"),
    );
    assert_eq!(session_for(&r, &account_b()), SessionCheck::NotSignedIn);
}

#[test]
fn probe_that_does_not_finish_is_undetermined() {
    let r = FakeRunner::default();
    r.push_unknown("timeout");
    assert_eq!(session_for(&r, &account_b()), SessionCheck::Undetermined);
}

#[test]
fn probe_with_an_unrecorded_reply_is_undetermined() {
    let r = FakeRunner::default();
    r.push_with_stderr(Output::failure(1), "");
    assert_eq!(session_for(&r, &account_b()), SessionCheck::Undetermined);
}
