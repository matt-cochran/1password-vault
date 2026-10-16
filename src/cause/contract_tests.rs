//! The catalog contract: derived classifications (design §4, §6.3). One assertion each.

use super::*;

fn observed() -> Observed {
    Observed::from_failed_call(
        CallId {
            system: System::OnePassword,
            program: "op".into(),
            words: vec!["vault".into(), "get".into()],
        },
        ExitClass::Code { code: 1 },
        Principal::Person { account: None },
    )
}

#[test]
fn a_vault_in_another_account_is_ids_not_in_account() {
    let c = Cause::InOtherAccount {
        vault: VaultId::new("v1"),
        item: None,
        selected: AccountId::new("A1"),
        owning: None,
        env: None,
        seen: observed(),
    };
    assert_eq!(c.code(), "ids_not_in_account");
}

#[test]
fn a_vault_in_another_account_exits_as_an_account_problem() {
    let c = Cause::InOtherAccount {
        vault: VaultId::new("v1"),
        item: None,
        selected: AccountId::new("A1"),
        owning: None,
        env: None,
        seen: observed(),
    };
    assert_eq!(c.exit_code(), 7);
}

#[test]
fn an_unknown_secret_bearing_create_is_check_first() {
    let c = Cause::CreateOutcomeUnknown {
        system: System::OnePassword,
        kind: CreateKind::ServiceAccount,
        name: "web-deploy".into(),
        refind: Refind::Check(Cmd {
            command: vec!["access".into()],
            args: vec!["prod".into()],
        }),
        seen: observed(),
    };
    assert_eq!(c.retry(), RetryClass::CheckFirst);
}

#[test]
fn a_create_opv_finds_again_by_title_is_safe_to_rerun() {
    let c = Cause::CreateOutcomeUnknown {
        system: System::OnePassword,
        kind: CreateKind::Vault,
        name: "shop-prod".into(),
        refind: Refind::ByTitle,
        seen: observed(),
    };
    assert_eq!(c.retry(), RetryClass::Safe);
}

#[test]
fn a_partial_failure_keeps_the_inner_code() {
    let c = Cause::Partial {
        done: vec!["vault shop-prod".into()],
        approval_used: None,
        approval_scope: None,
        then: Box::new(Cause::BudgetSpent {
            budget_seconds: 60,
            writes_started: true,
        }),
    };
    assert_eq!(c.code(), "budget_spent");
}

#[test]
fn a_partial_failure_is_check_first() {
    let c = Cause::Partial {
        done: vec![],
        approval_used: None,
        approval_scope: None,
        then: Box::new(Cause::Interrupted {
            signal: 2,
            writes_started: true,
        }),
    };
    assert_eq!(c.retry(), RetryClass::CheckFirst);
}

#[test]
fn a_bug_exits_70() {
    assert_eq!(Cause::Bug { site: "test" }.exit_code(), EXIT_INTERNAL);
}

#[test]
fn a_declined_prompt_exits_0() {
    assert_eq!(
        Cause::Guard {
            guard: Guard::Declined
        }
        .exit_code(),
        0
    );
}

#[test]
fn a_target_sign_in_is_not_a_1password_sign_in() {
    let c = Cause::NotSignedIn {
        system: System::Fly,
        account: None,
        state: SessionState::Expired,
    };
    assert_eq!(c.code(), "target_not_signed_in");
}

#[test]
fn a_live_session_for_another_account_is_not_signed_in_to_the_one_asked_for() {
    let c = Cause::NotSignedIn {
        system: System::OnePassword,
        account: Some(AccountId::new("B")),
        state: SessionState::OtherAccount {
            live: AccountId::new("A"),
        },
    };
    assert_eq!(c.code(), "op_not_signed_in");
}

#[test]
fn closest_is_none_when_two_names_are_close() {
    assert!(Closest::unique(&["prod", "prd"]).is_none());
}

#[test]
fn granting_a_right_is_person_only() {
    let a = Action::Grant {
        principal: Principal::Person { account: None },
        resource: ResourceRef {
            kind: ResourceKind::Vault,
            name: ResourceName::new("v1"),
            scope: None,
        },
        grant: GrantModel::VaultPermission,
    };
    assert!(a.person_only());
}

#[test]
fn inspecting_is_not_person_only() {
    assert!(!Action::Inspect.person_only());
}

#[test]
fn an_external_cause_carries_what_the_runner_observed() {
    let c = Cause::Unavailable {
        system: System::Fly,
        why: Unanswered::Timeout,
        attempts: 3,
        seen: observed(),
    };
    assert!(c.observed().is_some());
}
