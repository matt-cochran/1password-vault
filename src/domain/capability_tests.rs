//! Capability per vault (design Part V, row `capability`): one behavioural outcome per
//! recorded reply. Every test reads a recording under `tests/fixtures/op`; no op output is
//! invented. The refusal cases are diagnosed through the same item/vault strategy
//! `access_tests.rs` uses, then classified by [`from_refusal`].

use super::capability::{Capability, UnknownSource, classify, from_refusal};
use crate::adapters::onepassword_diagnose::Facts;
use crate::adapters::onepassword_diagnose_items::diagnose_item_call;
use crate::cause::{
    AccountId, CallId, Cause, DiagnoseContext, ExitClass, Observed, Principal, ResourceKind,
    ResourceName, ResourceRef, System,
};

const S20_WHOAMI: &str = include_str!("../../tests/fixtures/op/success/s20-whoami.stdout");
const S04_USERS: &str = include_str!("../../tests/fixtures/op/success/s04-vault-user-list.stdout");
const S06_WHOAMI: &str = include_str!("../../tests/fixtures/op/success/s06-whoami-a.stdout");
const S23_USERS: &str =
    include_str!("../../tests/fixtures/op/success/s23-writer-vault-user-list.stdout");

const F08: &str = include_str!("../../tests/fixtures/op/failures/08-vault-not-found.stderr");
const F14: &str = include_str!("../../tests/fixtures/op/failures/14-vault-in-other-account.stderr");
const F15: &str =
    include_str!("../../tests/fixtures/op/failures/15-vault-user-list-in-other-account.stderr");

/// The project's account in the recordings (`<ACCOUNT_2>`).
const ACCOUNT: &str = "<ACCOUNT_2>";

fn value(text: &str) -> serde_json::Value {
    serde_json::from_str(text).expect("a recorded reply is JSON")
}

/// The session's `user_uuid` named by a recorded `op whoami` reply.
fn session_user(whoami: &str) -> String {
    value(whoami)["user_uuid"]
        .as_str()
        .expect("a recorded whoami names its user")
        .to_string()
}

/// The cause a recorded refusal is diagnosed as, with the vault named by the context (the
/// recorded replies carry only the marker `<VAULT_B>`/`ZZZ…`). With an account selected the
/// vault is in another account ([`Cause::InOtherAccount`]); without one it is not found
/// ([`Cause::NotFound`]).
fn diagnosed(stderr: &str, words: &str, account: Option<&str>) -> Cause {
    let call = CallId {
        system: System::OnePassword,
        program: "op".to_string(),
        words: words.split_whitespace().map(str::to_string).collect(),
    };
    let seen = Observed::from_failed_call(
        call,
        ExitClass::Code { code: 1 },
        Principal::Person { account: None },
    );
    let ctx = DiagnoseContext {
        account: account.map(AccountId::new),
        resource: Some(ResourceRef {
            kind: ResourceKind::Vault,
            name: ResourceName::new("<VAULT_B>"),
            scope: None,
        }),
        ..DiagnoseContext::default()
    };
    diagnose_item_call(seen, stderr, &ctx, &Facts::default())
}

// --- classify: recorded success replies --------------------------------------------

#[test]
fn a_writer_in_the_recorded_vault_user_list_is_write() {
    let users = value(S23_USERS);
    assert_eq!(
        classify(Some(&users), &session_user(S20_WHOAMI)),
        Capability::Write
    );
}

#[test]
fn a_member_with_editing_in_the_recorded_vault_user_list_is_write() {
    let users = value(S04_USERS);
    assert_eq!(
        classify(Some(&users), &session_user(S06_WHOAMI)),
        Capability::Write
    );
}

#[test]
fn a_recorded_vault_user_list_without_the_session_user_is_none() {
    let users = value(S04_USERS);
    assert_eq!(
        classify(Some(&users), &session_user(S20_WHOAMI)),
        Capability::None
    );
}

#[test]
fn a_recorded_entry_without_a_permissions_list_is_unknown() {
    let mut users = value(S04_USERS);
    let me = session_user(S06_WHOAMI);
    users
        .as_array_mut()
        .expect("a recorded user list is an array")
        .iter_mut()
        .find(|user| user.get("id").and_then(|id| id.as_str()) == Some(me.as_str()))
        .expect("the session's own entry")
        .as_object_mut()
        .expect("an entry is an object")
        .remove("permissions");
    assert_eq!(
        classify(Some(&users), &me),
        Capability::Unknown {
            source: UnknownSource::NoPermissionsInReply
        }
    );
}

// --- from_refusal: recorded refusals -----------------------------------------------

#[test]
fn a_recorded_other_account_vault_refusal_is_none() {
    let cause = diagnosed(
        F14,
        &format!("vault get <VAULT_B> --account {ACCOUNT} --format json"),
        Some(ACCOUNT),
    );
    assert_eq!(from_refusal(&cause), Some(Capability::None));
}

#[test]
fn a_recorded_other_account_user_list_refusal_is_none() {
    let cause = diagnosed(
        F15,
        &format!("vault user list <VAULT_B> --account {ACCOUNT} --format json"),
        Some(ACCOUNT),
    );
    assert_eq!(from_refusal(&cause), Some(Capability::None));
}

#[test]
fn a_recorded_not_found_vault_refusal_is_none() {
    let cause = diagnosed(F08, "vault get <VAULT_B> --format json", None);
    assert_eq!(from_refusal(&cause), Some(Capability::None));
}
