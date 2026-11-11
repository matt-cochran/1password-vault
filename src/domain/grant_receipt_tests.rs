//! CI reader grant receipts (#304, FR-70): one behavioural outcome per test, observed through
//! the public API. Ids are placeholders; no value exists in this model.

use super::*;
use crate::domain::access_plan::Principal;

const WHOAMI: &str =
    include_str!("../../tests/fixtures/op/success/s30-whoami-service-account.stdout");
const VAULT_LIST: &str =
    include_str!("../../tests/fixtures/op/success/s31-vault-list-service-account.stdout");

const TODAY: &str = "2026-11-11";

fn grant(vault: &str, permission: Permission) -> Grant {
    Grant {
        principal: Principal::CiReader {
            environment: "prod".into(),
        },
        service_account: "p-ci-ci-20261111".into(),
        vault_id: vault.into(),
        permission,
    }
}

/// The contract's grants: read on vaults A and B.
fn required() -> Vec<Grant> {
    vec![grant("VA", Permission::Read), grant("VB", Permission::Read)]
}

/// A receipt issued for [`required`] that the [`observed`] token matches.
fn receipt() -> GrantReceipt {
    GrantReceipt {
        schema: SCHEMA.into(),
        account_id: "ACC".into(),
        service_account_user_id: "USR".into(),
        service_account_name: "p-ci-ci-20261111".into(),
        vaults: vec![
            ReceiptVault {
                id: "VA".into(),
                permissions: vec!["read_items".into()],
            },
            ReceiptVault {
                id: "VB".into(),
                permissions: vec!["read_items".into()],
            },
        ],
        issued_at: "2026-11-11T10:24:11Z".into(),
        issued_by: IssuedBy::Create,
        expires_on: "2027-02-09".into(),
        contract_grants: contract_grants(&required()),
    }
}

fn observed() -> Observations {
    Observations {
        identity: ProviderRead::Complete(Identity {
            user_id: "USR".into(),
            account_id: "ACC".into(),
            user_type: SERVICE_ACCOUNT.into(),
        }),
        vaults: ProviderRead::Complete(["VA".to_string(), "VB".to_string()].into()),
    }
}

fn with_identity(change: impl FnOnce(&mut Identity)) -> Observations {
    let mut seen = observed();
    if let ProviderRead::Complete(identity) = &mut seen.identity {
        change(identity);
    }
    seen
}

fn with_vaults(ids: &[&str]) -> Observations {
    Observations {
        vaults: ProviderRead::Complete(ids.iter().map(|s| s.to_string()).collect()),
        ..observed()
    }
}

#[test]
fn a_matching_receipt_passes() {
    assert!(evaluate(Some(&receipt()), &required(), &observed(), TODAY).passes());
}

#[test]
fn a_missing_receipt_is_receipt_missing() {
    assert_eq!(
        evaluate(None, &required(), &observed(), TODAY).receipt,
        Outcome::NotVerified(Reason::ReceiptMissing)
    );
}

#[test]
fn a_missing_receipt_does_not_pass() {
    assert!(!evaluate(None, &required(), &observed(), TODAY).passes());
}

#[test]
fn a_receipt_of_another_schema_is_receipt_invalid() {
    let r = GrantReceipt {
        schema: "opv.grant-receipt/0".into(),
        ..receipt()
    };
    assert_eq!(
        evaluate(Some(&r), &required(), &observed(), TODAY).receipt,
        Outcome::NotVerified(Reason::ReceiptInvalid)
    );
}

#[test]
fn a_token_in_another_account_is_wrong_account() {
    let seen = with_identity(|i| i.account_id = "OTHER".into());
    assert_eq!(
        evaluate(Some(&receipt()), &required(), &seen, TODAY).identity,
        Outcome::NotVerified(Reason::WrongAccount)
    );
}

#[test]
fn another_service_account_is_identity_mismatch() {
    let seen = with_identity(|i| i.user_id = "OTHER".into());
    assert_eq!(
        evaluate(Some(&receipt()), &required(), &seen, TODAY).identity,
        Outcome::NotVerified(Reason::IdentityMismatch)
    );
}

#[test]
fn a_person_token_is_not_a_service_account() {
    let seen = with_identity(|i| i.user_type = "HUMAN".into());
    assert_eq!(
        evaluate(Some(&receipt()), &required(), &seen, TODAY).identity,
        Outcome::NotVerified(Reason::NotAServiceAccount)
    );
}

#[test]
fn an_incomplete_identity_read_is_provider_read_incomplete() {
    let seen = Observations {
        identity: ProviderRead::Incomplete,
        ..observed()
    };
    assert_eq!(
        evaluate(Some(&receipt()), &required(), &seen, TODAY).identity,
        Outcome::NotVerified(Reason::ProviderReadIncomplete)
    );
}

#[test]
fn an_incomplete_vault_read_is_provider_read_incomplete() {
    let seen = Observations {
        vaults: ProviderRead::Incomplete,
        ..observed()
    };
    assert_eq!(
        evaluate(Some(&receipt()), &required(), &seen, TODAY).vault_set,
        Outcome::NotVerified(Reason::ProviderReadIncomplete)
    );
}

#[test]
fn an_extra_vault_is_extra_vault() {
    let seen = with_vaults(&["VA", "VB", "VC"]);
    assert_eq!(
        evaluate(Some(&receipt()), &required(), &seen, TODAY).vault_set,
        Outcome::NotVerified(Reason::ExtraVault)
    );
}

#[test]
fn a_missing_vault_is_missing_vault() {
    let seen = with_vaults(&["VA"]);
    assert_eq!(
        evaluate(Some(&receipt()), &required(), &seen, TODAY).vault_set,
        Outcome::NotVerified(Reason::MissingVault)
    );
}

#[test]
fn a_changed_contract_is_contract_changed() {
    let now = vec![grant("VA", Permission::Read)];
    assert_eq!(
        evaluate(Some(&receipt()), &now, &observed(), TODAY).contract,
        Outcome::NotVerified(Reason::ContractChanged)
    );
}

#[test]
fn an_issued_write_permission_is_write_permission() {
    let mut r = receipt();
    r.vaults[0].permissions.push("write_items".into());
    assert_eq!(
        evaluate(Some(&r), &required(), &observed(), TODAY).permissions_issued,
        Outcome::NotVerified(Reason::WritePermission)
    );
}

#[test]
fn an_expired_receipt_is_expired() {
    let r = GrantReceipt {
        expires_on: TODAY.into(),
        ..receipt()
    };
    assert_eq!(
        evaluate(Some(&r), &required(), &observed(), TODAY).freshness,
        Outcome::NotVerified(Reason::Expired)
    );
}

#[test]
fn permissions_live_is_not_supported() {
    assert_eq!(
        evaluate(Some(&receipt()), &required(), &observed(), TODAY).permissions_live,
        Outcome::NotSupported
    );
}

#[test]
fn the_digest_does_not_depend_on_grant_order() {
    let reversed: Vec<Grant> = required().into_iter().rev().collect();
    assert_eq!(contract_grants(&reversed), contract_grants(&required()));
}

#[test]
fn the_digest_changes_when_a_permission_changes() {
    let widened = vec![
        grant("VA", Permission::ReadWrite),
        grant("VB", Permission::Read),
    ];
    assert_ne!(contract_grants(&widened), contract_grants(&required()));
}

#[test]
fn a_receipt_round_trips_through_toml() {
    assert_eq!(GrantReceipt::from_toml(&receipt().to_toml()), Ok(receipt()));
}

#[test]
fn the_recorded_identity_reply_parses_as_a_service_account() {
    let ProviderRead::Complete(identity) = parse_whoami(WHOAMI) else {
        panic!("the recorded reply is complete");
    };
    assert_eq!(identity.user_type, SERVICE_ACCOUNT);
}

#[test]
fn the_recorded_vault_list_parses_its_ids() {
    assert_eq!(
        parse_vault_list(VAULT_LIST),
        ProviderRead::Complete(["<VAULT_A>".to_string()].into())
    );
}

#[test]
fn a_vault_entry_without_an_id_makes_the_list_incomplete() {
    assert_eq!(
        parse_vault_list(r#"[{"id":"VA"},{"name":"x"}]"#),
        ProviderRead::Incomplete
    );
}

#[test]
fn a_report_serialises_reasons_by_their_fixed_names() {
    let json = serde_json::to_value(evaluate(None, &required(), &observed(), TODAY)).unwrap();
    assert_eq!(
        json["receipt"],
        serde_json::json!({"state": "not_verified", "reason": "receipt_missing"})
    );
}

#[test]
fn issued_names_that_differ_from_the_contract_are_permission_mismatch() {
    let now = vec![
        grant("VA", Permission::ReadWrite),
        grant("VB", Permission::Read),
    ];
    assert_eq!(
        evaluate(Some(&receipt()), &now, &observed(), TODAY).permissions_issued,
        Outcome::NotVerified(Reason::PermissionMismatch)
    );
}

/// A target's CI identity writes its own state vault: the write the contract asks for there
/// is no `write_permission`.
#[test]
fn a_write_the_contract_asks_for_is_verified() {
    let now = vec![
        grant("VA", Permission::ReadWrite),
        grant("VB", Permission::Read),
    ];
    let mut r = receipt();
    r.vaults[0].permissions.push("write_items".into());
    assert_eq!(
        evaluate(Some(&r), &now, &observed(), TODAY).permissions_issued,
        Outcome::Verified
    );
}
