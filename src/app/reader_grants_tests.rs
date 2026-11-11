use super::*;
use crate::runner::{Output, fake::FakeRunner};
const ACCOUNT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
const USER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbb";
const VAULT: &str = "cccccccccccccccccccccccccc";
const TOKEN: &str = "ops_FAKE304_SECRET_MARKER";

fn fleet() -> Fleet {
    crate::config::parse(&format!(
        r#"
[environments.test]
account = "{ACCOUNT}"
boundaries.app = {{ vault_id = "{VAULT}", item_id = "dddddddddddddddddddddddddd" }}
[products.app.keys.KEY]
kind = "secret"
environments = ["test"]
"#
    ))
    .unwrap()
}
fn native(user_type: &str, user: &str, account: &str) -> Output {
    Output::success(
        serde_json::json!({"user_type":user_type,"user_uuid":user,"account_uuid":account})
            .to_string(),
    )
}
fn receipt() -> Receipt {
    let c = contract(&fleet(), "test").unwrap();
    let r = FakeRunner::new(vec![native("SERVICE_ACCOUNT", USER, ACCOUNT)]);
    issued(&c, &SecretValue::new(TOKEN.into()), &r).unwrap()
}
fn bytes(r: &Receipt) -> Vec<u8> {
    serde_json::to_vec(r).unwrap()
}

#[test]
fn native_immutable_issuance_is_accepted() {
    let r = receipt();
    let b = bytes(&r);
    assert!(validate(&r.contract, &b, &digest(&b), r.issued_at + 1).is_ok());
}
#[test]
fn tampered_receipt_is_not_trusted() {
    let r = receipt();
    let b = bytes(&r);
    assert_eq!(
        validate(&r.contract, &b, &"0".repeat(64), r.issued_at).unwrap_err(),
        "untrusted_or_tampered_receipt"
    );
}
#[test]
fn future_receipt_is_rejected() {
    let r = receipt();
    let b = bytes(&r);
    assert_eq!(
        validate(&r.contract, &b, &digest(&b), r.issued_at - 1).unwrap_err(),
        "receipt_stale_or_future"
    );
}
#[test]
fn expired_receipt_is_rejected() {
    let r = receipt();
    let b = bytes(&r);
    assert_eq!(
        validate(&r.contract, &b, &digest(&b), r.not_after).unwrap_err(),
        "receipt_stale_or_future"
    );
}
#[test]
fn validity_wider_than_closed_issuance_is_rejected() {
    let mut r = receipt();
    r.not_after += 1;
    let b = bytes(&r);
    assert_eq!(
        validate(&r.contract, &b, &digest(&b), r.issued_at).unwrap_err(),
        "receipt_stale_or_future"
    );
}
#[test]
fn unsupported_revisions_fail_closed() {
    let mut r = receipt();
    r.revision += 1;
    let b = bytes(&r);
    assert_eq!(
        validate(&r.contract, &b, &digest(&b), r.issued_at).unwrap_err(),
        "receipt_not_supported"
    );
}
#[test]
fn unsupported_schema_fails_closed() {
    let mut r = receipt();
    r.receipt_schema += 1;
    let b = bytes(&r);
    assert_eq!(
        validate(&r.contract, &b, &digest(&b), r.issued_at).unwrap_err(),
        "receipt_not_supported"
    );
}
#[test]
fn wrong_contract_identity_is_rejected() {
    let mut r = receipt();
    r.contract_sha256 = "0".repeat(64);
    let b = bytes(&r);
    assert_eq!(
        validate(&r.contract, &b, &digest(&b), r.issued_at).unwrap_err(),
        "contract_mismatch"
    );
}
#[test]
fn extra_runtime_vault_is_rejected() {
    let mut r = receipt();
    let expected = r.contract.clone();
    r.contract.vaults.push(VaultGrant {
        vault_id: USER.into(),
        permissions: vec!["read_items".into()],
    });
    let b = bytes(&r);
    assert_eq!(
        validate(&expected, &b, &digest(&b), r.issued_at).unwrap_err(),
        "contract_mismatch"
    );
}
#[test]
fn create_vault_authority_is_rejected() {
    let mut r = receipt();
    let expected = r.contract.clone();
    r.contract.can_create_vaults = true;
    let b = bytes(&r);
    assert_eq!(
        validate(&expected, &b, &digest(&b), r.issued_at).unwrap_err(),
        "contract_mismatch"
    );
}
#[test]
fn write_permission_is_rejected() {
    let mut r = receipt();
    let expected = r.contract.clone();
    r.contract.vaults[0].permissions.push("write_items".into());
    let b = bytes(&r);
    assert_eq!(
        validate(&expected, &b, &digest(&b), r.issued_at).unwrap_err(),
        "contract_mismatch"
    );
}
#[test]
fn unknown_permission_is_rejected() {
    let mut r = receipt();
    let expected = r.contract.clone();
    r.contract.vaults[0]
        .permissions
        .push("unknown_permission".into());
    let b = bytes(&r);
    assert_eq!(
        validate(&expected, &b, &digest(&b), r.issued_at).unwrap_err(),
        "contract_mismatch"
    );
}
#[test]
fn owner_authentication_cannot_issue_a_receipt() {
    let c = contract(&fleet(), "test").unwrap();
    let r = FakeRunner::new(vec![native("HUMAN", USER, ACCOUNT)]);
    assert!(issued(&c, &SecretValue::new(TOKEN.into()), &r).is_err());
}
#[test]
fn a_different_native_account_cannot_issue_a_receipt() {
    let c = contract(&fleet(), "test").unwrap();
    let r = FakeRunner::new(vec![native("SERVICE_ACCOUNT", USER, USER)]);
    assert!(issued(&c, &SecretValue::new(TOKEN.into()), &r).is_err());
}

fn verify_result(outputs: Vec<Output>) -> (Result<(), Error>, String, FakeRunner) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.json");
    let b = bytes(&receipt());
    std::fs::write(&path, &b).unwrap();
    let r = FakeRunner::new(outputs);
    let mut out = Vec::new();
    let result = verify(
        &fleet(),
        "test",
        &path,
        &digest(&b),
        &SecretValue::new(TOKEN.into()),
        &r,
        true,
        &mut out,
    );
    (result, String::from_utf8(out).unwrap(), r)
}
#[test]
fn ci_verifies_identity_and_exact_current_read_access() {
    let (result, _, _) = verify_result(vec![
        native("SERVICE_ACCOUNT", USER, ACCOUNT),
        Output::success(format!(r#"[{{"id":"{VAULT}"}}]"#)),
    ]);
    assert!(result.is_ok());
}
#[test]
fn replaced_token_identity_is_rejected() {
    let (result, _, _) = verify_result(vec![native("SERVICE_ACCOUNT", VAULT, ACCOUNT)]);
    assert!(result.is_err());
}
#[test]
fn revoked_or_unreadable_native_identity_is_rejected() {
    let (result, _, _) = verify_result(crate::runner::fake::failed_read(1).collect());
    assert!(result.is_err());
}
#[test]
fn incomplete_provider_metadata_is_rejected() {
    let (result, _, _) = verify_result(vec![
        native("SERVICE_ACCOUNT", USER, ACCOUNT),
        Output::success("{\"partial\":[]}"),
    ]);
    assert!(result.is_err());
}
#[test]
fn disabled_vault_is_rejected() {
    let (result, _, _) = verify_result(vec![
        native("SERVICE_ACCOUNT", USER, ACCOUNT),
        Output::success("[]"),
    ]);
    assert!(result.is_err());
}
#[test]
fn native_extra_vault_is_rejected() {
    let (result, _, _) = verify_result(vec![
        native("SERVICE_ACCOUNT", USER, ACCOUNT),
        Output::success(format!(r#"[{{"id":"{VAULT}"}},{{"id":"{USER}"}}]"#)),
    ]);
    assert!(result.is_err());
}
#[test]
fn native_queries_never_put_the_token_in_argv_or_public_output() {
    let (_, out, r) = verify_result(vec![
        native("SERVICE_ACCOUNT", USER, ACCOUNT),
        Output::success(format!(r#"[{{"id":"{VAULT}"}}]"#)),
    ]);
    assert!(
        !out.contains(TOKEN)
            && r.calls
                .borrow()
                .iter()
                .all(|c| !c.args.iter().any(|a| a.contains(TOKEN)))
    );
}
#[test]
fn metadata_queries_use_only_supported_read_commands() {
    let (_, _, r) = verify_result(vec![
        native("SERVICE_ACCOUNT", USER, ACCOUNT),
        Output::success(format!(r#"[{{"id":"{VAULT}"}}]"#)),
    ]);
    assert!(
        r.calls
            .borrow()
            .iter()
            .all(|c| c.args == ["whoami", "--format", "json"]
                || c.args == ["vault", "list", "--format", "json"])
    );
}
#[test]
fn issuance_proof_never_claims_delivery_or_native_credential_expiry() {
    let (_, out, _) = verify_result(vec![
        native("SERVICE_ACCOUNT", USER, ACCOUNT),
        Output::success(format!(r#"[{{"id":"{VAULT}"}}]"#)),
    ]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        (
            v["reader_grants"]["delivery"].as_str(),
            v["reader_grants"]["credential_expiry"].as_str()
        ),
        (Some("not_verified"), Some("not_verified"))
    );
}
#[test]
fn existing_receipts_are_never_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.json");
    std::fs::write(&path, "approved").unwrap();
    assert!(save(&path, &receipt()).is_err());
}

#[test]
fn an_invalid_receipt_never_exposes_an_arbitrary_input_file_hash() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.json");
    std::fs::write(&path, TOKEN).unwrap();
    let mut out = Vec::new();
    let _ = verify(
        &fleet(),
        "test",
        &path,
        &"0".repeat(64),
        &SecretValue::new(TOKEN.into()),
        &FakeRunner::default(),
        true,
        &mut out,
    );
    let out = String::from_utf8(out).unwrap();
    assert!(!out.contains(TOKEN) && !out.contains(&digest(TOKEN.as_bytes())));
}

#[test]
fn adding_keys_in_an_existing_vault_does_not_change_reader_authority() {
    let before = fleet();
    let mut after = before.clone();
    let product = after.products.get_mut("app").unwrap();
    product
        .keys
        .insert("ANOTHER_KEY".into(), product.keys["KEY"].clone());
    assert_eq!(
        contract(&before, "test").unwrap(),
        contract(&after, "test").unwrap()
    );
}

#[test]
fn a_different_environment_cannot_reuse_the_receipt() {
    let r = receipt();
    let b = bytes(&r);
    let mut expected = r.contract.clone();
    expected.environment = "production".into();
    assert_eq!(
        validate(&expected, &b, &digest(&b), r.issued_at).unwrap_err(),
        "contract_mismatch"
    );
}

#[test]
fn a_different_role_cannot_reuse_the_receipt() {
    let mut r = receipt();
    let expected = r.contract.clone();
    r.contract.role = "deploy".into();
    let b = bytes(&r);
    assert_eq!(
        validate(&expected, &b, &digest(&b), r.issued_at).unwrap_err(),
        "contract_mismatch"
    );
}

#[test]
fn an_unknown_receipt_field_is_not_ignored() {
    let r = receipt();
    let mut value = serde_json::to_value(&r).unwrap();
    value["extra_authority"] = true.into();
    let b = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        validate(&r.contract, &b, &digest(&b), r.issued_at).unwrap_err(),
        "receipt_invalid"
    );
}
