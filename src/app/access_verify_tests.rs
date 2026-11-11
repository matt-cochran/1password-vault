//! `opv access <env> --verify` (#304, FR-70): one behavioural outcome per test, through
//! [`run`] on a recording fake runner. Ids are placeholders; no value exists here.

use super::*;
use crate::config::Source;
use crate::domain::Fleet;
use crate::domain::access_plan::Grant;
use crate::domain::grant_receipt::{IssuedBy, ReceiptVault, SCHEMA, contract_grants};
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const CONFIG: &str = "\
[environments.prod]
boundaries.web = { vault_id = \"vweb\", item_id = \"iweb\" }

[environments.prod.targets.web]
fly.app = \"shop-prod\"
fly.secret_name = \"{KEY}\"
state_vault_id = \"vstate\"

[products.web.keys.WEB_KEY]
kind = \"secret\"
environments = [\"prod\"]
";

const WHOAMI: &str = r#"{"user_uuid":"USR","account_uuid":"ACC","user_type":"SERVICE_ACCOUNT"}"#;
const VAULTS: &str = r#"[{"id":"vweb","name":"web"}]"#;

/// A value that must never reach argv or output.
const MARKER: &str = "opv-marker-value-7f3a9c";

/// The grants the contract requires for prod's CI reader.
fn required() -> Vec<Grant> {
    let fleet = crate::config::parse(CONFIG).unwrap();
    crate::app::access::required_grants(&fleet, "prod", None, "p").unwrap()
}

/// A receipt the [`WHOAMI`] and [`VAULTS`] token matches, expiring in a year.
fn receipt() -> GrantReceipt {
    GrantReceipt {
        schema: SCHEMA.into(),
        account_id: "ACC".into(),
        service_account_user_id: "USR".into(),
        service_account_name: "p-ci-prod-20261111".into(),
        vaults: vec![ReceiptVault {
            id: "vweb".into(),
            permissions: vec!["read_items".into()],
        }],
        issued_at: "2026-11-11T10:24:11Z".into(),
        issued_by: IssuedBy::Create,
        expires_on: "2099-01-01".into(),
        contract_grants: contract_grants(&required()),
    }
}

/// The receipt as the bindings file holds it.
fn receipt_table(receipt: &GrantReceipt) -> String {
    format!(
        "[environments.prod.ci_reader.receipt]\n{}",
        receipt.to_toml()
    )
}

/// The contract and its sibling bindings file (holding `bindings`) in a temp folder.
fn project(bindings: &str) -> (tempfile::TempDir, Fleet) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    std::fs::write(&path, CONFIG).unwrap();
    std::fs::write(dir.path().join("secrets.bindings.toml"), bindings).unwrap();
    let fleet = crate::config::parse_at(CONFIG, Source::File(&path)).unwrap();
    (dir, fleet)
}

fn token(whoami: &str, vaults: &str) -> FakeRunner {
    FakeRunner::new([Output::success(whoami), Output::success(vaults)])
}

/// Run `--verify` for prod's CI reader with `bindings` beside the contract.
fn verify_with(bindings: &str, r: &FakeRunner, json: bool) -> (Result<(), Error>, String) {
    let (_dir, fleet) = project(bindings);
    let mut out = Vec::new();
    let res = run(&fleet, "prod", None, Some("p"), r, json, &mut out);
    (res, String::from_utf8(out).unwrap())
}

fn verified(receipt: &GrantReceipt) -> Result<(), Error> {
    verify_with(&receipt_table(receipt), &token(WHOAMI, VAULTS), false).0
}

#[test]
fn a_matching_receipt_exits_zero() {
    assert!(verified(&receipt()).is_ok());
}

#[test]
fn a_missing_receipt_exits_with_the_policy_code() {
    let (res, _) = verify_with("", &token(WHOAMI, VAULTS), false);
    assert_eq!(res.unwrap_err().exit_code(), 6);
}

#[test]
fn a_missing_receipt_names_the_rotate_command_in_next() {
    let (res, _) = verify_with("", &token(WHOAMI, VAULTS), false);
    assert_eq!(
        res.unwrap_err().next_text().as_deref(),
        Some("opv access prod --rotate --github '<owner/repo>'")
    );
}

#[test]
fn an_unparsable_receipt_is_receipt_invalid() {
    let bindings = "[environments.prod.ci_reader.receipt]\nschema = \"other\"\n";
    let (_, out) = verify_with(bindings, &token(WHOAMI, VAULTS), true);
    let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(doc["checks"][0]["reason"], "receipt_invalid");
}

#[test]
fn another_identity_type_fails() {
    let person = r#"{"user_uuid":"USR","account_uuid":"ACC","user_type":"HUMAN"}"#;
    let (res, _) = verify_with(&receipt_table(&receipt()), &token(person, VAULTS), false);
    assert!(res.unwrap_err().mentions("not_a_service_account"));
}

#[test]
fn another_account_fails() {
    let other = r#"{"user_uuid":"USR","account_uuid":"OTHER","user_type":"SERVICE_ACCOUNT"}"#;
    let (res, _) = verify_with(&receipt_table(&receipt()), &token(other, VAULTS), false);
    assert!(res.unwrap_err().mentions("wrong_account"));
}

#[test]
fn an_extra_vault_fails() {
    let more = r#"[{"id":"vweb"},{"id":"vother"}]"#;
    let (res, _) = verify_with(&receipt_table(&receipt()), &token(WHOAMI, more), false);
    assert!(res.unwrap_err().mentions("extra_vault"));
}

#[test]
fn a_failed_whoami_is_an_incomplete_read() {
    let r = FakeRunner::new(crate::runner::fake::failed_read(1).chain([Output::success(VAULTS)]));
    let (res, _) = verify_with(&receipt_table(&receipt()), &r, false);
    assert!(res.unwrap_err().mentions("provider_read_incomplete"));
}

#[test]
fn a_changed_contract_fails() {
    let stale = GrantReceipt {
        contract_grants: format!("sha256:{}", "0".repeat(64)),
        ..receipt()
    };
    assert!(verified(&stale).unwrap_err().mentions("contract_changed"));
}

#[test]
fn an_issued_write_permission_fails() {
    let mut writer = receipt();
    writer.vaults[0].permissions.push("write_items".into());
    assert!(verified(&writer).unwrap_err().mentions("write_permission"));
}

#[test]
fn an_expired_receipt_fails() {
    let old = GrantReceipt {
        expires_on: "2020-01-01".into(),
        ..receipt()
    };
    assert!(verified(&old).unwrap_err().mentions("expired"));
}

#[test]
fn the_only_calls_are_whoami_and_vault_list() {
    let r = token(WHOAMI, VAULTS);
    let _ = verify_with(&receipt_table(&receipt()), &r, false);
    let argv: Vec<Vec<String>> = r
        .calls
        .borrow()
        .iter()
        .map(|c| {
            std::iter::once(c.program.clone())
                .chain(c.args.clone())
                .collect()
        })
        .collect();
    assert_eq!(
        argv,
        [
            ["op", "whoami", "--format", "json"]
                .map(String::from)
                .to_vec(),
            ["op", "vault", "list", "--format", "json"]
                .map(String::from)
                .to_vec(),
        ]
    );
}

#[test]
fn no_call_reads_an_item() {
    let r = token(WHOAMI, VAULTS);
    let _ = verify_with("", &r, false);
    assert!(
        !r.calls
            .borrow()
            .iter()
            .any(|c| c.args.iter().any(|a| a == "item"))
    );
}

#[test]
fn json_carries_the_seven_checks_with_fixed_reason_names() {
    let (_, out) = verify_with("", &token(WHOAMI, VAULTS), true);
    let doc: serde_json::Value = serde_json::from_str(&out).unwrap();
    let checks: Vec<(String, serde_json::Value)> = doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["name"].as_str().unwrap().to_string(), c["reason"].clone()))
        .collect();
    let want: Vec<(String, serde_json::Value)> = [
        ("receipt", "receipt_missing".into()),
        ("identity", "receipt_missing".into()),
        ("vault_set", "receipt_missing".into()),
        ("contract", "receipt_missing".into()),
        ("permissions_issued", "receipt_missing".into()),
        ("permissions_live", serde_json::Value::Null),
        ("freshness", "receipt_missing".into()),
    ]
    .into_iter()
    .map(|(n, r)| (n.to_string(), r))
    .collect();
    assert_eq!(checks, want);
}

#[test]
fn text_says_permission_levels_are_proven_only_at_issuance() {
    let (_, out) = verify_with(&receipt_table(&receipt()), &token(WHOAMI, VAULTS), false);
    assert!(out.contains("permission levels are proven only at issuance"));
}

/// A manifest project's configuration as `parse_at` records it.
fn manifest_fleet() -> Fleet {
    let mut fleet = crate::config::parse(CONFIG).unwrap();
    fleet.read_from.0 = ConfigSource::Manifest {
        title: "opv manifest".into(),
        vault: crate::cause::VaultId::new("vmanifest"),
        project: "p".into(),
    };
    fleet
}

#[test]
fn a_manifest_project_reports_every_check_not_supported() {
    let r = FakeRunner::default();
    let mut out = Vec::new();
    let _ = run(
        &manifest_fleet(),
        "prod",
        None,
        Some("p"),
        &r,
        true,
        &mut out,
    );
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(
        doc["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["state"] == "not_supported")
    );
}

#[test]
fn a_manifest_project_says_why_it_cannot_verify() {
    let r = FakeRunner::default();
    let mut out = Vec::new();
    let res = run(
        &manifest_fleet(),
        "prod",
        None,
        Some("p"),
        &r,
        false,
        &mut out,
    );
    assert!(res.unwrap_err().mentions("1Password manifest"));
}

#[test]
fn a_marker_in_the_environment_never_reaches_argv_or_output() {
    // SAFETY: the variable is unique to this test; nothing else reads or writes it.
    unsafe { std::env::set_var("OPV_TEST_VERIFY_MARKER", MARKER) };
    let whoami = format!(
        r#"{{"url":"{MARKER}","user_uuid":"USR","account_uuid":"ACC","user_type":"SERVICE_ACCOUNT"}}"#
    );
    let r = token(&whoami, VAULTS);
    let (res, out) = verify_with("", &r, true);
    let argv: String = r
        .calls
        .borrow()
        .iter()
        .flat_map(|c| c.args.clone())
        .collect::<Vec<_>>()
        .join(" ");
    let error = crate::error::report(&res.unwrap_err());
    assert!(![argv, out, error].iter().any(|s| s.contains(MARKER)));
}
