//! End-to-end CLI framing with a disposable native metadata simulator, never real op.
#![cfg(unix)]
use opv::app::reader_grants::{Contract, Receipt, VaultGrant, digest};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

const ACCOUNT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
const USER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbb";
const VAULT: &str = "cccccccccccccccccccccccccc";

fn run(native_type: &str, trusted: bool) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("secrets.toml");
    opv::config::bindings::write_split(
        &cfg,
        &format!(
            r#"
[environments.test]
account = "{ACCOUNT}"
boundaries.app = {{ vault_id = "{VAULT}", item_id = "dddddddddddddddddddddddddd" }}
[products.app.keys.KEY]
kind = "secret"
environments = ["test"]
"#
        ),
    )
    .unwrap();
    let contract = Contract {
        environment: "test".into(),
        role: "ci_reader".into(),
        account_id: ACCOUNT.into(),
        vaults: vec![VaultGrant {
            vault_id: VAULT.into(),
            permissions: vec!["read_items".into()],
        }],
        can_create_vaults: false,
    };
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let receipt = Receipt {
        receipt_schema: 1,
        revision: 1,
        proof: "native_immutable_issuance".into(),
        service_account_id: USER.into(),
        contract_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&contract).unwrap())),
        contract,
        issued_at: at - 1,
        not_after: at + 3600,
    };
    let bytes = serde_json::to_vec(&receipt).unwrap();
    let path = dir.path().join("reader.json");
    std::fs::write(&path, &bytes).unwrap();
    let bin = dir.path().join("op");
    std::fs::write(&bin, format!(r#"#!/bin/sh
case "$1" in
--version) printf '2.40.0\n'; exit 0;;
esac
# A native metadata query must receive no alternative identity, even if OPV inherited it.
[ -z "$OP_SESSION_owner$OP_CONNECT_HOST$OP_CONNECT_TOKEN$OP_ACCOUNT" ] || exit 91
[ "$OP_BIOMETRIC_UNLOCK_ENABLED" = false ] || exit 92
[ "$OP_CACHE" = false ] || exit 93
[ "$OP_SERVICE_ACCOUNT_TOKEN" = ops_FAKE304_CLI_MARKER ] || exit 94
case "$1 $2" in
'whoami --format') printf '%s\n' '{{"user_uuid":"{USER}","account_uuid":"{ACCOUNT}","user_type":"{native_type}"}}';;
'vault list') printf '%s\n' '[{{"id":"{VAULT}","name":"ignored mutable name"}}]';;
*) exit 95;;
esac
"#)).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
    let approved = if trusted {
        digest(&bytes)
    } else {
        "0".repeat(64)
    };
    Command::new(env!("CARGO_BIN_EXE_opv"))
        .current_dir(dir.path())
        .env_clear()
        .env("PATH", dir.path())
        .env("HOME", dir.path())
        .env("OPV_NO_SKILL", "1")
        .env("OP_SERVICE_ACCOUNT_TOKEN", "ops_FAKE304_CLI_MARKER")
        .env("OP_SESSION_owner", "FAKE_OWNER_CANARY")
        .env("OP_CONNECT_HOST", "https://connect.invalid")
        .env("OP_CONNECT_TOKEN", "FAKE_CONNECT_CANARY")
        .env("OP_ACCOUNT", "owner-name")
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "access",
            "test",
            "--verify-reader",
            "--grant-receipt",
            path.to_str().unwrap(),
            "--grant-receipt-sha256",
            &approved,
            "--json",
        ])
        .output()
        .unwrap()
}

#[test]
fn successful_cli_json_is_framed_and_verifies_only_immutable_issuance() {
    let out = run("SERVICE_ACCOUNT", true);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        out.status.success()
            && doc["schema_version"] == 4
            && doc["ok"] == true
            && doc["reader_grants"]["status"] == "verified"
            && doc["reader_grants"]["retrospective_effective_grants"] == "not_supported",
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
#[test]
fn a_bad_approved_digest_is_a_typed_failure_with_preserved_report() {
    let out = run("SERVICE_ACCOUNT", false);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        out.status.code() == Some(8)
            && doc["ok"] == false
            && doc["error"]["code"] == "reader_grants_unverified"
            && doc["reader_grants"]["status"] == "not_verified"
            && doc["reader_grants"]["finding"] == "untrusted_or_tampered_receipt",
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
#[test]
fn human_identity_cannot_impersonate_the_issued_service_account_in_cli() {
    let out = run("HUMAN", true);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        out.status.code() == Some(8)
            && doc["error"]["code"] == "reader_grants_unverified"
            && doc["reader_grants"]["finding"] == "native_identity_unverified",
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
