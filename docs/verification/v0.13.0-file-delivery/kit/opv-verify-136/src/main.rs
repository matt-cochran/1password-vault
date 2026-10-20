//! opv-verify-136 (0.13.0 kit): the §12.1 consumer, run with canary values.
//!
//! Reads each Journeeze destination through the real `jz_secrets::MountedSecretStore`
//! (ced358d; `crates/jz_secrets` is unchanged up to journeeze-saas f7772b2) and prints
//! `<name>: match|differ|absent` by SHA-256. Prints names and verdicts only, never a value.
//!
//! Unlike the 0.11.0 kit, the expected digests are not compiled in: each run's canaries are
//! new (`canary/gen-canary.py`), so the digests come from an expectations file,
//! `OPV_VERIFY_EXPECT` (default `/etc/opv-verify/expect`), with lines `<name> <sha256>`,
//! `LOG_LEVEL <sha256>` and `needle_hex <hex of the canary prefix>`. The file holds no
//! value: digests, and the prefix only hex-encoded, so the canary scan doesn't hit it.
//!
//! Usage: `opv-verify-136 check serve|migrate` or `opv-verify-136 loop serve|migrate [secs]`.
//! Root: `JZ_VAULT_DIR` (default `/run/secrets/journeeze`).

use jz_core::ports::SecretStore;
use jz_core::CoreError;
use jz_secrets::MountedSecretStore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const SERVE: &[&str] = &[
    "database/url",
    "github-app/private-key",
    "github/webhook-secret",
    "jev/api-key",
    "blob/access-key-id",
    "blob/secret-access-key",
    "guide-assets/signing-key",
    "otel/endpoint",
    "otel/headers",
];
const MIGRATE: &[&str] = &["database/owner-url", "database/app-password"];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn digest(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

/// The expectations, re-read on every check so a ConfigMap update (V10) is picked up.
fn expectations() -> Result<(HashMap<String, String>, Vec<u8>), String> {
    let path =
        std::env::var("OPV_VERIFY_EXPECT").unwrap_or_else(|_| "/etc/opv-verify/expect".into());
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let mut map = HashMap::new();
    let mut needle = None;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (k, v) = line
            .split_once(' ')
            .ok_or_else(|| format!("{path}: bad line"))?;
        if k == "needle_hex" {
            needle = unhex(v.trim());
        } else {
            map.insert(k.to_string(), v.trim().to_string());
        }
    }
    let needle = needle
        .filter(|n| n.len() >= 8)
        .ok_or_else(|| format!("{path}: no needle_hex"))?;
    Ok((map, needle))
}

async fn check(role: &str) -> bool {
    let (want_digest, needle) = match expectations() {
        Ok(x) => x,
        Err(e) => {
            println!("expectations: unreadable ({e})");
            println!("result: FAIL");
            return false;
        }
    };
    let root = std::env::var("JZ_VAULT_DIR").unwrap_or_else(|_| "/run/secrets/journeeze".into());
    let store = MountedSecretStore::new(root);
    let (want, other) = match role {
        "serve" => (SERVE, MIGRATE),
        "migrate" => (MIGRATE, SERVE),
        _ => {
            eprintln!("role must be serve or migrate");
            std::process::exit(2);
        }
    };
    let mut ok = true;
    for name in want {
        let verdict = match (store.read(name).await, want_digest.get(*name)) {
            (Ok(s), Some(d)) if &digest(s.expose()) == d => "match",
            (Ok(_), Some(_)) => "differ",
            (Ok(_), None) => "differ (no expectation)",
            (Err(_), _) => "absent",
        };
        ok &= verdict == "match";
        println!("{name}: {verdict}");
    }
    for name in other {
        let verdict = match store.read(name).await {
            Ok(_) => "present (not expected for this role)",
            Err(_) => "absent",
        };
        ok &= verdict == "absent";
        println!("{name}: {verdict}");
    }
    let traversal = match store.read("../etc/passwd").await {
        Err(CoreError::PermissionDenied) => "refused",
        Err(_) => "error (not PermissionDenied)",
        Ok(_) => "READ (traversal not refused)",
    };
    ok &= traversal == "refused";
    println!("traversal ../etc/passwd: {traversal}");
    let log = match (std::env::var("LOG_LEVEL"), want_digest.get("LOG_LEVEL")) {
        (Ok(v), Some(d)) if &digest(v.as_bytes()) == d => "match",
        (Ok(_), _) => "differ",
        (Err(_), _) => "absent",
    };
    ok &= log == "match";
    println!("LOG_LEVEL: {log}");
    let mut in_env = Vec::new();
    for (k, v) in std::env::vars_os() {
        let v = v.to_string_lossy();
        if k != "LOG_LEVEL" && v.as_bytes().windows(needle.len()).any(|w| w == needle.as_slice()) {
            in_env.push(k.to_string_lossy().into_owned());
        }
    }
    ok &= in_env.is_empty();
    if in_env.is_empty() {
        println!("canary in env: none");
    } else {
        println!("canary in env: {}", in_env.join(","));
    }
    println!("result: {}", if ok { "ok" } else { "FAIL" });
    ok
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check") => {
            let ok = check(args.get(1).map(String::as_str).unwrap_or("serve")).await;
            std::process::exit(if ok { 0 } else { 1 });
        }
        Some("loop") => {
            let role = args.get(1).cloned().unwrap_or_else(|| "serve".into());
            let secs = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(30);
            loop {
                check(&role).await;
                tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            }
        }
        _ => {
            eprintln!("usage: opv-verify-136 check|loop serve|migrate [secs]");
            std::process::exit(2);
        }
    }
}
