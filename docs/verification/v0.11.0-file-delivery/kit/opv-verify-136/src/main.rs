//! opv-verify-136: the §12.1 kit consumer. Reads each Journeeze destination through the
//! real `jz_secrets::MountedSecretStore` (ced358d) and prints `<name>: match|differ|absent`
//! by SHA-256 against the test markers. Prints names and verdicts only, never a value.
//!
//! Usage: `opv-verify-136 check serve|migrate` or `opv-verify-136 loop serve|migrate [secs]`.
//! Root: `JZ_VAULT_DIR` (default `/run/secrets/journeeze`).

use jz_core::ports::SecretStore;
use jz_core::CoreError;
use jz_secrets::MountedSecretStore;
use sha2::{Digest, Sha256};

const PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\nTESTMARKER136LINE1\nTESTMARKER136LINE2\n-----END RSA PRIVATE KEY-----\n";

/// (destination, test marker): the markers of `tests/mounted_consumer.rs:13-52`.
const SERVE: &[(&str, &str)] = &[
    ("database/url", "test-marker-db-url\n"),
    ("github-app/private-key", PEM),
    ("github/webhook-secret", "test-marker-webhook"),
    ("jev/api-key", "test-marker-jev"),
    ("blob/access-key-id", "test-marker-blob-id"),
    ("blob/secret-access-key", "test-marker-blob-secret"),
    ("guide-assets/signing-key", "test-marker-guide"),
    ("otel/endpoint", "https://otel.example.test"),
    ("otel/headers", "x-test-marker=136"),
];
const MIGRATE: &[(&str, &str)] = &[
    ("database/owner-url", "test-marker-owner-url\n"),
    ("database/app-password", "test-marker-app-password"),
];
/// The config marker, delivered as `LOG_LEVEL` (env from a ConfigMap).
const LOG_LEVEL: &str = "test-marker-log-level";
/// Substrings that identify any marker (the PEM's body lines included).
const MARKER_NEEDLES: &[&str] = &["test-marker", "TESTMARKER136", "otel.example.test"];

fn digest(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

async fn check(role: &str) -> bool {
    let root = std::env::var("JZ_VAULT_DIR").unwrap_or_else(|_| "/run/secrets/journeeze".into());
    let store = MountedSecretStore::new(root);
    let (want, other): (&[(&str, &str)], &[(&str, &str)]) = match role {
        "serve" => (SERVE, MIGRATE),
        "migrate" => (MIGRATE, SERVE),
        _ => {
            eprintln!("role must be serve or migrate");
            std::process::exit(2);
        }
    };
    let mut ok = true;
    for (name, marker) in want {
        let verdict = match store.read(name).await {
            Ok(s) if digest(s.expose()) == digest(marker.as_bytes()) => "match",
            Ok(_) => "differ",
            Err(_) => "absent",
        };
        ok &= verdict == "match";
        println!("{name}: {verdict}");
    }
    for (name, _) in other {
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
    let log = match std::env::var("LOG_LEVEL") {
        Ok(v) if digest(v.as_bytes()) == digest(LOG_LEVEL.as_bytes()) => "match",
        Ok(_) => "differ",
        Err(_) => "absent",
    };
    ok &= log == "match";
    println!("LOG_LEVEL: {log}");
    let mut in_env = Vec::new();
    for (k, v) in std::env::vars_os() {
        let v = v.to_string_lossy();
        if k != "LOG_LEVEL" && MARKER_NEEDLES.iter().any(|n| v.contains(n)) {
            in_env.push(k.to_string_lossy().into_owned());
        }
    }
    ok &= in_env.is_empty();
    if in_env.is_empty() {
        println!("marker in env: none");
    } else {
        println!("marker in env: {}", in_env.join(","));
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
