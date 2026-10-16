//! #136: a fixture consumer shaped like Journeeze's `MountedSecretStore` (one file per
//! logical secret under `JZ_VAULT_DIR`; names are lowercase alphanumeric/dash segments
//! joined by `/`, no traversal) reads the serving role's mapping through the real
//! `opv local-delivery` step. Test markers only, never a real credential.
//!
//! The consumer is this test binary itself: `consumer` does its work only when it runs
//! inside the delivery step (`JZ_VAULT_DIR` set), and prints names and verdicts only.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

const PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\nTESTMARKER136LINE1\nTESTMARKER136LINE2\n-----END RSA PRIVATE KEY-----\n";

/// The serving role's mapping from #136: (source key, destination name, marker value).
const SERVE: &[(&str, &str, &str)] = &[
    ("DATABASE_URL", "database/url", "test-marker-db-url\n"),
    ("GITHUB_APP_PRIVATE_KEY", "github-app/private-key", PEM),
    (
        "GITHUB_WEBHOOK_SECRET",
        "github/webhook-secret",
        "test-marker-webhook",
    ),
    ("TYPESAFE_JEV_API_KEY", "jev/api-key", "test-marker-jev"),
    (
        "BLOB_ACCESS_KEY_ID",
        "blob/access-key-id",
        "test-marker-blob-id",
    ),
    (
        "BLOB_SECRET_ACCESS_KEY",
        "blob/secret-access-key",
        "test-marker-blob-secret",
    ),
    (
        "GUIDE_ASSET_SIGNING_KEY",
        "guide-assets/signing-key",
        "test-marker-guide",
    ),
    (
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "otel/endpoint",
        "https://otel.example.test",
    ),
    (
        "OTEL_EXPORTER_OTLP_HEADERS",
        "otel/headers",
        "x-test-marker=136",
    ),
];

/// Migration-only destinations, which a serving run never delivers.
const MIGRATE_ONLY: &[&str] = &["database/owner-url", "database/app-password"];

/// `MountedSecretStore::get`: validate the name, then read exactly the file's bytes.
fn get(dir: &str, name: &str) -> Result<Vec<u8>, &'static str> {
    let valid = name.split('/').all(|seg| {
        !seg.is_empty()
            && seg.split('-').all(|p| {
                !p.is_empty()
                    && p.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            })
    });
    if !valid {
        return Err("invalid name");
    }
    std::fs::read(PathBuf::from(dir).join(name)).map_err(|_| "not found")
}

/// The consumer's entry point; a no-op unless run inside the delivery step.
#[test]
fn consumer() {
    let Ok(dir) = std::env::var("JZ_VAULT_DIR") else {
        return;
    };
    for (_, name, value) in SERVE {
        let ok = get(&dir, name).is_ok_and(|b| b == value.as_bytes());
        println!("verdict {name} {}", if ok { "exact" } else { "wrong" });
    }
    for name in MIGRATE_ONLY {
        let absent = get(&dir, name) == Err("not found");
        println!(
            "verdict {name} {}",
            if absent { "absent" } else { "present" }
        );
    }
    let traversal = get(&dir, "../etc/passwd") == Err("invalid name");
    println!(
        "verdict traversal {}",
        if traversal { "refused" } else { "allowed" }
    );
}

fn runtime_dir() -> Option<PathBuf> {
    let uid = rustix::process::geteuid().as_raw();
    let p = PathBuf::from(format!("/run/user/{uid}"));
    let st = rustix::fs::statfs(&p).ok()?;
    #[allow(clippy::unnecessary_cast)]
    let magic = (st.f_type as u64) & 0xffff_ffff;
    (magic == 0x0102_1994).then_some(p)
}

/// Run the consumer under `opv local-delivery` with the serving keys; its verdict lines.
fn verdicts() -> Option<Vec<String>> {
    let rt = runtime_dir()?;
    let mut c = Command::new(env!("CARGO_BIN_EXE_opv"));
    c.arg("local-delivery");
    for (key, name, _) in SERVE {
        c.args(["--key", key, "--file", &format!("{key}={name}")]);
    }
    c.args(["--dir-env", "JZ_VAULT_DIR", "--declared-only", "--"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "consumer", "--nocapture", "--test-threads=1"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_RUNTIME_DIR", rt);
    for (key, _, value) in SERVE {
        c.env(key, value);
    }
    let out = c.output().unwrap();
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            // The harness may print "test consumer ... " on the first verdict's line.
            .filter_map(|l| l.find("verdict ").map(|i| l[i..].to_string()))
            .collect(),
    )
}

#[test]
fn the_consumer_reads_every_serving_secret_byte_for_byte() {
    let Some(v) = verdicts() else { return };
    let exact = v.iter().filter(|l| l.ends_with(" exact")).count();
    assert_eq!(exact, SERVE.len(), "{v:?}");
}

#[test]
fn the_consumer_finds_no_migration_material() {
    let Some(v) = verdicts() else { return };
    let absent = v.iter().filter(|l| l.ends_with(" absent")).count();
    assert_eq!(absent, MIGRATE_ONLY.len(), "{v:?}");
}

#[test]
fn the_consumer_refuses_a_traversing_name() {
    let Some(v) = verdicts() else { return };
    assert!(
        v.contains(&"verdict traversal refused".to_string()),
        "{v:?}"
    );
}
