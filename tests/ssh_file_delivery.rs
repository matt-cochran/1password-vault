//! #294 acceptance: the local delivery step of `opv run` writes an `ssh_ed25519` key to a
//! private file with its bytes verbatim (the trailing newline kept) and never prints the
//! private key. As `tests/local_delivery.rs`, the step is driven as the real binary with
//! the environment `op run` would give it (the value already resolved); the child compares
//! the file itself and prints only a verdict. The key is built in-test, never committed.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

use ssh_key::LineEnding;
use ssh_key::private::Ed25519Keypair;

/// The resolved variable, and the file `opv run` delivers it as.
const KEY: &str = "SIGNING_KEY";
const FILE: &str = "ssh/signing-key";

/// A fresh, valid, unencrypted Ed25519 OpenSSH private key, as `ssh-keygen` writes it.
fn signing_key() -> String {
    ssh_key::PrivateKey::from(Ed25519Keypair::from_seed(&[42u8; 32]))
        .to_openssh(LineEnding::LF)
        .unwrap()
        .to_string()
}

/// The user-owned tmpfs runtime directory, when this machine has one (CI runners often do
/// not: the file scenarios are then skipped, as in `tests/local_delivery.rs`).
fn runtime_dir() -> Option<PathBuf> {
    let uid = rustix::process::geteuid().as_raw();
    let p = PathBuf::from(format!("/run/user/{uid}"));
    let st = rustix::fs::statfs(&p).ok()?;
    #[allow(clippy::unnecessary_cast)]
    let magic = (st.f_type as u64) & 0xffff_ffff;
    (magic == 0x0102_1994).then_some(p)
}

/// Run the delivery step with `key` resolved, returning the child's code, stdout and stderr.
///
/// The key travels only in the child's environment (SR-3), never as an argument.
fn deliver(
    key: &str,
    extra: &[(&str, &str)],
    script: &str,
) -> Option<(Option<i32>, String, String)> {
    let runtime = runtime_dir()?;
    let mapping = format!("{KEY}={FILE}");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_opv"));
    cmd.arg("local-delivery")
        .arg("--key")
        .arg(KEY)
        .arg("--file")
        .arg(&mapping)
        .args(["--key", "EXPECTED_FILE"])
        .args(["--dir-env", "APP_SECRETS_DIR", "--declared-only"])
        .args(["--", "sh", "-c", script])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_RUNTIME_DIR", runtime)
        .env(KEY, key);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    Some((
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Skip the test when this machine has no RAM-backed runtime directory.
fn skipped() -> bool {
    if runtime_dir().is_none() {
        eprintln!("skipped: no tmpfs runtime directory here");
        return true;
    }
    false
}

#[test]
fn a_delivered_signing_key_file_holds_the_stored_bytes() {
    if skipped() {
        return;
    }
    let key = signing_key();
    let dir = tempfile::tempdir().unwrap();
    let reference = dir.path().join("expected");
    std::fs::write(&reference, key.as_bytes()).unwrap();
    let reference = reference.to_str().unwrap();
    let Some((_, out, _)) = deliver(
        &key,
        &[("EXPECTED_FILE", reference)],
        &format!(
            "cmp -s \"$APP_SECRETS_DIR/{FILE}\" \"$EXPECTED_FILE\" && echo match || echo differ"
        ),
    ) else {
        return;
    };
    assert_eq!(out.trim(), "match");
}

#[test]
fn a_delivered_signing_key_file_has_no_group_or_other_bits() {
    if skipped() {
        return;
    }
    let key = signing_key();
    let Some((_, out, _)) = deliver(
        &key,
        &[],
        &format!("stat -c %a \"$APP_SECRETS_DIR/{FILE}\""),
    ) else {
        return;
    };
    let mode = u32::from_str_radix(out.trim(), 8).unwrap();
    assert_eq!(mode & 0o077, 0);
}

#[test]
fn the_private_key_never_appears_in_the_steps_output() {
    if skipped() {
        return;
    }
    let key = signing_key();
    let Some((_, out, err)) = deliver(&key, &[], "true") else {
        return;
    };
    assert!(!format!("{out}{err}").contains(&key));
}
