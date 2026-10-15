//! #136, #137: the local delivery step `opv run` puts between `op run` and the app, run as
//! the real binary with the environment `op run` would give it (values already resolved;
//! test markers only, never a real credential). The child compares values itself and
//! prints only names and verdicts.
#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

const MARKER: &str = "test-marker-value-136";

/// `opv local-delivery <args> -- sh -c <script>` with exactly `env`.
fn deliver(args: &[&str], env: &[(&str, &str)], script: &str) -> (Option<i32>, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_opv"));
    cmd.arg("local-delivery")
        .args(args)
        .args(["--", "sh", "-c", script])
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// The variable names the app sees.
fn names_seen(args: &[&str], env: &[(&str, &str)]) -> Vec<String> {
    let (_, out) = deliver(args, env, "env | cut -d= -f1");
    out.lines().map(str::to_string).collect()
}

const WORKER_ENV: &[(&str, &str)] = &[
    ("AUTH_SECRET", MARKER),
    ("STRIPE_SECRET_KEY", MARKER),
    ("OP_SESSION_my", MARKER),
    ("OP_SERVICE_ACCOUNT_TOKEN", MARKER),
    ("UNRELATED_CLOUD_TOKEN", MARKER),
    ("HOME", "/tmp"),
];

const WORKER_ARGS: &[&str] = &[
    "--key",
    "AUTH_SECRET",
    "--key",
    "STRIPE_SECRET_KEY",
    "--declared-only",
];

#[test]
fn a_declared_only_app_sees_its_declared_keys() {
    let seen = names_seen(WORKER_ARGS, WORKER_ENV);
    assert!(
        seen.contains(&"AUTH_SECRET".to_string())
            && seen.contains(&"STRIPE_SECRET_KEY".to_string()),
        "{seen:?}"
    );
}

#[test]
fn a_declared_only_app_never_sees_a_1password_credential() {
    let seen = names_seen(WORKER_ARGS, WORKER_ENV);
    assert!(!seen.iter().any(|n| n.starts_with("OP_")), "{seen:?}");
}

#[test]
fn a_declared_only_app_never_sees_an_unrelated_variable() {
    let seen = names_seen(WORKER_ARGS, WORKER_ENV);
    assert!(
        !seen.contains(&"UNRELATED_CLOUD_TOKEN".to_string()),
        "{seen:?}"
    );
}

#[test]
fn an_inheriting_app_never_sees_a_1password_credential() {
    let seen = names_seen(&["--key", "AUTH_SECRET"], WORKER_ENV);
    assert!(!seen.iter().any(|n| n.starts_with("OP_")), "{seen:?}");
}

#[test]
fn the_apps_exit_code_is_passed_through() {
    let (code, _) = deliver(WORKER_ARGS, WORKER_ENV, "exit 7");
    assert_eq!(code, Some(7));
}

/// A user-owned tmpfs runtime directory, when this machine has one (CI runners often do
/// not: the file tests then check only the refusal).
fn runtime_dir() -> Option<PathBuf> {
    let uid = rustix::process::geteuid().as_raw();
    let p = PathBuf::from(format!("/run/user/{uid}"));
    let st = rustix::fs::statfs(&p).ok()?;
    #[allow(clippy::unnecessary_cast)]
    let magic = (st.f_type as u64) & 0xffff_ffff;
    (magic == 0x0102_1994).then_some(p)
}

const MOUNT_ARGS: &[&str] = &[
    "--key",
    "GITHUB_APP_PRIVATE_KEY",
    "--file",
    "GITHUB_APP_PRIVATE_KEY=github-app/private-key",
    "--dir-env",
    "JZ_SECRETS_DIR",
    "--declared-only",
];

fn mounted(script: &str) -> Option<(Option<i32>, String)> {
    let runtime = runtime_dir()?;
    let r = runtime.to_str().unwrap().to_string();
    Some(deliver(
        MOUNT_ARGS,
        &[
            ("GITHUB_APP_PRIVATE_KEY", MARKER),
            ("EXPECTED", MARKER),
            ("XDG_RUNTIME_DIR", &r),
        ],
        script,
    ))
}

#[test]
fn a_mounted_key_is_a_file_holding_its_value() {
    let Some((_, out)) = mounted(
        r#"[ "$(cat "$JZ_SECRETS_DIR/github-app/private-key")" = "test-marker-value-136" ] && echo match"#,
    ) else {
        eprintln!("skipped: no tmpfs runtime directory here");
        return;
    };
    assert_eq!(out.trim(), "match");
}

#[test]
fn a_mounted_key_is_not_a_variable() {
    let Some((_, out)) = mounted(r#"[ -z "${GITHUB_APP_PRIVATE_KEY+x}" ] && echo absent"#) else {
        eprintln!("skipped: no tmpfs runtime directory here");
        return;
    };
    assert_eq!(out.trim(), "absent");
}

#[test]
fn the_secrets_directory_is_gone_when_the_app_exits() {
    let Some((_, out)) = mounted(r#"echo "$JZ_SECRETS_DIR""#) else {
        eprintln!("skipped: no tmpfs runtime directory here");
        return;
    };
    assert!(!PathBuf::from(out.trim()).exists(), "{out}");
}

#[test]
fn without_a_ram_directory_nothing_is_written_or_started() {
    let dir = tempfile::tempdir().unwrap();
    let started = dir.path().join("started");
    let script = format!("touch {}", started.display());
    let (_, _) = deliver(
        MOUNT_ARGS,
        &[
            ("GITHUB_APP_PRIVATE_KEY", MARKER),
            ("XDG_RUNTIME_DIR", "/tmp"),
        ],
        &script,
    );
    assert!(!started.exists());
}

#[test]
fn without_a_ram_directory_the_refusal_is_ram_dir_unavailable() {
    let (code, _) = deliver(
        MOUNT_ARGS,
        &[
            ("GITHUB_APP_PRIVATE_KEY", MARKER),
            ("XDG_RUNTIME_DIR", "/tmp"),
        ],
        "true",
    );
    assert_eq!(code, Some(6));
}
