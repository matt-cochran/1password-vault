//! #136, #137: what the app's environment holds, and how file values are written.

use super::*;

fn inherited() -> Vec<(String, String)> {
    [
        ("PATH", "/usr/bin"),
        ("HOME", "/home/u"),
        ("LC_ALL", "C"),
        ("AUTH_SECRET", "a"),
        ("STRIPE_SECRET_KEY", "s"),
        ("GITHUB_APP_PRIVATE_KEY", "k"),
        ("OTHER_PRODUCT_TOKEN", "o"),
        ("AWS_SECRET_ACCESS_KEY", "aws"),
        ("OP_SESSION_my", "session"),
        ("OP_SERVICE_ACCOUNT_TOKEN", "ops"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// X25: the person's run, passed to the step, never reaches the app.
#[test]
fn the_persons_run_never_reaches_the_app() {
    let mut env = inherited();
    env.push((OUTER_VAR.into(), "{}".into()));
    let d = Delivery::default();
    assert!(!names(&child_env(&d, &env, None)).contains(&OUTER_VAR));
}

fn persons_run() -> Outer {
    Outer::new(
        "dev",
        "web",
        None,
        &crate::cause::Invocation::from_cli(&[
            "opv".into(),
            "run".into(),
            "dev".into(),
            "--product".into(),
            "web".into(),
            "--".into(),
            "npm".into(),
        ]),
    )
}

fn rendered(e: &Error, inv: &crate::cause::Invocation) -> String {
    match e.cause() {
        Some((c, _)) => crate::cause::render::render_text(c, None, inv, false, false),
        None => e.to_string(),
    }
}

/// 07.09, 07.17: no folder for file keys steps to the run's preview, never `opv doctor`.
#[test]
fn a_missing_ram_folder_steps_to_the_runs_preview() {
    let o = persons_run();
    let e = Outer::ram_dir_unavailable(Some(&o), false, crate::cause::RamDir::Unset);
    assert!(rendered(&e, &o.invocation()).contains("Next: opv run dev --product web --preview"));
}

/// 07.17: the refusal says why the folder is unavailable.
#[test]
fn a_missing_ram_folder_says_why() {
    let o = persons_run();
    let e = Outer::ram_dir_unavailable(Some(&o), false, crate::cause::RamDir::NotTmpfs);
    assert!(rendered(&e, &o.invocation()).contains("tmpfs"));
}

/// 07.18: the receiver's refusal names the remote host's folder.
#[test]
fn a_remote_missing_ram_folder_names_the_remote_host() {
    let mut o = persons_run();
    o.profile = Some("builder".into());
    let e = Outer::ram_dir_unavailable(Some(&o), true, crate::cause::RamDir::Unset);
    assert!(rendered(&e, &o.invocation()).contains("remote profile builder"));
}

/// 07.09: the step's re-run is the person's run, never the hidden step.
#[test]
fn the_steps_rerun_is_the_persons_run() {
    let o = persons_run();
    assert_eq!(
        crate::cause::render::rerun_text(&o.invocation()),
        "opv run dev --product web -- <command>"
    );
}

fn names(env: &[(String, String)]) -> Vec<&str> {
    let mut n: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
    n.sort();
    n
}

fn worker() -> Delivery {
    Delivery {
        keys: vec!["AUTH_SECRET".into(), "STRIPE_SECRET_KEY".into()],
        declared_only: true,
        command: vec!["vite".into()],
        ..Delivery::default()
    }
}

#[test]
fn declared_only_keeps_the_declared_keys_and_the_basics() {
    let env = child_env(&worker(), &inherited(), None);
    assert_eq!(
        names(&env),
        ["AUTH_SECRET", "HOME", "LC_ALL", "PATH", "STRIPE_SECRET_KEY"]
    );
}

#[test]
fn inherit_keeps_everything_but_1password_variables() {
    let mut d = worker();
    d.declared_only = false;
    let env = child_env(&d, &inherited(), None);
    assert!(!names(&env).iter().any(|n| n.starts_with("OP_")));
}

#[test]
fn inherit_keeps_unrelated_variables() {
    let mut d = worker();
    d.declared_only = false;
    let env = child_env(&d, &inherited(), None);
    assert!(names(&env).contains(&"AWS_SECRET_ACCESS_KEY"));
}

fn mounted() -> Delivery {
    Delivery {
        keys: vec!["GITHUB_APP_PRIVATE_KEY".into()],
        declared_only: true,
        files: vec![(
            "GITHUB_APP_PRIVATE_KEY".into(),
            "github-app/private-key".into(),
        )],
        dir_env: Some("JZ_SECRETS_DIR".into()),
        command: vec!["app".into()],
    }
}

#[test]
fn a_file_key_is_not_a_variable() {
    let env = child_env(&mounted(), &inherited(), Some("/run/user/1/opv-run.1-x"));
    assert!(!names(&env).contains(&"GITHUB_APP_PRIVATE_KEY"));
}

#[test]
fn the_directory_variable_names_the_private_directory() {
    let env = child_env(&mounted(), &inherited(), Some("/run/user/1/opv-run.1-x"));
    assert!(env.contains(&("JZ_SECRETS_DIR".into(), "/run/user/1/opv-run.1-x".into())));
}

#[cfg(unix)]
mod files {
    use super::super::write_file;
    use std::os::unix::fs::PermissionsExt;

    fn private() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    #[test]
    fn a_file_holds_the_value() {
        let d = private();
        write_file(d.path(), "github-app/private-key", b"PEM").unwrap();
        assert_eq!(
            std::fs::read(d.path().join("github-app/private-key")).unwrap(),
            b"PEM"
        );
    }

    #[test]
    fn a_file_is_read_only_for_its_owner() {
        let d = private();
        write_file(d.path(), "webhook-secret", b"x").unwrap();
        let mode = std::fs::metadata(d.path().join("webhook-secret"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o400);
    }

    #[test]
    fn a_nested_directory_is_private() {
        let d = private();
        write_file(d.path(), "github/webhook-secret", b"x").unwrap();
        let mode = std::fs::metadata(d.path().join("github"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn a_planted_link_is_never_followed() {
        let d = private();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path().join("stolen"), d.path().join("key")).unwrap();
        let _ = write_file(d.path(), "key", b"x");
        assert!(!outside.path().join("stolen").exists());
    }

    #[test]
    fn a_planted_directory_link_is_refused() {
        let d = private();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), d.path().join("github")).unwrap();
        assert!(write_file(d.path(), "github/key", b"x").is_err());
    }
}
