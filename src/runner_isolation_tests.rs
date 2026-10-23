//! Operation children under [`isolated_env`] (#234, design §5.5; T6 unit half, T15): a
//! cleared environment with opv's basics, the program's pinned variables and the call's own.
//! Names only: no test reads or prints a value.

#[cfg(unix)]
use std::collections::BTreeSet;

use super::*;

/// Names a shell adds to its own environment when it starts (bash as `sh`), never opv's.
#[cfg(unix)]
const SHELL_OWN: &[&str] = &["PWD", "OLDPWD", "SHLVL", "_"];

/// Run `program` (a script in a fresh `PATH` directory that writes the names of its
/// environment, builtins only) with `env` on top, inside [`isolated_env`]; the names it saw.
#[cfg(unix)]
fn names_seen_by(program: &str, args: &[&str], env: &[(&str, &str)]) -> BTreeSet<String> {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join(program);
    std::fs::write(
        &script,
        "#!/bin/sh\nexport -p | while IFS= read -r line; do\n  case \"$line\" in \
         export\\ *) n=\"${line#export }\"; echo \"${n%%=*}\";; esac\ndone > \"$OPV_DUMP\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let dump = dir.path().join("names");
    let (path, dump_s) = (dir.path().to_str().unwrap(), dump.to_str().unwrap());
    let mut all = vec![("PATH", path), ("OPV_DUMP", dump_s)];
    all.extend_from_slice(env);
    let call = Call {
        env: &all,
        ..Call::new(program, args)
    };
    let outcome = isolated_env(|| ProcessRunner::default().read(&call, &[])).unwrap();
    assert!(
        matches!(outcome, Outcome::Done(_)),
        "the script did not run"
    );
    std::fs::read_to_string(dump)
        .unwrap()
        .lines()
        .filter(|n| !SHELL_OWN.contains(n))
        .map(str::to_string)
        .collect()
}

/// The names a child of `program` should see: opv's basics, the pinned ones and `own`.
#[cfg(unix)]
fn allowed(program: &str, own: &[&str]) -> BTreeSet<String> {
    std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .filter(|k| crate::host::is_basic_env(k))
        .chain(pinned_env(program).iter().map(|(k, _)| k.to_string()))
        .chain(
            ["PATH", "OPV_DUMP"]
                .iter()
                .chain(own)
                .map(|k| k.to_string()),
        )
        .filter(|k| !SHELL_OWN.contains(&k.as_str()))
        .collect()
}

/// T6: an isolated child sees exactly the basics and its own names; never a 1Password one,
/// even one set on the call.
#[cfg(unix)]
#[test]
fn an_isolated_child_sees_only_the_basics_and_its_own_env() {
    let env = [
        ("OPV_OWN_SETTING", "1"),
        ("OP_SERVICE_ACCOUNT_TOKEN", "canary"),
        ("OP_SESSION_acct", "canary"),
    ];
    let seen = names_seen_by("opv-dump-env", &[], &env);
    assert_eq!(seen, allowed("opv-dump-env", &["OPV_OWN_SETTING"]));
}

/// T15: `flyctl version` runs under the allowlist, with flyctl's pinned variables.
#[cfg(unix)]
#[test]
fn flyctl_version_runs_under_the_allowlist() {
    let seen = names_seen_by("flyctl", &["version"], &[]);
    assert_eq!(seen, allowed("flyctl", &[]));
}

/// `op` keeps its environment inside isolation (it needs the session or token); another CLI
/// gets the basics put back on a cleared one.
#[test]
fn only_an_op_call_escapes_isolation() {
    let rebuilt = |p: &str| {
        isolated_env(|| {
            command_for(&Call::new(p, &[]))
                .get_envs()
                .any(|(k, _)| k == "PATH")
        })
    };
    assert_eq!((rebuilt("op"), rebuilt("flyctl")), (false, true));
}

/// Isolation ends with its scope, so `plan`, `sync` and `run` keep the inherited environment.
#[test]
fn isolation_ends_with_its_scope() {
    isolated_env(|| isolated_env(|| ()));
    assert!(!ISOLATED.with(std::cell::Cell::get));
}

/// T15, Windows: `Path`, as Windows spells it, is kept like `PATH`.
#[cfg(windows)]
#[test]
fn windows_path_is_a_basic_whatever_its_case() {
    assert!(crate::host::is_basic_env("Path"));
}
