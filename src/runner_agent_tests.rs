//! `op` children under the agent identity (#338, design `agent-identity.md` §4.3 steps 2
//! and 3, vet R1): the token reaches the `op` child alone, which never acts as the person.
//! The token here is a canary; no test sets a process-wide variable or identity.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use super::*;
use crate::domain::SecretValue;

const CANARY: &str = "ops_CANARY-s6-agent-token-91d2";

fn token() -> &'static SecretValue {
    static TOKEN: OnceLock<SecretValue> = OnceLock::new();
    TOKEN.get_or_init(|| SecretValue::new(CANARY.to_string()))
}

fn agent() -> OpAs<'static> {
    OpAs::Agent(Some(token()))
}

/// Every variable `cmd` sets or removes whose name passes `pick`: `Some(value)` when set,
/// `None` when removed.
fn changes(cmd: &Command, pick: impl Fn(&str) -> bool) -> BTreeMap<String, Option<String>> {
    cmd.get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .filter(|(k, _)| pick(k))
        .collect()
}

fn sets_token(cmd: &Command) -> bool {
    cmd.get_envs()
        .any(|(k, v)| k == "OP_SERVICE_ACCOUNT_TOKEN" && v.is_some())
}

#[test]
fn a_captured_op_call_under_the_agent_has_its_token_and_no_person_session() {
    let env = [
        ("OP_SESSION_owner", "OWNER_SESSION_CANARY"),
        ("OP_ACCOUNT", "owner-account"),
        ("OP_CONNECT_HOST", "https://connect.invalid"),
    ];
    let call = Call {
        env: &env,
        ..Call::new("op", &["item", "get", "i1"])
    };
    let cmd = command_as(&call, agent());
    assert_eq!(
        changes(&cmd, |k| k.starts_with("OP_")),
        BTreeMap::from([
            ("OP_SERVICE_ACCOUNT_TOKEN".into(), Some(CANARY.into())),
            ("OP_BIOMETRIC_UNLOCK_ENABLED".into(), Some("false".into())),
            ("OP_CACHE".into(), Some("false".into())),
        ])
    );
}

#[test]
fn an_inherited_op_run_under_the_agent_has_its_token_without_other_identities_and_keeps_the_rest() {
    let env = [
        ("APP_SETTING", "1"),
        ("OP_SESSION_owner", "OWNER_SESSION_CANARY"),
        ("OP_ACCOUNT", "owner-account"),
    ];
    let inherited = [
        "OP_SESSION_owner",
        "OP_CONNECT_HOST",
        "OP_CONNECT_TOKEN",
        "OP_ACCOUNT",
        "UNRELATED_INHERITED",
    ];
    let cmd = inherited_command(
        "op",
        &["run", "--", "app"],
        &env,
        &[],
        ChildSession::Strip,
        agent(),
        inherited.iter().map(|s| s.to_string()),
    );
    assert_eq!(
        changes(&cmd, |k| k.starts_with("OP_")
            || k == "APP_SETTING"
            || k == "UNRELATED_INHERITED"),
        BTreeMap::from([
            ("APP_SETTING".into(), Some("1".into())),
            ("OP_ACCOUNT".into(), None),
            ("OP_BIOMETRIC_UNLOCK_ENABLED".into(), Some("false".into())),
            ("OP_CACHE".into(), Some("false".into())),
            ("OP_CONNECT_HOST".into(), None),
            ("OP_CONNECT_TOKEN".into(), None),
            ("OP_SERVICE_ACCOUNT_TOKEN".into(), Some(CANARY.into())),
            ("OP_SESSION_owner".into(), None),
        ])
    );
}

#[test]
fn an_inherited_op_run_under_the_agent_has_no_account_flag_in_argv() {
    let env = [("OP_ACCOUNT", "owner-account")];
    let cmd = inherited_command(
        "op",
        &["run", "--", "app"],
        &env,
        &[],
        ChildSession::Strip,
        agent(),
        std::iter::empty(),
    );
    assert_eq!(cmd.get_args().collect::<Vec<_>>(), ["run", "--", "app"]);
}

#[test]
fn a_non_op_child_under_the_agent_never_has_its_token() {
    let captured = command_as(&Call::new("flyctl", &["status"]), agent());
    let inherited = inherited_command(
        "cargo",
        &["test"],
        &[],
        &[],
        ChildSession::Strip,
        agent(),
        std::iter::empty(),
    );
    assert_eq!(
        (sets_token(&captured), sets_token(&inherited)),
        (false, false)
    );
}

#[test]
fn an_op_call_before_the_agent_is_resolved_has_no_person_session() {
    use_op_session(vec![(
        "OP_SESSION_S6PROBE".into(),
        SecretValue::new("S6_SESSION_CANARY".into()),
    )]);
    let cmd = command_as(&Call::new("op", &["whoami"]), OpAs::Agent(None));
    use_op_session(Vec::new());
    assert_eq!(
        changes(&cmd, |k| k.starts_with("OP_")),
        BTreeMap::from([
            ("OP_BIOMETRIC_UNLOCK_ENABLED".into(), Some("false".into())),
            ("OP_CACHE".into(), Some("false".into())),
        ])
    );
}

#[test]
fn a_token_the_call_names_itself_wins_over_the_agent_token() {
    let env = [("OP_SERVICE_ACCOUNT_TOKEN", "ops_FAKE_issued_reader")];
    let call = Call {
        env: &env,
        ..Call::new("op", &["whoami"])
    };
    assert_eq!(
        changes(&command_as(&call, agent()), |k| k
            == "OP_SERVICE_ACCOUNT_TOKEN"),
        BTreeMap::from([(
            "OP_SERVICE_ACCOUNT_TOKEN".into(),
            Some("ops_FAKE_issued_reader".into())
        )])
    );
}

#[test]
fn under_the_default_identity_a_captured_op_call_gets_no_agent_token() {
    assert!(!sets_token(&command_as(
        &Call::new("op", &["whoami"]),
        OpAs::Default
    )));
}

/// A `PATH` directory holding an `op` script that exits 0.
#[cfg(unix)]
fn op_script() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("op");
    std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[cfg(unix)]
#[test]
fn opv_own_environment_never_gains_the_agent_token() {
    let dir = op_script();
    let env = [("PATH", dir.path().to_str().unwrap())];
    let call = Call {
        env: &env,
        ..Call::new("op", &["whoami"])
    };
    let _ = with_op_as(agent(), || ProcessRunner::default().read(&call, &[]));
    assert!(std::env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_none());
}

/// ADR-0001: no rendering of the runner, its call or its failure holds the token.
#[test]
fn no_error_or_debug_rendering_of_the_runner_holds_the_agent_token() {
    let env = [("PATH", "/nonexistent-opv-s6")];
    let call = Call {
        env: &env,
        ..Call::new("op", &["item", "get", "i1"])
    };
    let r = ProcessRunner::default();
    let res = with_op_as(agent(), || r.read(&call, &[]));
    let mut rendered = format!("{r:?} {call:?} {res:?}");
    if let Err(e) = &res {
        rendered.push_str(&e.to_string());
    }
    assert!(!rendered.contains(CANARY));
}
