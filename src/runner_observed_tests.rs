//! What the runner observes about a failed call (design §5 "Sealing"): its `CallId`, how it
//! ended and the principal in effect. One assertion each.

use std::io;

use super::fake::FakeRunner;
use super::*;
use crate::cause::{CallId, EnvName, ExitClass, ItemId, Principal, System, TargetName, VarName};

fn failed_write(r: &FakeRunner, call: &Call) -> Option<crate::cause::Observed> {
    let _ = r.write(call);
    take_observed()
}

#[test]
fn failed_call_is_observed_with_its_call_id() {
    let r = FakeRunner::new([Output::failure(1)]);
    let seen = failed_write(&r, &Call::new("flyctl", &["secrets", "list", "-a", "api"]));
    assert_eq!(
        seen.map(|o| o.call().clone()),
        Some(CallId {
            system: System::Fly,
            program: "flyctl".into(),
            words: vec!["secrets".into(), "list".into(), "-a".into(), "api".into()],
        })
    );
}

#[test]
fn timed_out_call_is_observed_as_timed_out() {
    let r = FakeRunner::default();
    r.push_unknown("timeout");
    let seen = failed_write(&r, &Call::new("flyctl", &["secrets", "deploy"]));
    assert_eq!(seen.map(|o| o.exit()), Some(ExitClass::TimedOut));
}

#[test]
fn call_that_could_not_start_is_observed_as_spawn_failed() {
    let r = FakeRunner::default();
    r.push_io_error(io::ErrorKind::NotFound);
    let seen = failed_write(&r, &Call::new("az", &["account", "show"]));
    assert_eq!(seen.map(|o| o.exit()), Some(ExitClass::SpawnFailed));
}

#[test]
fn call_with_gh_token_in_its_env_is_observed_under_that_shell_token() {
    let r = FakeRunner::new([Output::failure(1)]);
    let env = [("GH_TOKEN", "MARKER-not-a-real-token")];
    let call = Call {
        env: &env,
        ..Call::new("gh", &["secret", "list"])
    };
    let seen = failed_write(&r, &call);
    assert_eq!(
        seen.map(|o| o.principal().clone()),
        Some(Principal::ShellToken {
            var: VarName::new("GH_TOKEN")
        })
    );
}

#[test]
fn call_under_deploy_credentials_is_observed_under_them() {
    let r = FakeRunner::new([Output::failure(1)]);
    let deploy = Principal::DeployCredentials {
        vault: crate::cause::VaultId::new("vlt-deploy"),
        item: ItemId::new("abc123"),
        env: EnvName::new("prod"),
        target: TargetName::new("web"),
    };
    let seen = under_deploy(deploy.clone(), || {
        failed_write(&r, &Call::new("flyctl", &["secrets", "deploy"]))
    });
    assert_eq!(seen.map(|o| o.principal().clone()), Some(deploy));
}

#[test]
fn successful_call_leaves_nothing_observed() {
    let r = FakeRunner::new([Output::success("")]);
    let seen = failed_write(&r, &Call::new("flyctl", &["secrets", "deploy"]));
    assert!(seen.is_none());
}

#[test]
fn op_run_child_words_never_reach_the_call_id() {
    let call = Call::new("op", &["run", "--no-masking", "--", "printenv", "API_KEY"]);
    let words = observe::call_id(&call).map(|c| c.words);
    assert_eq!(
        words,
        Some(vec!["run".to_string(), "--no-masking".to_string()])
    );
}

#[test]
fn name_value_word_keeps_only_its_name() {
    let call = Call::new("op", &["item", "edit", "abc123", "password=MARKER"]);
    let words = observe::call_id(&call).map(|c| c.words);
    assert_eq!(
        words,
        Some(vec![
            "item".into(),
            "edit".into(),
            "abc123".into(),
            "password".into()
        ])
    );
}

/// `op run`'s exit is the person's own command's: a non-zero exit is not a 1Password failure.
#[cfg(unix)]
#[test]
fn the_persons_command_exiting_non_zero_is_not_observed() {
    let r = ProcessRunner::new(Budget::starting_now(Duration::from_secs(30)), false);
    let _ = r.run_inherited("sh", &["-c", "exit 3"], &[]);
    assert!(take_observed().is_none());
}

// --- B1: one way to hand a diagnosis the failed call; A1: unusable answers ----------------

#[test]
fn take_failure_hands_the_diagnosis_the_raw_stderr_b1() {
    let r = FakeRunner::default();
    r.push_with_stderr(Output::failure(1), "gh: Bad credentials (HTTP 401)");
    let _ = r.write(&Call::new("gh", &["secret", "set", "API_KEY"]));
    assert_eq!(
        take_failure().map(|f| f.stderr().to_string()),
        Some("gh: Bad credentials (HTTP 401)".to_string())
    );
}

#[test]
fn a_killed_call_keeps_its_stderr_for_the_diagnosis_b1() {
    let r = FakeRunner::default();
    r.push_unknown_with_stderr("killed", "partial reply");
    let _ = r.write(&Call::new("flyctl", &["secrets", "deploy"]));
    assert_eq!(
        take_failure().map(|f| f.stderr().to_string()),
        Some("partial reply".to_string())
    );
}

#[test]
fn a_lost_reply_is_an_observed_failure_b1() {
    let r = FakeRunner::default();
    r.push_unknown("lost");
    let _ = r.write(&Call::new("flyctl", &["secrets", "deploy"]));
    assert!(take_failure().is_some());
}

#[test]
fn a_streamed_child_is_handed_over_with_its_stderr_b1() {
    record_streamed(
        "ssh",
        &["-p", "22", "host"],
        ExitClass::Code { code: 255 },
        b"Permission denied (publickey).",
    );
    assert_eq!(
        take_failure().map(|f| f.stderr().to_string()),
        Some("Permission denied (publickey).".to_string())
    );
}

fn item_get() -> Call<'static> {
    Call::new("op", &["item", "get", "deploy"])
}

#[test]
fn a_call_that_answered_is_observed_as_an_unusable_reply_a1() {
    let r = FakeRunner::new([Output::success("{not json")]);
    let _ = r.read(&item_get(), &[]);
    assert_eq!(
        take_unusable_reply(&item_get()).map(|o| o.exit()),
        Some(ExitClass::Code { code: 0 })
    );
}

/// The runner's own observation, not one made up from the call: output over the cap keeps
/// how the child really ended.
#[test]
fn an_answer_over_the_cap_keeps_how_the_child_ended_a1() {
    let r = FakeRunner::default();
    r.push_io_error(io::ErrorKind::OutOfMemory);
    let _ = r.read(&item_get(), &[]);
    assert_eq!(
        take_unusable_reply(&item_get()).map(|o| o.exit()),
        Some(ExitClass::Signal { signal: 9 })
    );
}

#[test]
fn a_later_failed_call_drops_the_unusable_reply_a1() {
    let r = FakeRunner::new([Output::success(""), Output::failure(1)]);
    let _ = r.read(&item_get(), &[]);
    let _ = r.write(&Call::new("op", &["item", "edit", "deploy"]));
    assert!(take_unusable_reply(&item_get()).is_none());
}

#[test]
fn a_failed_call_is_not_an_unusable_reply_a1() {
    let r = FakeRunner::new([Output::failure(1)]);
    let _ = r.write(&Call::new("op", &["item", "edit", "deploy"]));
    assert!(take_unusable_reply(&item_get()).is_none());
}
