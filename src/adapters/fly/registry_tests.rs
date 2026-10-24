//! Behaviour of `registry-push` (#234, `docs/design/provider-operations.md` §5.3, T5-T10):
//! one scenario and one assertion each. The docker replies are built from docker's
//! documented output, never recorded (owner decision §8.1); replace them with the S1
//! recordings when they exist.

use std::cell::RefCell;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::*;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const TOKEN: &str = "FlyV1 fm2_FIXTUREVALUE_registry_token";
const IMAGE: &str = "registry.fly.io/shop:v2";
const ENDPOINT: &str = "unix:///var/run/docker.sock";
const DIGEST: &str = "sha256:4c6f1d5b0c3e8a9f2d7b1e6a5c4d3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c";

// unrecorded: built from docker docs (`docker login`, `docker push`), replace with S1 (#234 §8.1)
const LOGIN_OK: &str = "Login Succeeded\n";
const LOGIN_UNAUTHORIZED: &str = "Error response from daemon: Get \"https://registry.fly.io/v2/\": unauthorized: not authorized\n";
const LOGIN_NETWORK: &str = "Error response from daemon: Get \"https://registry.fly.io/v2/\": dial tcp: lookup registry.fly.io: no such host\n";
const PUSH_FAILED: &str = "error parsing HTTP 502 response body: unexpected end of JSON input\n";

fn push_ok() -> String {
    format!(
        "The push refers to repository [registry.fly.io/shop]\n5f70bf18a086: Pushed\nv2: digest: {DIGEST} size: 1570\n"
    )
}

/// What the stand-in docker writes into `config.json` at login: the file store, or a helper.
const FILE_STORE: &str =
    r#"{"auths":{"opv.invalid":{},"registry.fly.io":{"auth":"eDpGSVhUVVJF"}}}"#;
const HELPER_STORE: &str =
    r#"{"auths":{"opv.invalid":{},"registry.fly.io":{}},"credsStore":"secretservice"}"#;

/// A FakeRunner whose docker writes `store` at login, as docker does, and records the
/// modes of the private directory and of `config.json` while each docker child runs.
struct Docker {
    fake: FakeRunner,
    store: &'static str,
    modes: RefCell<Vec<(u32, u32)>>,
}

impl Docker {
    fn new(store: &'static str) -> Self {
        let fake = FakeRunner::new([crate::app::testutil::item(&[crate::app::testutil::secret(
            "",
            "FLY_API_TOKEN",
            TOKEN,
        )])]);
        Self {
            fake,
            store,
            modes: RefCell::default(),
        }
    }

    fn child(&self, call: &Call) {
        let Some((_, dir)) = call.env.iter().find(|(k, _)| *k == "DOCKER_CONFIG") else {
            return;
        };
        let mode = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.permissions().mode() & 0o777);
        let config = Path::new(dir).join("config.json");
        self.modes
            .borrow_mut()
            .push((mode(Path::new(dir)), mode(&config)));
        if call.args.first() == Some(&"login") {
            std::fs::write(&config, self.store).unwrap();
        }
    }
}

impl CommandRunner for Docker {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.child(call);
        self.fake.read(call, refused)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.child(call);
        self.fake.write(call)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        self.fake.probe(call, limit)
    }
    fn pause(&self, d: Duration, note: &str) {
        self.fake.pause(d, note);
    }
    fn note(&self, line: &str) {
        self.fake.note(line);
    }
    fn run_inherited(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<i32> {
        self.fake.run_inherited(program, args, env)
    }
}

/// A world whose login answers `login` (stdout, or exit 1 with that stderr) and whose push
/// answers `push`.
fn world(
    store: &'static str,
    login: Result<&str, &str>,
    push: Option<Result<String, &str>>,
) -> Docker {
    let d = Docker::new(store);
    match login {
        Ok(out) => d
            .fake
            .responses
            .borrow_mut()
            .push_back(Ok(Output::success(out))),
        Err(stderr) => d.fake.push_with_stderr(Output::failure(1), stderr),
    }
    match push {
        Some(Ok(out)) => d
            .fake
            .responses
            .borrow_mut()
            .push_back(Ok(Output::success(out))),
        Some(Err(stderr)) => d.fake.push_with_stderr(Output::failure(1), stderr),
        None => {}
    }
    d
}

fn ok_world() -> Docker {
    world(FILE_STORE, Ok(LOGIN_OK), Some(Ok(push_ok())))
}

/// Run the push in a fresh runtime directory; the directory stays for the leftover check.
fn run(d: &Docker) -> (Result<String, Error>, tempfile::TempDir) {
    let runtime = tempfile::tempdir().unwrap();
    let item = ItemRef {
        vault: "vprod".into(),
        item: "ideploy".into(),
    };
    let req = PushRequest {
        env: "prod",
        target: "web",
        app: "shop",
        item: &item,
        image: IMAGE,
        endpoint: ENDPOINT,
        runtime: runtime.path(),
    };
    (registry_push(d, &req), runtime)
}

fn leftovers(runtime: &tempfile::TempDir) -> Vec<PathBuf> {
    std::fs::read_dir(runtime.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect()
}

fn code(d: &Docker) -> (&'static str, i32) {
    let e = run(d).0.expect_err("the push fails");
    (e.code_str(), e.exit_code())
}

fn docker_calls(d: &Docker) -> Vec<Vec<String>> {
    d.fake
        .calls
        .borrow()
        .iter()
        .filter(|c| c.program == "docker")
        .map(|c| c.args.clone())
        .collect()
}

// --- T6: the token reaches docker on stdin only -------------------------------------------

#[test]
fn the_login_reads_the_token_on_stdin() {
    let d = ok_world();
    run(&d).0.unwrap();
    assert_eq!(
        d.fake.calls.borrow()[1].stdin.as_deref(),
        Some(TOKEN.as_bytes())
    );
}

#[test]
fn no_argv_holds_the_token() {
    let d = ok_world();
    run(&d).0.unwrap();
    assert!(!d.fake.argv_contains("FIXTUREVALUE"));
}

#[test]
fn no_child_env_holds_the_token_by_name_or_value() {
    let d = ok_world();
    run(&d).0.unwrap();
    assert!(d.fake.calls.borrow().iter().all(|c| {
        c.env
            .iter()
            .all(|(k, v)| !k.contains("FIXTUREVALUE") && !v.contains("FIXTUREVALUE"))
    }));
}

#[test]
fn docker_children_get_only_their_config_dir_and_the_resolved_endpoint() {
    let d = ok_world();
    run(&d).0.unwrap();
    let calls = d.fake.calls.borrow();
    assert!(calls.iter().filter(|c| c.program == "docker").all(|c| {
        c.isolated
            && c.env.len() == 2
            && c.env[0].0 == "DOCKER_CONFIG"
            && c.env[1] == ("DOCKER_HOST".to_string(), ENDPOINT.to_string())
    }));
}

#[test]
fn the_calls_are_login_then_push_with_fixed_argv() {
    let d = ok_world();
    run(&d).0.unwrap();
    assert_eq!(
        docker_calls(&d),
        [
            LOGIN_ARGS.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            vec!["push".to_string(), IMAGE.to_string()],
        ]
    );
}

#[test]
fn the_token_and_its_docker_encoding_are_scrubbed() {
    let d = ok_world();
    run(&d).0.unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("x:{TOKEN}").as_bytes());
    assert!(!crate::scrub::scrub(&format!("{TOKEN} {encoded}")).contains("FIXTUREVALUE"));
}

// --- T8: private while the child runs; a helper store fails closed -------------------------

#[test]
fn the_config_dir_is_0700_while_each_child_runs() {
    let d = ok_world();
    run(&d).0.unwrap();
    assert!(d.modes.borrow().iter().all(|(dir, _)| *dir == 0o700));
}

#[test]
fn the_config_file_is_0600_while_each_child_runs() {
    let d = ok_world();
    run(&d).0.unwrap();
    assert!(d.modes.borrow().iter().all(|(_, file)| *file == 0o600));
}

#[test]
fn a_creds_store_after_login_refuses_before_the_push() {
    let d = world(HELPER_STORE, Ok(LOGIN_OK), None);
    assert_eq!(code(&d), ("policy_refused", 6));
}

#[test]
fn a_creds_store_after_login_removes_the_dir() {
    let d = world(HELPER_STORE, Ok(LOGIN_OK), None);
    let (_, runtime) = run(&d);
    assert!(leftovers(&runtime).is_empty());
}

#[test]
fn the_seed_never_follows_a_planted_link() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::os::unix::fs::symlink(dir.path().join("elsewhere"), &path).unwrap();
    assert!(write_seed(&path).is_err());
}

// --- T7: the directory is gone on every exit path -------------------------------------------

#[test]
fn no_config_dir_remains_after_success() {
    let d = ok_world();
    let (_, runtime) = run(&d);
    assert!(leftovers(&runtime).is_empty());
}

#[test]
fn no_config_dir_remains_after_a_refused_login() {
    let d = world(FILE_STORE, Err(LOGIN_UNAUTHORIZED), None);
    let (_, runtime) = run(&d);
    assert!(leftovers(&runtime).is_empty());
}

#[test]
fn no_config_dir_remains_after_a_failed_push() {
    let d = world(FILE_STORE, Ok(LOGIN_OK), Some(Err(PUSH_FAILED)));
    let (_, runtime) = run(&d);
    assert!(leftovers(&runtime).is_empty());
}

#[test]
fn no_config_dir_remains_after_a_push_without_a_digest() {
    let d = world(FILE_STORE, Ok(LOGIN_OK), Some(Ok("v2: pushed\n".into())));
    let (_, runtime) = run(&d);
    assert!(leftovers(&runtime).is_empty());
}

// --- T9: the digest, and each failure by its step -------------------------------------------

#[test]
fn the_pushed_digest_is_reported() {
    assert_eq!(run(&ok_world()).0.unwrap(), DIGEST);
}

#[test]
fn a_digest_that_is_not_64_hex_is_not_one() {
    assert_eq!(pushed_digest("v2: digest: sha256:abc size: 1\n"), None);
}

#[test]
fn an_unauthorized_login_is_the_deploy_credentials_rejection() {
    let d = world(FILE_STORE, Err(LOGIN_UNAUTHORIZED), None);
    assert_eq!(code(&d), ("deploy_credentials_failed", 7));
}

#[test]
fn an_unauthorized_login_pushes_nothing() {
    let d = world(FILE_STORE, Err(LOGIN_UNAUTHORIZED), None);
    let _ = run(&d);
    assert_eq!(docker_calls(&d).len(), 1);
}

#[test]
fn any_other_failed_login_is_unavailable() {
    let d = world(FILE_STORE, Err(LOGIN_NETWORK), None);
    assert_eq!(code(&d), ("provider_unavailable", 9));
}

#[test]
fn a_failed_push_is_outcome_unknown() {
    let d = world(FILE_STORE, Ok(LOGIN_OK), Some(Err(PUSH_FAILED)));
    assert_eq!(code(&d), ("outcome_unknown", 9));
}

#[test]
fn a_killed_push_is_outcome_unknown() {
    let d = world(FILE_STORE, Ok(LOGIN_OK), None);
    d.fake.push_unknown("killed");
    assert_eq!(code(&d), ("outcome_unknown", 9));
}

#[test]
fn a_failed_push_is_not_retried() {
    let d = world(FILE_STORE, Ok(LOGIN_OK), Some(Err(PUSH_FAILED)));
    let _ = run(&d);
    assert_eq!(docker_calls(&d).len(), 2);
}

#[test]
fn a_push_without_a_digest_is_unexpected_output() {
    let d = world(FILE_STORE, Ok(LOGIN_OK), Some(Ok("v2: pushed\n".into())));
    assert_eq!(code(&d), ("unexpected_output", 5));
}
