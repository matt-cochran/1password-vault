//! `opv unseal --exec` (#271, design sealed-target §5.5, lane st-u2): a verified, decrypted
//! sealed bundle delivered to a real child process (`sh -c …`), with no plaintext at rest
//! beyond the RAM directory of the file keys. Bundles are sealed here with the stock-tool
//! fixture signer and identity (`tests/fixtures/sealed/kat/`); every value is a marker, and
//! no test prints one. One behavioural assertion each.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use opv::bundle::crypto::{parse_identity, parse_signing_key, recipient_fingerprint, seal};
use opv::bundle::format::{Header, Name};

/// The bundle's variable, a marker only.
const TOKEN_MARKER: &str = "S7MARKERunsealtoken0001";
/// The bundle's `PORT`, which an inherited `PORT` must not shadow.
const PORT_BUNDLE: &str = "S7MARKERunsealport0001";
/// An inherited `PORT`, as an image's `ENV PORT` would set it.
const PORT_INHERITED: &str = "S7MARKERinheritedport0001";
/// The file key's value.
const FILE_MARKER: &str = "S7MARKERunsealfile0001";

fn kat(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sealed/kat")
        .join(name)
}

fn kat_str(name: &str) -> String {
    std::fs::read_to_string(kat(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// One delivered entry: name, destination, value.
type Entry<'a> = (&'a str, &'a str, &'a str);

/// Seal `entries` for `prod/api` to the fixture identity with the fixture signer, into a
/// fresh directory (kept alive by the returned guard).
fn bundle(entries: &[Entry<'_>], secrets_dir_env: Option<&str>) -> (tempfile::TempDir, PathBuf) {
    let identity = parse_identity(&kat_str("age-identity.txt")).expect("fixture identity");
    let key = parse_signing_key(&kat_str("signer_ed25519")).expect("fixture signer");
    let header = Header {
        format: "opv-sealed/1".into(),
        project: "fleet".into(),
        environment: "prod".into(),
        product: "api".into(),
        target: "box".into(),
        revision: 11,
        created_at: "2026-11-05T12:00:00Z".into(),
        opv_version: "0.18.0".into(),
        plan_id: "plan_exec0001".into(),
        contract_digest: "sha256:00".into(),
        recipients: vec![recipient_fingerprint(&identity.recipient())],
        signer: key.fingerprint(),
        names: entries
            .iter()
            .map(|(name, destination, _)| Name {
                name: (*name).into(),
                destination: (*destination).into(),
            })
            .collect(),
        secrets_dir_env: secrets_dir_env.map(str::to_string),
    };
    let values: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(name, _, value)| (*name, value.as_bytes()))
        .collect();
    let sealed = seal(&header, &values, &[identity.recipient()], &key).expect("seal");
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("api.opv-sealed");
    std::fs::write(&path, sealed).expect("write bundle");
    (dir, path)
}

/// A bundle of variables only: `API_TOKEN` and `PORT`.
fn variables_bundle() -> (tempfile::TempDir, PathBuf) {
    bundle(
        &[
            ("API_TOKEN", "env:API_TOKEN", TOKEN_MARKER),
            ("PORT", "env:PORT", PORT_BUNDLE),
        ],
        None,
    )
}

/// A bundle with one file key (`tls/key` under `$SECRETS_DIR`) and one variable.
fn files_bundle() -> (tempfile::TempDir, PathBuf) {
    bundle(
        &[
            ("API_TOKEN", "env:API_TOKEN", TOKEN_MARKER),
            ("TLS_KEY", "file:tls/key", FILE_MARKER),
        ],
        Some("SECRETS_DIR"),
    )
}

/// `opv unseal <bundle> … --exec -- sh -c <script>` with a clean environment plus `env`.
/// The identity comes from the fixture file unless `env` passes `--identity-env`'s variable
/// and `identity_env` names it.
fn unseal_cmd(
    bundle: &Path,
    identity_env: Option<&str>,
    env: &[(&str, &str)],
    script: &str,
) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_opv"));
    c.arg("unseal")
        .arg(bundle)
        .args(["--env", "prod", "--product", "api", "--signers"])
        .arg(kat("allowed_signers"));
    match identity_env {
        Some(var) => c.args(["--identity-env", var]),
        None => c.arg("--identity-file").arg(kat("age-identity.txt")),
    };
    c.args(["--exec", "--", "sh", "-c", script])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .envs(env.iter().copied());
    c
}

fn run(bundle: &Path, env: &[(&str, &str)], script: &str) -> Output {
    unseal_cmd(bundle, None, env, script)
        .output()
        .expect("opv starts")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// The names (never the values) of the child's environment, from `env`.
fn names_seen(o: &Output) -> Vec<String> {
    stdout(o)
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k.to_string()))
        .collect()
}

#[test]
fn the_child_sees_the_bundles_variables() {
    let (_d, b) = variables_bundle();
    let o = run(&b, &[], "printf %s \"$API_TOKEN\"");
    assert!(stdout(&o) == TOKEN_MARKER, "the child got API_TOKEN");
}

#[test]
fn the_bundle_wins_over_an_inherited_variable_of_the_same_name() {
    let (_d, b) = variables_bundle();
    let o = run(&b, &[("PORT", PORT_INHERITED)], "printf %s \"$PORT\"");
    assert!(stdout(&o) == PORT_BUNDLE, "the bundle's PORT replaced it");
}

#[test]
fn an_overridden_variable_gets_one_notice_naming_it_and_no_value() {
    let (_d, b) = variables_bundle();
    let o = run(&b, &[("PORT", PORT_INHERITED)], "true");
    let err = stderr(&o);
    let notices: Vec<&str> = err.lines().filter(|l| l.contains("replaces")).collect();
    assert!(
        notices == ["opv unseal: PORT from the bundle replaces the inherited value"]
            && !err.contains("S7MARKER"),
        "one names-only notice"
    );
}

#[test]
fn no_1password_variable_or_identity_variable_reaches_the_child() {
    let (_d, b) = variables_bundle();
    let identity = kat_str("age-identity.txt");
    let o = unseal_cmd(
        &b,
        Some("APP_AGE_IDENTITY"),
        &[
            ("APP_AGE_IDENTITY", identity.as_str()),
            ("OP_SERVICE_ACCOUNT_TOKEN", "S7MARKERoptoken0001"),
            ("OP_SESSION_x", "S7MARKERopsession0001"),
        ],
        "env",
    )
    .output()
    .expect("opv starts");
    let names = names_seen(&o);
    assert!(
        names.contains(&"API_TOKEN".to_string())
            && !names
                .iter()
                .any(|n| n.starts_with("OP_") || n == "APP_AGE_IDENTITY"),
        "the child's environment is scrubbed: {names:?}"
    );
}

#[test]
fn the_childs_exit_code_is_passed_through() {
    let (_d, b) = variables_bundle();
    let o = run(&b, &[], "exit 42");
    assert_eq!(o.status.code(), Some(42));
}

#[test]
fn with_variables_only_the_command_replaces_opv() {
    let (_d, b) = variables_bundle();
    let child = unseal_cmd(&b, None, &[], "echo $$")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("opv starts");
    let pid = child.id();
    let o = child.wait_with_output().expect("wait");
    assert_eq!(stdout(&o).trim(), pid.to_string());
}

#[test]
fn json_with_exec_is_refused_as_usage() {
    let (_d, b) = variables_bundle();
    let o = Command::new(env!("CARGO_BIN_EXE_opv"))
        .arg("unseal")
        .arg(&b)
        .args(["--env", "prod", "--product", "api", "--signers"])
        .arg(kat("allowed_signers"))
        .arg("--identity-file")
        .arg(kat("age-identity.txt"))
        .args(["--json", "--exec", "--", "true"])
        .output()
        .expect("opv starts");
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn json_without_exec_lists_the_names_the_bundle_would_override() {
    let (_d, b) = variables_bundle();
    let o = Command::new(env!("CARGO_BIN_EXE_opv"))
        .arg("unseal")
        .arg(&b)
        .args(["--env", "prod", "--product", "api", "--signers"])
        .arg(kat("allowed_signers"))
        .args(["--verify-only", "--json"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("PORT", PORT_INHERITED)
        .output()
        .expect("opv starts");
    let doc: serde_json::Value = serde_json::from_slice(&o.stdout).expect("one JSON document");
    assert_eq!(doc["overridden"], serde_json::json!(["PORT"]));
}

// --- file keys: a supervised private RAM directory (Linux) ---------------------------------

/// A private tmpfs directory for `$XDG_RUNTIME_DIR`, owned by this test; `None` where the
/// machine has no RAM directory (the file scenarios are then skipped).
#[cfg(target_os = "linux")]
fn runtime_dir() -> Option<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::Builder::new().tempdir_in("/dev/shm").ok()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).ok()?;
    let st = rustix::fs::statfs(dir.path()).ok()?;
    #[allow(clippy::unnecessary_cast)]
    let magic = (st.f_type as u64) & 0xffff_ffff;
    (magic == 0x0102_1994).then_some(dir)
}

#[cfg(target_os = "linux")]
fn run_with_files(script: &str) -> Option<(Output, PathBuf)> {
    let rt = runtime_dir()?;
    let (_d, b) = files_bundle();
    let rt_path = rt.path().to_str().expect("utf-8").to_string();
    let o = run(&b, &[("XDG_RUNTIME_DIR", rt_path.as_str())], script);
    Some((o, rt.path().to_path_buf()))
}

#[cfg(target_os = "linux")]
#[test]
fn a_file_key_lands_0400_in_a_0700_ram_directory() {
    let Some((o, _rt)) = run_with_files("stat -c %a \"$SECRETS_DIR\" \"$SECRETS_DIR/tls/key\"")
    else {
        return;
    };
    assert_eq!(stdout(&o), "700\n400\n");
}

#[cfg(target_os = "linux")]
#[test]
fn a_file_key_holds_its_value() {
    let script = format!("[ \"$(cat \"$SECRETS_DIR/tls/key\")\" = '{FILE_MARKER}' ] && echo same");
    let Some((o, _rt)) = run_with_files(&script) else {
        return;
    };
    assert_eq!(stdout(&o), "same\n");
}

#[cfg(target_os = "linux")]
#[test]
fn the_ram_directory_is_removed_when_the_child_exits() {
    let Some((o, rt)) = run_with_files("echo \"$SECRETS_DIR\"") else {
        return;
    };
    let dir = PathBuf::from(stdout(&o).trim());
    assert!(
        dir.starts_with(&rt) && !dir.exists(),
        "{} was removed",
        dir.display()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_file_key_is_not_a_variable() {
    let Some((o, _rt)) = run_with_files("env") else {
        return;
    };
    assert!(!names_seen(&o).contains(&"TLS_KEY".to_string()));
}

#[cfg(target_os = "linux")]
#[test]
fn sigterm_is_forwarded_to_the_supervised_child_and_its_code_passed_through() {
    use std::io::{BufRead as _, BufReader};
    let Some(rt) = runtime_dir() else { return };
    let (_d, b) = files_bundle();
    let rt_path = rt.path().to_str().expect("utf-8").to_string();
    let mut child = unseal_cmd(
        &b,
        None,
        &[("XDG_RUNTIME_DIR", rt_path.as_str())],
        "trap 'exit 7' TERM; echo ready; while :; do sleep 0.05; done",
    )
    .stdout(std::process::Stdio::piped())
    .spawn()
    .expect("opv starts");
    let mut line = String::new();
    BufReader::new(child.stdout.take().expect("stdout"))
        .read_line(&mut line)
        .expect("ready");
    // SAFETY: a plain kill on the pid of the child this test spawned and has not reaped.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    assert_eq!(child.wait().expect("wait").code(), Some(7));
}

#[test]
fn file_keys_without_a_ram_directory_are_refused_before_the_child_starts() {
    let (_d, b) = files_bundle();
    let marker = tempfile::tempdir().expect("tempdir");
    let started = marker.path().join("started");
    let o = run(
        &b,
        &[],
        &format!("touch '{}'", started.to_str().expect("utf-8")),
    );
    assert!(
        o.status.code() == Some(6) && !started.exists(),
        "refused, nothing started: {}",
        stderr(&o)
    );
}
