//! Remote development delivery (#139): the payload, the pinned SSH call, the remote
//! environment, the profile rules and `opv run --remote`. One atomic scenario per test, one
//! assertion each. Fixture values are markers, never credentials.

use super::*;
use crate::app::testutil::*;
use crate::runner::fake::FakeRunner;

const MARKER: &str = "test-marker-value-139";
const PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----\nTESTMARKER139\n-----END PRIVATE KEY-----\n";
const HOST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestMarkerHostKeyNotARealKey139";

fn header() -> Header {
    Header {
        keys: vec!["SERVE_TOKEN".into(), "GITHUB_APP_PRIVATE_KEY".into()],
        files: vec![(
            "GITHUB_APP_PRIVATE_KEY".into(),
            "github-app/private-key".into(),
        )],
        dir_env: Some("JZ_VAULT_DIR".into()),
        workdir: "/home/dev/src/app".into(),
        command: vec!["cargo".into(), "run".into()],
        outer: None,
    }
}

fn payload() -> Zeroizing<Vec<u8>> {
    encode(&header(), &[MARKER.as_bytes(), PEM]).unwrap()
}

fn decoded(bytes: &[u8]) -> Result<Decoded, Refusal> {
    decode(&mut &bytes[..])
}

fn plan() -> Plan {
    Plan {
        profile: "builder".into(),
        host: "builder.example.internal".into(),
        port: 2222,
        user: "dev".into(),
        host_key: HOST_KEY.into(),
        identity_file: None,
        opv: "/usr/local/bin/opv".into(),
        header: header(),
    }
}

fn args() -> Vec<String> {
    ssh_args(&plan(), Path::new("/run/user/1000/opv-ssh.1/known_hosts"))
}

/// The value after `-o` that starts with `name=`.
fn option(name: &str) -> Option<String> {
    args()
        .windows(2)
        .find(|w| w[0] == "-o" && w[1].starts_with(&format!("{name}=")))
        .map(|w| w[1].clone())
}

// --- the payload ----------------------------------------------------------------------

#[test]
fn a_pem_value_arrives_byte_for_byte() {
    let (_, values) = decoded(&payload()).unwrap();
    assert_eq!(&values[1][..], PEM);
}

#[test]
fn the_header_arrives_unchanged() {
    let (h, _) = decoded(&payload()).unwrap();
    assert_eq!(h, header());
}

#[test]
fn a_payload_cut_inside_a_value_is_refused() {
    let p = payload();
    assert!(decoded(&p[..p.len() - 10]).is_err());
}

#[test]
fn a_payload_without_its_commit_marker_is_refused() {
    let p = payload();
    assert!(decoded(&p[..p.len() - END.len()]).is_err());
}

#[test]
fn a_payload_of_another_protocol_is_refused() {
    let mut p = payload().to_vec();
    p[11] = b'9';
    assert!(decoded(&p).is_err());
}

#[test]
fn a_refusal_never_quotes_a_value() {
    let p = payload();
    let Refusal(why) = decoded(&p[..p.len() - 10]).unwrap_err();
    assert!(
        !why.contains(MARKER) && !why.contains("TESTMARKER139"),
        "{why}"
    );
}

#[test]
fn an_op_key_name_is_refused_by_the_receiver() {
    let mut h = header();
    h.keys[0] = "OP_SESSION_my".into();
    assert!(check_header(&h).is_err());
}

#[test]
fn a_file_path_that_climbs_out_is_refused_by_the_receiver() {
    let mut h = header();
    h.files[0].1 = "../escape".into();
    assert!(check_header(&h).is_err());
}

#[test]
fn a_relative_working_directory_is_refused_by_the_receiver() {
    let mut h = header();
    h.workdir = "src/app".into();
    assert!(check_header(&h).is_err());
}

#[test]
fn file_keys_without_a_directory_variable_are_refused() {
    let mut h = header();
    h.dir_env = None;
    assert!(check_header(&h).is_err());
}

// --- the pinned SSH call --------------------------------------------------------------

#[test]
fn ssh_reads_no_configuration_file() {
    assert_eq!(&args()[..2], ["-F", "none"]);
}

#[test]
fn ssh_checks_the_host_key_strictly() {
    assert_eq!(
        option("StrictHostKeyChecking").as_deref(),
        Some("StrictHostKeyChecking=yes")
    );
}

#[test]
fn ssh_never_forwards_the_agent() {
    assert_eq!(option("ForwardAgent").as_deref(), Some("ForwardAgent=no"));
}

#[test]
fn ssh_never_shares_a_connection() {
    assert_eq!(option("ControlPath").as_deref(), Some("ControlPath=none"));
}

#[test]
fn ssh_never_asks_a_question() {
    assert_eq!(option("BatchMode").as_deref(), Some("BatchMode=yes"));
}

#[test]
fn the_remote_command_is_the_fixed_receiver() {
    assert_eq!(
        args().last().map(String::as_str),
        Some("/usr/local/bin/opv remote-receive")
    );
}

#[test]
fn the_known_hosts_line_holds_only_the_pinned_key() {
    assert_eq!(
        known_hosts_line(&plan()),
        format!("opv-remote-builder {HOST_KEY}\n")
    );
}

#[test]
fn ssh_looks_the_host_up_under_the_profile_alias() {
    assert_eq!(
        option("HostKeyAlias").as_deref(),
        Some("HostKeyAlias=opv-remote-builder")
    );
}

#[test]
fn no_value_reaches_ssh_arguments() {
    assert!(args().iter().all(|a| !a.contains(MARKER)));
}

#[test]
fn ssh_gets_no_op_credential() {
    let inherited = vec![
        ("OP_SESSION_my".to_string(), MARKER.to_string()),
        ("PATH".to_string(), "/usr/bin".to_string()),
    ];
    assert!(
        ssh_env(&inherited)
            .iter()
            .all(|(k, _)| !k.starts_with("OP_"))
    );
}

#[test]
fn ssh_gets_no_resolved_key() {
    let inherited = vec![
        ("SERVE_TOKEN".to_string(), MARKER.to_string()),
        ("SSH_AUTH_SOCK".to_string(), "/run/agent".to_string()),
    ];
    assert!(ssh_env(&inherited).iter().all(|(_, v)| v != MARKER));
}

#[test]
fn ssh_keeps_the_agent_socket() {
    let inherited = vec![("SSH_AUTH_SOCK".to_string(), "/run/agent".to_string())];
    assert_eq!(ssh_env(&inherited).len(), 1);
}

// --- the remote environment -----------------------------------------------------------

fn remote_names(session: &[(String, String)]) -> Vec<String> {
    let values = vec![
        Zeroizing::new(MARKER.as_bytes().to_vec()),
        Zeroizing::new(PEM.to_vec()),
    ];
    remote_env(
        &header(),
        &values,
        session,
        Some("/run/user/1000/opv-remote.1"),
    )
    .unwrap()
    .into_iter()
    .map(|(k, _)| k.into_string().unwrap())
    .collect()
}

#[test]
fn the_remote_app_gets_its_variable_key() {
    assert!(remote_names(&[]).contains(&"SERVE_TOKEN".to_string()));
}

#[test]
fn the_remote_app_gets_no_file_key_as_a_variable() {
    assert!(!remote_names(&[]).contains(&"GITHUB_APP_PRIVATE_KEY".to_string()));
}

#[test]
fn the_remote_app_gets_the_directory_variable() {
    assert!(remote_names(&[]).contains(&"JZ_VAULT_DIR".to_string()));
}

#[test]
fn the_remote_app_gets_nothing_else_of_the_remote_session() {
    let session = vec![
        ("AWS_SECRET_ACCESS_KEY".to_string(), MARKER.to_string()),
        ("OP_SERVICE_ACCOUNT_TOKEN".to_string(), MARKER.to_string()),
        ("PATH".to_string(), "/usr/bin".to_string()),
    ];
    let names = remote_names(&session);
    assert_eq!(names, ["PATH", "SERVE_TOKEN", "JZ_VAULT_DIR"]);
}

#[test]
fn a_variable_key_holding_a_nul_byte_is_refused() {
    let values = vec![
        Zeroizing::new(b"a\0b".to_vec()),
        Zeroizing::new(PEM.to_vec()),
    ];
    assert!(remote_env(&header(), &values, &[], None).is_err());
}

// --- profile rules at load --------------------------------------------------------------

fn profile(fields: &str) -> String {
    format!(
        "{ROLE_KEYS}\n[products.allumata.remotes.builder]\nhost = \"builder.example.internal\"\n\
         user = \"dev\"\nhost_key = \"{HOST_KEY}\"\nopv = \"/usr/local/bin/opv\"\n\
         workdir = \"/home/dev/src/app\"\ncommand = [\"cargo\", \"run\"]\n{fields}\n"
    )
}

fn loads(fields: &str) -> Result<crate::domain::Fleet, Error> {
    let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
    crate::config::parse(&format!("{text}\n{}", profile(fields)))
}

fn remote_fleet() -> crate::domain::Fleet {
    loads("environments = [\"prod\"]\nroles = [\"serve\"]").unwrap()
}

#[test]
fn a_reviewed_profile_loads() {
    assert!(loads("environments = [\"prod\"]").is_ok());
}

#[test]
fn a_profile_for_an_undefined_environment_is_refused() {
    assert!(loads("environments = [\"nowhere\"]").is_err());
}

#[test]
fn a_profile_with_no_environment_is_refused() {
    assert!(loads("environments = []").is_err());
}

#[test]
fn a_profile_for_an_undeclared_role_is_refused() {
    assert!(loads("environments = [\"prod\"]\nroles = [\"admin\"]").is_err());
}

#[test]
fn a_host_that_looks_like_an_ssh_option_is_refused() {
    let text = profile("environments = [\"prod\"]")
        .replace("builder.example.internal", "-oProxyCommand=x");
    let base = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
    assert!(crate::config::parse(&format!("{base}\n{text}")).is_err());
}

#[test]
fn a_host_key_with_a_host_name_is_refused() {
    let text =
        profile("environments = [\"prod\"]").replace(HOST_KEY, &format!("builder {HOST_KEY}"));
    let base = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
    assert!(crate::config::parse(&format!("{base}\n{text}")).is_err());
}

#[test]
fn a_remote_opv_path_with_shell_characters_is_refused() {
    let text =
        profile("environments = [\"prod\"]").replace("/usr/local/bin/opv", "/usr/bin/opv;rm");
    let base = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
    assert!(crate::config::parse(&format!("{base}\n{text}")).is_err());
}

// --- opv run --remote -------------------------------------------------------------------

fn remote_run(env: &str, role: &str) -> (Result<i32, Error>, FakeRunner) {
    let r = FakeRunner::new([crate::runner::Output::success(Vec::new())]);
    let res = crate::app::run::run_remote(
        &remote_fleet(),
        env,
        Some("allumata"),
        Some(role),
        "builder",
        &r,
    );
    (res, r)
}

#[test]
fn a_remote_run_starts_the_remote_step_under_op_run() {
    let (_, r) = remote_run("prod", "serve");
    assert_eq!(r.calls.borrow()[0].args[3], "remote-send");
}

#[test]
fn a_remote_run_passes_references_never_values() {
    let (_, r) = remote_run("prod", "serve");
    assert!(
        r.calls.borrow()[0]
            .env
            .iter()
            .all(|(_, v)| v.starts_with("op://"))
    );
}

#[test]
fn a_remote_run_never_sends_another_roles_key() {
    let (_, r) = remote_run("prod", "serve");
    let plan = r.calls.borrow()[0].args[5].clone();
    assert!(!plan.contains("DATABASE_URL_UNPOOLED"), "{plan}");
}

#[test]
fn a_remote_run_for_an_environment_the_profile_does_not_allow_is_refused() {
    let (res, _) = remote_run("staging", "serve");
    assert_eq!(res.unwrap_err().code_str(), "policy_refused");
}

#[test]
fn a_refused_remote_run_reads_nothing() {
    let (_, r) = remote_run("staging", "serve");
    assert!(r.calls.borrow().is_empty());
}

#[test]
fn a_remote_run_for_a_role_the_profile_does_not_allow_is_refused() {
    let (res, _) = remote_run("prod", "migrate");
    assert_eq!(res.unwrap_err().code_str(), "policy_refused");
}

/// The catalog names the undeclared profile (`unknown_profile`, was `usage`).
#[test]
fn an_unknown_profile_is_an_undeclared_name() {
    let r = FakeRunner::new([]);
    let res = crate::app::run::run_remote(
        &remote_fleet(),
        "prod",
        Some("allumata"),
        Some("serve"),
        "elsewhere",
        &r,
    );
    assert_eq!(res.unwrap_err().code_str(), "unknown_profile");
}

fn refusal_text(env: &str, role: &str) -> String {
    let (res, _) = remote_run(env, role);
    match res.unwrap_err().cause() {
        Some((c, _)) => crate::cause::render::render_text(
            c,
            None,
            &crate::cause::Invocation::from_cli(&[
                "opv".into(),
                "run".into(),
                env.into(),
                "--remote".into(),
                "builder".into(),
            ]),
            false,
            false,
            false,
        ),
        None => String::new(),
    }
}

/// 07.20: a profile's refusal never steps to the run it just refused.
#[test]
fn a_refused_environment_never_steps_to_the_same_run() {
    assert!(!refusal_text("staging", "serve").contains("Next: opv run staging"));
}

/// 07.20: the refusal names what the profile allows.
#[test]
fn a_refused_environment_names_the_allowed_ones() {
    assert!(refusal_text("staging", "serve").contains("it allows prod"));
}

// --- remote-send: SSH's stderr and the receiver's handshake (07.08, 07.19) -------------

fn relayed(stderr: &str) -> (Relayed, String) {
    let mut out = Vec::new();
    let seen = relay_stderr(&mut stderr.as_bytes(), &mut out);
    (seen, String::from_utf8(out).unwrap())
}

#[test]
fn the_receivers_handshake_line_is_not_shown() {
    let (_, shown) = relayed("OPV-REMOTE READY 1\nOPV-REMOTE DELIVERED\napp says hi\n");
    assert_eq!(shown, "app says hi\n");
}

#[test]
fn the_receivers_handshake_names_its_protocol() {
    let (seen, _) = relayed("OPV-REMOTE READY 2\n");
    assert_eq!(seen.protocol, Some(2));
}

#[test]
fn ssh_messages_before_the_handshake_are_shown() {
    let (_, shown) = relayed("ssh: connect to host h port 22: Connection refused\n");
    assert!(shown.contains("Connection refused"));
}

#[test]
fn the_payload_is_confirmed_by_the_delivered_line() {
    let (seen, _) = relayed("OPV-REMOTE READY 1\nOPV-REMOTE DELIVERED\n");
    assert!(seen.delivered);
}

/// 07.19: a receiver of another protocol is a version mismatch, whatever SSH's code.
#[test]
fn a_receiver_of_another_protocol_is_a_version_mismatch() {
    let (seen, _) = relayed("OPV-REMOTE READY 2\n");
    let e = ssh_outcome(&plan(), &args(), 3, &seen).unwrap_err();
    assert_eq!(e.code_str(), "remote_version_mismatch");
}

/// R77: after delivery, a code SSH did not fail with is the remote app's own.
#[test]
fn the_remote_apps_own_exit_code_passes_through() {
    let (seen, _) = relayed("OPV-REMOTE READY 1\nOPV-REMOTE DELIVERED\n");
    assert_eq!(ssh_outcome(&plan(), &args(), 7, &seen).unwrap(), 7);
}

/// 07.08: a refused connection before the handshake is the pinned host's reachability.
#[test]
fn a_refused_connection_before_the_handshake_is_unreachable() {
    let (seen, _) = relayed("ssh: connect to host h port 2222: Connection refused\n");
    let e = ssh_outcome(&plan(), &args(), 255, &seen).unwrap_err();
    assert_eq!(e.code_str(), "remote_unreachable");
}

/// The session's end after delivery is a disconnect, not the app's exit (RemoteDisconnected).
#[test]
fn a_session_closed_after_delivery_is_a_disconnect() {
    let (seen, _) = relayed(
        "OPV-REMOTE READY 1\nOPV-REMOTE DELIVERED\nConnection to h closed by remote host.\n",
    );
    let e = ssh_outcome(&plan(), &args(), 255, &seen).unwrap_err();
    assert_eq!(e.code_str(), "remote_disconnected");
}

/// R77: an unexplained 255 after delivery is the remote app's own exit.
#[test]
fn an_unexplained_255_after_delivery_is_the_apps_exit() {
    let (seen, _) = relayed("OPV-REMOTE READY 1\nOPV-REMOTE DELIVERED\n");
    assert_eq!(ssh_outcome(&plan(), &args(), 255, &seen).unwrap(), 255);
}

/// A remote opv missing at the profile's path is a start failure on the remote host.
#[test]
fn a_missing_remote_opv_is_a_remote_start_failure() {
    let (seen, _) = relayed(
        "sh: 1: /usr/local/bin/opv: not found\nbash: /usr/local/bin/opv: No such file or directory\n",
    );
    let e = ssh_outcome(&plan(), &args(), 127, &seen).unwrap_err();
    assert_eq!(e.code_str(), "child_start_failed");
}

/// The plan carries the person's run to the receiver (X25).
#[test]
fn the_plan_carries_the_persons_run() {
    let (_, r) = remote_run("prod", "serve");
    let plan: Plan = serde_json::from_str(&r.calls.borrow()[0].args[5]).unwrap();
    assert_eq!(plan.header.outer.map(|o| o.env), Some("prod".to_string()));
}

/// 07.24: the text preview of a remote run never reports this machine's file support.
#[test]
fn the_remote_text_preview_never_reports_local_file_support() {
    let r = FakeRunner::new([crate::runner::Output::success(
        b"{\"user_type\":\"USER\"}".to_vec(),
    )]);
    let mut out = Vec::new();
    crate::app::delivery_preview::preview_for(
        &remote_fleet(),
        "prod",
        Some("allumata"),
        Some("serve"),
        Some("builder"),
        false,
        &r,
        &mut out,
    )
    .unwrap();
    assert!(
        !String::from_utf8(out)
            .unwrap()
            .contains("file delivery: unsupported")
    );
}

#[test]
fn the_remote_preview_names_the_transport() {
    let r = FakeRunner::new([crate::runner::Output::success(
        b"{\"user_type\":\"USER\"}".to_vec(),
    )]);
    let doc = crate::app::delivery_preview::build_for(
        &remote_fleet(),
        "prod",
        Some("allumata"),
        Some("serve"),
        Some("builder"),
        &r,
    )
    .unwrap();
    assert_eq!(doc["transport"], "remote");
}
