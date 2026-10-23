//! `opv target op` (#234, `docs/design/provider-operations.md` §4, §10 T1–T3, T10, T11):
//! admission (P1–P6) and preflight (P7–P10). One assertion each; no value ever printed.

use std::ffi::OsString;

use super::*;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

// --- fixtures ------------------------------------------------------------------------------

/// Two Fly targets with different apps and different deploy-credential items, a Fly target
/// with no deploy credentials, and a target of another provider: `--target` must select
/// exactly one target's app and item (T3).
const FLEET: &str = r#"[environments.prod]
confirm_env = true

[environments.prod.targets.web]
fly.app = "shop"
fly.secret_name = "SHOP__{KEY}"
deploy_credentials = "op://vprod/ideploy"

[environments.prod.targets.admin]
fly.app = "admin-app"
fly.secret_name = "ADMIN__{KEY}"
deploy_credentials = "op://vprod/iadmin"

[environments.prod.targets.bare]
fly.app = "bare-app"
fly.secret_name = "BARE__{KEY}"

[environments.prod.targets.upper]
fly.app = "Shop-App"
fly.secret_name = "UPPER__{KEY}"

[environments.dev.targets.k8s]

[environments.dev.targets.k8s.kubernetes]
context = "kind-opv"
namespace = "opv"
deployment = "api"
env_name = "{KEY}"
"#;

fn fleet() -> Fleet {
    crate::config::parse(FLEET).expect("config")
}

fn request(op: Operation) -> Request {
    Request {
        env: "prod".into(),
        target: "web".into(),
        op,
        image: None,
        machine: None,
        confirm: None,
    }
}

/// A registry push of `target`'s app, confirmed for `prod`.
fn push(image: &str, target: &str) -> Request {
    Request {
        env: "prod".into(),
        target: target.into(),
        op: Operation::RegistryPush,
        image: Some(image.into()),
        machine: None,
        confirm: Some("prod".into()),
    }
}

/// A machine update of `web` named for `shop`, confirmed for `prod`.
fn machine_update(image: &str, machine: &str) -> Request {
    Request {
        env: "prod".into(),
        target: "web".into(),
        op: Operation::MachineUpdate,
        image: Some(image.into()),
        machine: Some(machine.into()),
        confirm: Some("prod".into()),
    }
}

fn admitted(op: Operation) -> Admitted {
    Admitted {
        env: "prod".into(),
        target: "web".into(),
        app: "shop".into(),
        registry: "registry.fly.io",
        tool: crate::host::tool("flyctl").expect("flyctl is a known tool"),
        credentials: ItemRef {
            vault: "vprod".into(),
            item: "ideploy".into(),
        },
        op,
        image: Some("registry.fly.io/shop:v1".into()),
        machine: Some("0123456789abcd".into()),
        docker_endpoint: None,
    }
}

/// The docker probe, the local context and an image the daemon has.
fn local_daemon() -> FakeRunner {
    FakeRunner::new([
        Output::success("Docker version 27.0.0"),
        Output::success("unix:///var/run/docker.sock\n"),
        Output::success("sha256:abc\n"),
    ])
}

fn ok() -> Vec<Output> {
    vec![
        Output::success("Docker version 27.0.0"),
        Output::success("unix:///var/run/docker.sock\n"),
        Output::success("sha256:abc\n"),
    ]
}

/// A directory the current user owns, so P8's ownership check passes (its RAM test is
/// supplied by the test).
fn owned_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn preflight_push(a: &mut Admitted, r: &FakeRunner, dir: &tempfile::TempDir) -> Result<(), Error> {
    let runtime = Some(OsString::from(dir.path()));
    preflight_in(Platform::Linux, runtime, &|_| Ok(true), a, r)
}

// --- P1–P6: admission ----------------------------------------------------------------------

#[test]
fn an_unknown_environment_is_refused() {
    let mut req = request(Operation::Machines);
    req.env = "staging".into();
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("unknown_env", 2));
}

#[test]
fn an_unknown_target_is_refused() {
    let mut req = request(Operation::Machines);
    req.target = "nope".into();
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("unknown_target", 2));
}

#[test]
fn a_target_of_another_provider_is_refused() {
    let mut req = request(Operation::Machines);
    req.env = "dev".into();
    req.target = "k8s".into();
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("policy_refused", 6));
}

#[test]
fn the_wrong_provider_refusal_names_the_provider() {
    let mut req = request(Operation::Machines);
    req.env = "dev".into();
    req.target = "k8s".into();
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert!(
        e.text().contains("the target is on kubernetes"),
        "{}",
        e.text()
    );
}

#[test]
fn a_target_without_deploy_credentials_is_refused() {
    let req = Request {
        target: "bare".into(),
        ..request(Operation::Machines)
    };
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("policy_refused", 6));
}

#[test]
fn a_read_needs_no_confirmation_even_where_the_environment_sets_it() {
    let a = admit(&fleet(), &request(Operation::Machines), &Host::detect()).unwrap();
    assert_eq!(a.op, Operation::Machines);
}

#[test]
fn a_write_without_the_confirmation_is_refused() {
    let req = Request {
        confirm: None,
        ..request(Operation::MachineUpdate)
    };
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("confirm_required", 6));
}

#[test]
fn a_write_with_another_environments_name_is_refused() {
    let req = Request {
        confirm: Some("dev".into()),
        ..request(Operation::MachineUpdate)
    };
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("confirm_mismatch", 6));
}

#[test]
fn a_machine_update_without_an_image_is_refused() {
    let req = Request {
        image: None,
        ..machine_update("registry.fly.io/shop:v1", "0123456789abcd")
    };
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("usage", 2));
}

#[test]
fn an_image_on_another_host_is_refused() {
    let req = push("example.com/shop:v1", "web");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("policy_refused", 6));
}

#[test]
fn an_image_outside_the_targets_app_is_refused() {
    let req = push("registry.fly.io/other:v1", "web");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("policy_refused", 6));
}

#[test]
fn the_image_outside_the_app_refusal_names_the_apps_repository() {
    let req = push("registry.fly.io/other:v1", "web");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert!(e.text().contains("registry.fly.io/shop"), "{}", e.text());
}

#[test]
fn an_image_with_a_space_is_refused() {
    let req = push("registry.fly.io/shop:a b", "web");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("usage", 2));
}

#[test]
fn an_image_with_a_shell_substitution_is_refused() {
    let req = push("registry.fly.io/shop:$(id)", "web");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("usage", 2));
}

#[test]
fn an_image_with_a_semicolon_is_refused() {
    let req = push("registry.fly.io/shop:v1;rm", "web");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("usage", 2));
}

#[test]
fn an_image_with_a_newline_is_refused() {
    let req = push("registry.fly.io/shop:v1\n--debug", "web");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("usage", 2));
}

#[test]
fn an_image_with_a_flag_shaped_tag_is_refused() {
    let req = push("registry.fly.io/shop:-x", "web");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("usage", 2));
}

#[test]
fn an_image_that_is_only_a_flag_is_refused() {
    // A caller's `--image -x` must never reach a runner as an argv word.
    let req = push("-x", "web");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("policy_refused", 6));
}

#[test]
fn an_image_with_a_tag_of_129_characters_is_refused() {
    let tag = "t".repeat(129);
    let req = push(&format!("registry.fly.io/shop:{tag}"), "web");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("usage", 2));
}

#[test]
fn an_image_with_a_tag_of_128_characters_is_admitted() {
    let tag = "t".repeat(128);
    let req = push(&format!("registry.fly.io/shop:{tag}"), "web");
    assert!(admit(&fleet(), &req, &Host::detect()).is_ok());
}

#[test]
fn a_registry_push_named_by_a_digest_is_refused() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let req = push(&format!("registry.fly.io/shop@{digest}"), "web");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("usage", 2));
}

#[test]
fn a_machine_update_named_by_a_digest_is_admitted() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let req = machine_update(&format!("registry.fly.io/shop@{digest}"), "0123456789abcd");
    assert!(admit(&fleet(), &req, &Host::detect()).is_ok());
}

#[test]
fn a_machine_id_that_is_not_hex_is_refused() {
    let req = machine_update("registry.fly.io/shop:v1", "zzzzzzzzzzzzzz");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("usage", 2));
}

#[test]
fn a_machine_id_of_the_wrong_length_is_refused() {
    // Twelve characters, not fourteen.
    let req = machine_update("registry.fly.io/shop:v1", "0123456789ab");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("usage", 2));
}

#[test]
fn a_machine_id_shaped_like_a_flag_is_refused() {
    let req = machine_update("registry.fly.io/shop:v1", "--app=x");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("usage", 2));
}

#[test]
fn a_registry_push_to_an_app_docker_refuses_is_refused() {
    // `is_id` admits upper case; Docker's repository grammar does not (T2).
    let req = push("registry.fly.io/Shop-App:v1", "upper");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("policy_refused", 6));
}

// --- T3: the target selects the app and the item -------------------------------------------

#[test]
fn the_named_target_supplies_the_app_and_the_item() {
    let req = push("registry.fly.io/admin-app:v1", "admin");
    let a = admit(&fleet(), &req, &Host::detect()).unwrap();
    assert_eq!(
        (a.app.as_str(), a.credentials.item.as_str()),
        ("admin-app", "iadmin")
    );
}

#[test]
fn another_targets_app_is_not_the_named_targets_repository() {
    let req = push("registry.fly.io/shop:v1", "admin");
    let e = admit(&fleet(), &req, &Host::detect()).unwrap_err();
    assert_eq!(e.code_str(), "policy_refused");
}

// --- P7–P10: preflight ---------------------------------------------------------------------

#[test]
fn preflight_makes_no_op_call() {
    let r = FakeRunner::new([Output::success("flyctl v0.3")]);
    let _ = preflight(&mut admitted(Operation::MachineUpdate), &r);
    assert!(r.calls.borrow().iter().all(|c| c.program != "op"));
}

#[test]
fn a_missing_program_is_refused_without_a_call_of_the_operation() {
    let r = FakeRunner::default();
    r.push_io_error(std::io::ErrorKind::NotFound);
    let e = preflight(&mut admitted(Operation::MachineUpdate), &r).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("dependency_missing", 3));
}

#[test]
fn a_registry_push_on_macos_is_refused() {
    let mut a = admitted(Operation::RegistryPush);
    let dir = owned_dir();
    let e = preflight_in(
        Platform::MacOs,
        Some(OsString::from(dir.path())),
        &|_| Ok(true),
        &mut a,
        &FakeRunner::new(ok()),
    )
    .unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("ram_dir_unavailable", 6));
}

#[test]
fn a_registry_push_on_windows_is_refused() {
    let mut a = admitted(Operation::RegistryPush);
    let e = preflight_in(
        Platform::Windows,
        None,
        &|_| Ok(true),
        &mut a,
        &FakeRunner::new(ok()),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "ram_dir_unavailable");
}

#[test]
fn a_registry_push_with_no_runtime_directory_is_refused() {
    let e = registry_ram_in(Platform::Linux, None, &|_| Ok(true)).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("ram_dir_unavailable", 6));
}

#[test]
fn a_relative_runtime_directory_is_refused() {
    let e = registry_ram_in(Platform::Linux, Some(OsString::from("run/user/1")), &|_| {
        Ok(true)
    })
    .unwrap_err();
    assert_eq!(e.code_str(), "ram_dir_unavailable");
}

#[test]
fn a_runtime_directory_that_is_not_ram_backed_is_refused() {
    let dir = owned_dir();
    let e = registry_ram_in(Platform::Linux, Some(OsString::from(dir.path())), &|_| {
        Ok(false)
    })
    .unwrap_err();
    assert_eq!(e.code_str(), "ram_dir_unavailable");
}

#[test]
fn a_chosen_docker_context_is_refused_before_any_call() {
    let r = FakeRunner::default();
    let e = docker_endpoint_in(
        Some(OsString::from("remote")),
        &admitted(Operation::RegistryPush),
        &r,
    )
    .unwrap_err();
    assert_eq!(
        (e.code_str(), e.exit_code(), r.calls.borrow().len()),
        ("policy_refused", 6, 0)
    );
}

#[test]
fn a_remote_docker_endpoint_is_refused() {
    let mut a = admitted(Operation::RegistryPush);
    let dir = owned_dir();
    let r = FakeRunner::new([
        Output::success("Docker version 27.0.0"),
        Output::success("tcp://10.0.0.5:2375\n"),
    ]);
    let e = preflight_push(&mut a, &r, &dir).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("policy_refused", 6));
}

#[test]
fn a_remote_docker_endpoint_refusal_names_the_daemon() {
    let mut a = admitted(Operation::RegistryPush);
    let dir = owned_dir();
    let r = FakeRunner::new([
        Output::success("Docker version 27.0.0"),
        Output::success("tcp://10.0.0.5:2375\n"),
    ]);
    let e = preflight_push(&mut a, &r, &dir).unwrap_err();
    assert!(
        e.text().contains("not local to this machine"),
        "{}",
        e.text()
    );
}

#[test]
fn an_image_absent_from_the_local_daemon_is_refused() {
    let mut a = admitted(Operation::RegistryPush);
    let dir = owned_dir();
    let r = FakeRunner::new([
        Output::success("Docker version 27.0.0"),
        Output::success("unix:///var/run/docker.sock\n"),
        Output::failure(1),
    ]);
    let e = preflight_push(&mut a, &r, &dir).unwrap_err();
    assert_eq!((e.code_str(), e.exit_code()), ("policy_refused", 6));
}

#[test]
fn a_registry_push_over_a_local_daemon_records_the_endpoint() {
    let mut a = admitted(Operation::RegistryPush);
    let dir = owned_dir();
    let r = local_daemon();
    preflight_push(&mut a, &r, &dir).unwrap();
    assert_eq!(
        a.docker_endpoint.as_deref(),
        Some("unix:///var/run/docker.sock")
    );
}

#[test]
fn a_registry_push_preflights_the_image_with_the_resolved_endpoint() {
    let mut a = admitted(Operation::RegistryPush);
    let dir = owned_dir();
    let r = local_daemon();
    preflight_push(&mut a, &r, &dir).unwrap();
    let calls = r.calls.borrow();
    assert!(calls.iter().any(|c| {
        c.args.first().map(String::as_str) == Some("image")
            && c.env
                .iter()
                .any(|(k, v)| k == "DOCKER_HOST" && v == "unix:///var/run/docker.sock")
    }));
}

#[test]
fn a_machine_update_preflight_never_reaches_docker() {
    let r = FakeRunner::new([Output::success("flyctl v0.3")]);
    let a = preflight(&mut admitted(Operation::MachineUpdate), &r);
    assert!(a.is_ok() && r.calls.borrow().iter().all(|c| c.program != "docker"));
}

// --- execute (§5): the strict sign-in, then the target's calls, all isolated -------------

const MACHINE: &str = "8edd22dc379d68";
const CANARY: &str = "sk-proj-LEAKCANARY";

/// The deploy credentials item of `web` (`op://vprod/ideploy`).
fn deploy_item() -> Output {
    crate::app::testutil::item(&[crate::app::testutil::secret(
        "",
        "FLY_API_TOKEN",
        "fo1_FIXTUREVALUE_deploy_token",
    )])
}

// unrecorded: built from flyctl docs, replace with the first real reply (#234 §8.1)
fn listing() -> Output {
    Output::success(format!(
        r#"[{{"id": "{MACHINE}", "name": "opv-canary", "state": "started", "region": "iad",
            "config": {{"image": "registry.fly.io/shop:v1", "env": {{"OPVCANARY": "{CANARY}"}}}}}}]"#
    ))
}

/// `machine-update` of `machine` in `web`, admitted.
fn update_of(machine: &str) -> Admitted {
    Admitted {
        machine: Some(machine.into()),
        image: Some("registry.fly.io/shop:v2".into()),
        ..admitted(Operation::MachineUpdate)
    }
}

/// The first two argv words of each call after the sign-in's read.
fn verbs(r: &FakeRunner) -> Vec<String> {
    r.calls
        .borrow()
        .iter()
        .filter(|c| c.program != "op")
        .map(|c| c.args[..2].join(" "))
        .collect()
}

/// T5 (unit half): the lines and the document of `machines` hold no `config.env` value.
#[test]
fn machines_output_holds_no_config_env() {
    let r = FakeRunner::new([deploy_item(), listing()]);
    let report = execute(&fleet(), &admitted(Operation::Machines), &r).unwrap();
    let printed = format!("{}\n{}", report.lines.join("\n"), report.json());
    assert!(
        !printed.contains(CANARY) && !printed.contains("OPVCANARY"),
        "{printed}"
    );
}

#[test]
fn machines_prints_id_name_state_region_and_image() {
    let r = FakeRunner::new([deploy_item(), listing()]);
    let report = execute(&fleet(), &admitted(Operation::Machines), &r).unwrap();
    assert_eq!(
        report.lines,
        [format!(
            "{MACHINE}  opv-canary  started  iad  registry.fly.io/shop:v1"
        )]
    );
}

/// T4: the update is written only after a listing that holds the machine.
#[test]
fn machine_update_writes_after_a_listing_that_holds_the_machine() {
    let r = FakeRunner::new([deploy_item(), listing(), Output::success("")]);
    execute(&fleet(), &update_of(MACHINE), &r).unwrap();
    assert_eq!(verbs(&r), ["machine list", "machine update"]);
}

/// T4: a machine id the listing does not hold is never written.
#[test]
fn machine_update_of_an_unlisted_machine_writes_nothing() {
    let r = FakeRunner::new([deploy_item(), listing()]);
    let _ = execute(&fleet(), &update_of("0123456789abcd"), &r);
    assert_eq!(verbs(&r), ["machine list"]);
}

#[test]
fn machine_update_reports_the_machine_and_its_new_image() {
    let r = FakeRunner::new([deploy_item(), listing(), Output::success("")]);
    let report = execute(&fleet(), &update_of(MACHINE), &r).unwrap();
    assert_eq!(
        report.lines,
        [format!(
            "updated machine {MACHINE} to registry.fly.io/shop:v2"
        )]
    );
}

/// §5.5: every call of the run, the sign-in's included, is made inside the isolation, where
/// a child sees only opv's basics and its own variables.
#[test]
fn every_call_of_an_operation_runs_isolated() {
    let r = FakeRunner::new([deploy_item(), listing()]);
    execute(&fleet(), &admitted(Operation::Machines), &r).unwrap();
    assert!(r.calls.borrow().iter().all(|c| c.isolated));
}

/// The run signs in with the named target's own item, never another's.
#[test]
fn an_operation_reads_the_named_targets_deploy_credentials() {
    let r = FakeRunner::new([deploy_item(), listing()]);
    execute(&fleet(), &admitted(Operation::Machines), &r).unwrap();
    assert!(r.calls.borrow()[0].args.iter().any(|a| a == "ideploy"));
}

// --- registry-push is not yet available (L3b) -----------------------------------------------

#[test]
fn a_refused_operation_exits_with_the_policy_exit_code() {
    let e = execute(
        &fleet(),
        &admitted(Operation::RegistryPush),
        &FakeRunner::default(),
    )
    .unwrap_err();
    assert_eq!(e.exit_code(), 6);
}

#[test]
fn the_refusal_names_the_operation_and_its_target() {
    let e = execute(
        &fleet(),
        &admitted(Operation::RegistryPush),
        &FakeRunner::default(),
    )
    .unwrap_err();
    assert!(
        e.text().contains("registry-push on prod/web"),
        "{}",
        e.text()
    );
}
