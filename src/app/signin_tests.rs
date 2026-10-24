//! Per-environment account and deploy credentials (FR-40, SR-1, SR-3).

use super::*;
use crate::app::status;
use crate::app::testutil::*;
use crate::config;
use crate::host::FakeEnv;
use crate::runner::fake::FakeRunner;

const ACCOUNT: &str = "work.1password.com";
const TOKEN: &str = "fo1_FIXTUREVALUE_deploy_token";

/// The fixture with prod in `ACCOUNT`, signing in to Fly with `op://deploy-prd/fly`.
fn fleet_with_credentials() -> Fleet {
    let text = crate::config::merged_text("tests/fixtures/secrets.toml");
    let text = text.replacen(
        "[environments.prod]\n",
        &format!("[environments.prod]\naccount = \"{ACCOUNT}\"\n"),
        1,
    );
    config::parse(&text.replacen(
        "state_vault_id = \"sprd\"\n",
        "state_vault_id = \"sprd\"\ndeploy_credentials = \"op://deploy-prd/fly\"\n",
        1,
    ))
    .unwrap()
}

fn linux() -> Host {
    Host::from_env(&FakeEnv::new("linux").shell("/bin/bash"))
}

fn deploy_item() -> crate::runner::Output {
    item(&[secret("", "FLY_API_TOKEN", TOKEN)])
}

/// `status prod` through the signed-in runner: the deploy item, the item, Fly's list.
fn status_signed_in() -> (FakeRunner, String) {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([deploy_item(), complete_item(), fly_empty()]);
    let mut out = Vec::new();
    {
        let env_runner = open_on(&fl, "prod", &r, Reach::Target, &linux).unwrap();
        let _ = status::run(&fl, "prod", &env_runner, &mut out);
    }
    (r, text_of(&out))
}

fn env_of<'c>(c: &'c crate::runner::fake::Call, name: &str) -> Option<&'c str> {
    c.env
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[test]
fn account_is_passed_on_every_op_call() {
    let (r, _) = status_signed_in();
    let calls = r.calls.borrow();
    assert!(
        calls
            .iter()
            .filter(|c| c.program == "op")
            .all(|c| env_of(c, "OP_ACCOUNT") == Some(ACCOUNT))
    );
}

#[test]
fn account_is_not_added_under_a_service_account() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([complete_item()]);
    let ci = Host::from_env(&FakeEnv::new("linux").var("OP_SERVICE_ACCOUNT_TOKEN"));
    let env_runner = open_on(&fl, "prod", &r, Reach::Store, &|| ci).unwrap();
    let prod = fl.environment("prod").unwrap();
    crate::adapters::onepassword::read_item(
        &env_runner,
        prod,
        prod.bound_boundaries().next().unwrap().1,
    )
    .unwrap();
    assert_eq!(env_of(&r.calls.borrow()[0], "OP_ACCOUNT"), None);
}

#[test]
fn deploy_credentials_are_read_by_reference() {
    let (r, _) = status_signed_in();
    assert_eq!(
        r.calls.borrow()[0].args,
        [
            "item",
            "get",
            "fly",
            "--vault",
            "deploy-prd",
            "--format",
            "json"
        ]
    );
}

#[test]
fn store_only_commands_never_read_deploy_credentials() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([]);
    let _ = open_on(&fl, "prod", &r, Reach::Store, &linux).unwrap();
    assert!(r.calls.borrow().is_empty());
}

#[test]
fn fly_token_is_in_the_env_of_every_flyctl_call() {
    let (r, _) = status_signed_in();
    let calls = r.calls.borrow();
    let fly: Vec<_> = calls.iter().filter(|c| c.program == "flyctl").collect();
    assert!(
        !fly.is_empty()
            && fly
                .iter()
                .all(|c| env_of(c, "FLY_API_TOKEN") == Some(TOKEN))
    );
}

#[test]
fn fly_token_never_reaches_argv() {
    let (r, _) = status_signed_in();
    assert!(!r.argv_contains(TOKEN));
}

#[test]
fn fly_token_never_reaches_op_calls() {
    let (r, _) = status_signed_in();
    let calls = r.calls.borrow();
    assert!(
        calls
            .iter()
            .filter(|c| c.program != "flyctl")
            .all(|c| c.env.iter().all(|(_, v)| v != TOKEN))
    );
}

#[test]
fn marker_values_never_reach_output() {
    let (_, out) = status_signed_in();
    assert_no_values(&out);
}

#[test]
fn missing_token_field_names_the_field_not_a_value() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([item(&[secret("", "OTHER", TOKEN)])]);
    let e = match open_on(&fl, "prod", &r, Reach::Target, &linux) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a missing field must fail"),
    };
    assert!(e.contains("FLY_API_TOKEN") && !e.contains(MARKER), "{e}");
}

#[test]
fn token_of_the_wrong_type_is_refused() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([item(&[text("", "FLY_API_TOKEN", TOKEN)])]);
    let e = match open_on(&fl, "prod", &r, Reach::Target, &linux) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a text token must fail"),
    };
    // R37, I6: a field of another type is named with the type it must be.
    assert!(e.contains("is not a concealed (password) field"), "{e}");
}

/// A Kubernetes runtime keeping its secrets in a Key Vault (`secrets_in`) signs `az` in
/// with the deploy credentials: `az` writes the secrets, kubectl uses the kubeconfig.
#[test]
fn key_vault_behind_kubernetes_signs_in_to_azure() {
    let fl = config::parse(
        r#"
[stores.kv]
azure_key_vault = "kv-opv-fixture"
subscription = "00000000-0000-0000-0000-000000000000"

[environments.dev]
boundaries.app = { vault_id = "vdev", item_id = "idev" }
[environments.dev.targets.app]
state_vault_id = "sdev"
deploy_credentials = "op://deploy/azure"
[environments.dev.targets.app.kubernetes]
context = "kind-opv"
namespace = "opv"
deployment = "api"
env_name = "{KEY}"
secrets_in = "kv"

[products.app.keys.API_KEY]
kind = "secret"
environments = ["dev"]
"#,
    )
    .unwrap();
    let target = fl
        .environment("dev")
        .unwrap()
        .targets
        .values()
        .next()
        .unwrap()
        .config
        .as_ref();
    assert_eq!(crate::provider::deploy_provider(target).section(), "azure");
}

/// Signed out of 1Password, the deploy-credential read (the first call of `status prod`)
/// is diagnosed at once: the missing session, whose Do is the sign-in (FR-40, UX1).
#[test]
fn signed_out_deploy_read_names_opv_login_for_the_environment() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([
        crate::runner::Output::failure(1),
        crate::runner::Output::failure(1),
        crate::runner::Output::success(br#"[{"url":"x"}]"#.to_vec()),
    ]);
    let tty = Host::from_env(&FakeEnv::new("linux").shell("/bin/bash").tty());
    let res = crate::host::with_test_host(tty, || {
        open_on(&fl, "prod", &r, Reach::Target, &linux).map(|_| ())
    });
    let e = res.expect_err("signed out");
    assert_eq!(
        e.do_text().as_deref(),
        Some("sign in to 1Password"),
        "{e:?}"
    );
}

/// `doctor --env` keeps the failed deploy read's scrubbed stderr with the error, as its
/// evidence (NR-31, UX1, design §7.3).
#[test]
fn doctor_deploy_failure_keeps_the_excerpt_beside_the_error() {
    let e = doctor_signed_out_deploy_failure();
    assert_eq!(
        e.cause().and_then(|(_, up)| up).map(|u| u.said.clone()),
        Some(vec!["[ERROR] not signed in".to_string()]),
    );
}

/// M2: the excerpt is never part of the error's text, so no JSON document carries it.
#[test]
fn doctor_deploy_failure_text_has_no_excerpt() {
    let e = doctor_signed_out_deploy_failure();
    assert!(!e.text().contains("said:"), "{e:?}");
}

/// The excerpt never replaces the sign-in step, which stays the error's `Do:` (A3).
#[test]
fn doctor_deploy_failure_keeps_opv_login_as_its_step() {
    let e = doctor_signed_out_deploy_failure();
    assert_eq!(
        e.do_text().as_deref(),
        Some("sign in to 1Password"),
        "{e:?}"
    );
}

/// What `doctor --env` gets from a failed per-target deploy sign-in: the error, with the
/// failed call's scrubbed reply as its evidence (NR-31, M2).
fn doctor_signed_out_deploy_failure() -> Error {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([]);
    r.push_with_stderr(crate::runner::Output::failure(1), "[ERROR] not signed in");
    r.responses
        .borrow_mut()
        .push_back(Ok(crate::runner::Output::failure(1)));
    r.responses
        .borrow_mut()
        .push_back(Ok(crate::runner::Output::success(
            br#"[{"url":"x"}]"#.to_vec(),
        )));
    let tty = Host::from_env(&FakeEnv::new("linux").shell("/bin/bash").tty());
    crate::host::with_test_host(tty, || {
        open_targeted(&fl, "prod", None, &r, Reach::Target).err()
    })
    .expect("signed out")
}

// ---- FR-41 plan ids on deploy-credential runs and manifest configurations ----

/// The plan id `opv plan prod --json` reports through `r`.
fn plan_id_of(fl: &Fleet, r: &dyn CommandRunner) -> String {
    let mut out = Vec::new();
    crate::app::sync::plan_with(fl, "prod", r, &mut out, true).unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    doc["plan_id"].as_str().unwrap().to_string()
}

#[test]
fn plan_id_through_deploy_credentials_matches_a_plain_run() {
    let fl = fleet_with_credentials();
    let signed = FakeRunner::new([deploy_item(), complete_item(), fly_empty()]);
    let env_runner = open_on(&fl, "prod", &signed, Reach::Target, &linux).unwrap();
    let through = plan_id_of(&fl, &env_runner);
    let plain = FakeRunner::new([complete_item(), fly_empty()]);
    assert_eq!(through, plan_id_of(&fl, &plain));
}

#[test]
fn plan_id_of_a_manifest_configuration_matches_the_same_file() {
    let file = fleet_with_credentials();
    let mut manifest = file.clone();
    manifest.origin = crate::domain::Origin::Manifest;
    let a = plan_id_of(&file, &FakeRunner::new([complete_item(), fly_empty()]));
    let b = plan_id_of(&manifest, &FakeRunner::new([complete_item(), fly_empty()]));
    assert_eq!(a, b);
}

#[test]
fn plan_of_a_manifest_configuration_names_the_manifest_not_the_file() {
    let mut fl = fleet_with_credentials();
    fl.origin = crate::domain::Origin::Manifest;
    let mut out = Vec::new();
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    crate::app::sync::plan_with(&fl, "prod", &r, &mut out, false).unwrap();
    assert!(text_of(&out).contains("the target or the manifest changed"));
}

// 06.30: a rejected deploy credential names its item by the full reference, vault included.
#[test]
fn a_rejected_deploy_credential_names_the_vault_of_its_item() {
    use crate::cause::{
        CallId, Cause, CredentialProblem, CredentialRef, EnvName, ExitClass, ItemId, Observed,
        Principal, System, TargetName, VaultId,
    };
    let principal = Principal::DeployCredentials {
        vault: crate::cause::VaultId::new("vlt-deploy"),
        item: ItemId::new("fly"),
        env: EnvName::new("prod"),
        target: TargetName::new("web"),
    };
    let seen = Observed::from_failed_call(
        CallId {
            system: System::Fly,
            program: "flyctl".into(),
            words: vec!["auth".into(), "whoami".into()],
        },
        ExitClass::Code { code: 1 },
        principal,
    );
    let rejected: Error = Cause::CredentialRejected {
        system: System::Fly,
        credential: CredentialRef::DeployCredentials {
            vault: VaultId::new(""),
            item: ItemId::new("fly"),
            env: EnvName::new("prod"),
            target: TargetName::new("web"),
        },
        problem: CredentialProblem::Rejected { needs: Vec::new() },
        seen,
    }
    .into();
    let reference = ItemRef {
        vault: "deploy-prd".into(),
        item: "fly".into(),
    };
    assert!(matches!(
        deploy_failed(rejected, &reference).cause(),
        Some((Cause::CredentialRejected {
            credential: CredentialRef::DeployCredentials { vault, .. },
            ..
        }, _)) if vault.as_str() == "deploy-prd"
    ));
}

/// L2: a target write made through the environment's runner counts as started, so a
/// budget spent after it never says "before any write".
#[test]
fn a_target_write_through_the_environment_runner_counts_as_started() {
    let r = FakeRunner::new([fly_empty()]);
    let er = EnvRunner::new(&r, None);
    let _ = er.write(&crate::runner::Call::new("flyctl", &["secrets", "import"]));
    assert!(er.writes_started());
}

// #203 §2, §4, FMECA M3: which carrier an `op` call uses, and the sign-in wording.

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn listed_account(uuid: &str, shorthand: &str, user: &str, email: &str) -> Account {
    Account {
        account_uuid: uuid.into(),
        url: "my.1password.com".into(),
        email: email.into(),
        user_uuid: user.into(),
        shorthand: shorthand.into(),
    }
}

fn shell(var: &str) -> ReusePath {
    ReusePath::Shell { var: var.into() }
}

#[test]
fn no_session_variable_is_per_command() {
    assert_eq!(reuse_path(Some("work"), &[], &[]), ReusePath::PerCommand);
}

/// M3: with no listing, the only variable there is.
#[test]
fn the_only_session_variable_without_a_listing_is_the_shells() {
    assert_eq!(
        reuse_path(Some("work"), &names(&["OP_SESSION_ABCUSER"]), &[]),
        shell("OP_SESSION_ABCUSER")
    );
}

/// Without a listing, several variables decide only by the account's own name.
#[test]
fn several_variables_without_a_listing_pick_the_accounts_name() {
    let vars = names(&["OP_SESSION_home", "OP_SESSION_work"]);
    assert_eq!(
        reuse_path(Some("WORK"), &vars, &[]),
        shell("OP_SESSION_work")
    );
    assert_eq!(reuse_path(Some("acme"), &vars, &[]), ReusePath::PerCommand);
}

/// S3/S4: two accounts; op names each variable by the user UUID, matched via the listing.
#[test]
fn with_two_accounts_the_listing_names_the_owner() {
    let listed = [
        listed_account("ACCHOME", "home", "USERHOME", "me@home.example"),
        listed_account("ACCWORK", "work", "USERWORK", "me@work.example"),
    ];
    let vars = names(&["OP_SESSION_USERHOME", "OP_SESSION_USERWORK"]);
    assert_eq!(
        reuse_path(Some("me@work.example"), &vars, &listed),
        shell("OP_SESSION_USERWORK")
    );
    assert_eq!(
        reuse_path(Some("ACCHOME"), &vars, &listed),
        shell("OP_SESSION_USERHOME")
    );
}

/// With a listing, another account's only variable is not this account's.
#[test]
fn another_accounts_variable_with_a_listing_is_per_command() {
    let listed = [
        listed_account("ACCHOME", "home", "USERHOME", "me@home.example"),
        listed_account("ACCWORK", "work", "USERWORK", "me@work.example"),
    ];
    assert_eq!(
        reuse_path(Some("work"), &names(&["OP_SESSION_USERHOME"]), &listed),
        ReusePath::PerCommand
    );
}

/// L6: `OP_SESSION_DELEGATION_ENABLED` is a setting, never the shell's session.
#[test]
fn the_delegation_setting_is_no_session_variable() {
    assert_eq!(
        reuse_path(None, &names(&["OP_SESSION_DELEGATION_ENABLED"]), &[]),
        ReusePath::PerCommand
    );
}

#[test]
fn the_app_takes_over_only_where_no_shell_variable_decides() {
    let app = Some(DesktopIntegration::Available);
    assert_eq!(ReusePath::PerCommand.with_integration(app), ReusePath::App);
    assert_eq!(
        shell("OP_SESSION_x").with_integration(app),
        shell("OP_SESSION_x")
    );
    assert_eq!(
        ReusePath::PerCommand.with_integration(Some(DesktopIntegration::Unavailable {
            reason: crate::app::desktop_integration::NoIntegration::WslLinuxOp
        })),
        ReusePath::PerCommand
    );
}

fn wsl_linux_op() -> Host {
    Host::from_env(
        &FakeEnv::new("linux")
            .var("WSL_DISTRO_NAME")
            .shell("/bin/bash"),
    )
}

/// §4.1: under the app, never "for this command only".
#[test]
fn an_app_sign_in_says_the_terminal_stays_signed_in() {
    let n = sign_in_notice(Some(SignInKind::App), &wsl_linux_op(), None);
    assert!(
        n.contains("stays signed in while the 1Password app keeps it authorized")
            && !n.contains("this command only"),
        "{n}"
    );
}

/// WSL with the Linux op: the sign-in is per command, and the shell refresh is named.
#[test]
fn a_per_command_sign_in_names_the_shell_refresh() {
    let n = sign_in_notice(None, &wsl_linux_op(), None);
    assert!(
        n.contains("this command only") && n.contains("eval \"$(opv login --shell)\""),
        "{n}"
    );
}

/// Before the sign-in, on a host where the app may serve op, both outcomes are named.
#[test]
fn an_undecided_app_host_names_both_outcomes() {
    let n = sign_in_notice(
        None,
        &Host::from_env(&FakeEnv::new("macos").shell("/bin/zsh")),
        None,
    );
    assert!(
        n.contains("Approve 1Password's prompt") && n.contains("this command only"),
        "{n}"
    );
}

/// FMECA H5: no `--shell=powershell` in 0.14, so no refresh line is offered for it.
#[test]
fn a_powershell_sign_in_offers_no_shell_refresh() {
    let host = Host::from_env(
        &FakeEnv::new("linux")
            .var("WSL_DISTRO_NAME")
            .shell("/usr/bin/pwsh"),
    );
    let n = sign_in_notice(None, &host, None);
    assert!(!n.contains("opv login --shell"), "{n}");
}

/// §4.3, S4: an expired shell session is named by its variable, with the refresh, even on
/// a host where the app may serve op (the shell's variable decides first).
#[test]
fn an_expired_shell_session_names_its_variable_and_the_refresh() {
    for host in [
        wsl_linux_op(),
        Host::from_env(&FakeEnv::new("macos").shell("/bin/zsh")),
    ] {
        let n = sign_in_notice(None, &host, Some("OP_SESSION_ABC"));
        assert!(
            n.contains("This shell's 1Password session (OP_SESSION_ABC) expired")
                && n.contains("this command only")
                && n.contains("eval \"$(opv login --shell)\""),
            "{n}"
        );
    }
}

/// The shared signed-out decision (§4.3): a shell variable for the account is `expired`,
/// the app where op talks to it is `app_locked`, else `signed_out`.
#[test]
fn signed_out_state_is_one_decision() {
    use crate::app::desktop_integration::DesktopIntegration;
    use crate::cause::SessionState;
    let vars = vec!["OP_SESSION_abc".to_string()];
    assert_eq!(
        signed_out_state(Some("abc"), &vars, None),
        SessionState::Expired
    );
    assert_eq!(
        signed_out_state(Some("abc"), &vars, Some(DesktopIntegration::Available)),
        SessionState::Expired
    );
    assert_eq!(
        signed_out_state(Some("abc"), &[], Some(DesktopIntegration::Available)),
        SessionState::AppLocked
    );
    assert_eq!(
        signed_out_state(Some("abc"), &[], None),
        SessionState::SignedOut
    );
}

// ---- #234 strict sign-in for target operations (design §4 P4, T12) ----

/// The fixture without `deploy_credentials`.
fn fleet_without_credentials() -> Fleet {
    config::parse(&crate::config::merged_text("tests/fixtures/secrets.toml")).unwrap()
}

/// The cause `open_for_operation` refused with, and whether any call was made.
fn strict_refusal(fl: &Fleet, env: &str, target: &str) -> (crate::cause::Cause, bool) {
    let r = FakeRunner::new([]);
    let Err(Error::Catalog(cause, _)) = open_for_operation(fl, env, target, "machines", &r) else {
        panic!("the strict sign-in went on");
    };
    (*cause, !r.calls.borrow().is_empty())
}

/// T12: `plan`/`sync`'s sign-in signs nothing in for a target without deploy_credentials,
/// and goes on under the machine's own login.
#[test]
fn lenient_sign_in_goes_on_without_deploy_credentials() {
    let fl = fleet_without_credentials();
    let r = FakeRunner::new([]);
    let opened = open_targeted(&fl, "prod", Some("portfolio"), &r, Reach::Target);
    assert_eq!((opened.is_ok(), r.calls.borrow().len()), (true, 0));
}

/// T12: with no target named, `plan`/`sync`'s sign-in uses the environment's only one.
#[test]
fn lenient_sign_in_picks_the_only_target_when_none_is_named() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([deploy_item()]);
    let _ = open_targeted(&fl, "prod", None, &r, Reach::Target).unwrap();
    assert_eq!(r.calls.borrow()[0].args[2], "fly");
}

/// P4: an operation never runs under the machine's own login: a target without
/// deploy_credentials is refused before any call.
#[test]
fn strict_sign_in_refuses_a_target_without_deploy_credentials() {
    use crate::cause::{Cause, Guard, OperationRefusal};
    let (cause, called) = strict_refusal(&fleet_without_credentials(), "prod", "portfolio");
    assert!(
        matches!(
            cause,
            Cause::Guard {
                guard: Guard::OperationRefused {
                    reason: OperationRefusal::NoDeployCredentials,
                    ..
                }
            }
        ) && !called
    );
}

/// P2: the target is always named; an empty name is not "the only target".
#[test]
fn strict_sign_in_never_picks_the_only_target() {
    use crate::cause::{Cause, NameKind};
    let (cause, called) = strict_refusal(&fleet_with_credentials(), "prod", "");
    assert!(
        matches!(
            cause,
            Cause::NotDeclared {
                kind: NameKind::Target,
                ..
            }
        ) && !called
    );
}

/// P1: an unknown environment is refused, not returned as is.
#[test]
fn strict_sign_in_refuses_an_unknown_environment() {
    use crate::cause::{Cause, NameKind};
    let (cause, _) = strict_refusal(&fleet_with_credentials(), "prd", "portfolio");
    assert!(matches!(
        cause,
        Cause::NotDeclared {
            kind: NameKind::Environment,
            ..
        }
    ));
}

/// The named target's own item is read once, and flyctl then carries its token.
#[test]
fn strict_sign_in_signs_in_with_the_named_targets_item() {
    let fl = fleet_with_credentials();
    let r = FakeRunner::new([deploy_item(), fly_empty()]);
    let signed = open_for_operation(&fl, "prod", "portfolio", "machines", &r).unwrap();
    let _ = signed.read(&Call::new("flyctl", &["version"]), &[]);
    assert_eq!(env_of(&r.calls.borrow()[1], "FLY_API_TOKEN"), Some(TOKEN));
}
