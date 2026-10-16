//! X8 refusal table (design `docs/design/error-catalog.md` §6.4): one atomic test per row,
//! exactly one behavioural assertion each, through the public [`Situation::refuses`].

use std::path::PathBuf;

use super::{OpFlavour, RefusedBecause, Situation};
use crate::cause::{Cmd, ConfigSource, GivenBy, Principal, VaultId};
use crate::host::Platform;

fn base() -> Situation {
    Situation {
        ci: false,
        terminal: true,
        identity: Principal::Person { account: None },
        config_source: ConfigSource::File {
            path: PathBuf::from("secrets.toml"),
            given_by: GivenBy::Discovered,
        },
        platform: Platform::Linux,
        op: OpFlavour::Native,
        remote: false,
        deploy_credentials_or_shell_token: false,
    }
}

fn manifest() -> ConfigSource {
    ConfigSource::Manifest {
        title: "myapp".into(),
        vault: VaultId::new("v1"),
        project: "myapp".into(),
    }
}

fn cmd(words: &[&str]) -> Cmd {
    Cmd {
        command: words.iter().map(|w| (*w).to_string()).collect(),
        args: Vec::new(),
    }
}

fn cmd_with_args(words: &[&str], args: &[&str]) -> Cmd {
    Cmd {
        command: words.iter().map(|w| (*w).to_string()).collect(),
        args: args.iter().map(|a| (*a).to_string()).collect(),
    }
}

macro_rules! refusal_rows {
    ($($name:ident: $setup:expr, $cmd:expr, $expected:expr;)*) => {
        $(
            #[test]
            fn $name() {
                let situation = $setup;
                assert_eq!(situation.refuses(&$cmd), $expected);
            }
        )*
    };
}

refusal_rows! {
    a_plain_run_is_not_refused:
        base(),
        cmd(&["run", "dev"]),
        None;

    ci_refuses_login:
        { let mut s = base(); s.ci = true; s },
        cmd(&["login", "dev"]),
        Some(RefusedBecause::Ci);
    ci_refuses_approve:
        { let mut s = base(); s.ci = true; s },
        cmd(&["approve"]),
        Some(RefusedBecause::Ci);
    ci_refuses_setup:
        { let mut s = base(); s.ci = true; s },
        cmd(&["setup"]),
        Some(RefusedBecause::Ci);

    no_terminal_refuses_login:
        { let mut s = base(); s.terminal = false; s },
        cmd(&["login", "dev"]),
        Some(RefusedBecause::NoTerminal);

    a_service_account_refuses_login:
        { let mut s = base(); s.identity = Principal::ServiceAccount { name: "ci".into() }; s },
        cmd(&["login", "dev"]),
        Some(RefusedBecause::ServiceAccount);

    a_manifest_project_refuses_bootstrap:
        { let mut s = base(); s.config_source = manifest(); s },
        cmd(&["bootstrap"]),
        Some(RefusedBecause::ManifestProject);
    a_manifest_project_refuses_init_file:
        { let mut s = base(); s.config_source = manifest(); s },
        cmd_with_args(&["init"], &["dev", "--file"]),
        Some(RefusedBecause::ManifestProject);
    a_manifest_project_refuses_config_check_file:
        { let mut s = base(); s.config_source = manifest(); s },
        cmd_with_args(&["config", "check"], &["--file", "secrets.toml"]),
        Some(RefusedBecause::ManifestProject);

    macos_refuses_login_add:
        { let mut s = base(); s.platform = Platform::MacOs; s },
        cmd_with_args(&["login"], &["--add"]),
        Some(RefusedBecause::Platform);
    a_windows_exe_from_wsl_refuses_login_add:
        { let mut s = base(); s.op = OpFlavour::WindowsExe; s },
        cmd_with_args(&["login"], &["--add"]),
        Some(RefusedBecause::Platform);

    a_hidden_local_delivery_is_refused:
        base(),
        cmd(&["local-delivery"]),
        Some(RefusedBecause::HiddenCommand);
    a_hidden_remote_send_is_refused:
        base(),
        cmd(&["remote-send"]),
        Some(RefusedBecause::HiddenCommand);
    a_hidden_remote_receive_is_refused:
        base(),
        cmd(&["remote-receive"]),
        Some(RefusedBecause::HiddenCommand);

    a_remote_run_with_a_child_is_refused:
        base(),
        cmd_with_args(&["run", "dev"], &["--remote", "prod", "--", "echo"]),
        Some(RefusedBecause::RemoteChild);

    a_shell_token_refuses_flyctl_sign_in:
        { let mut s = base(); s.deploy_credentials_or_shell_token = true; s },
        cmd(&["flyctl", "auth", "login"]),
        Some(RefusedBecause::ShellToken);
    a_shell_token_refuses_gh_sign_in:
        { let mut s = base(); s.deploy_credentials_or_shell_token = true; s },
        cmd(&["gh", "auth", "login"]),
        Some(RefusedBecause::ShellToken);
    a_shell_token_refuses_az_sign_in:
        { let mut s = base(); s.deploy_credentials_or_shell_token = true; s },
        cmd(&["az", "login"]),
        Some(RefusedBecause::ShellToken);
}
