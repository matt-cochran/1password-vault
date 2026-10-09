//! `open <[product/]KEY> [--env <env>]` use case (H1).
//!
//! Prints where a declared key lives in 1Password (its section and field) and the private
//! link to its item, then opens that link with the desktop's opener (`xdg-open`, `wslview`,
//! `open`, or `rundll32 url.dll,FileProtocolHandler` on Windows) when there is a desktop.
//! Over SSH, under CI, on a headless machine or with `--print` it only prints the link.
//!
//! No value is read: the key is resolved from the configuration as `explain` resolves it,
//! and the only call before the opener is the free `op whoami` probe for the account in
//! the link (never an item read, FR-13). The opener is a structured command with the link
//! as its one argument, never a shell (SR-7); the link holds IDs only (SR-1, SR-3).

use std::io::Write;

use super::{explain, item_url, write_err};
use crate::domain::{Fleet, key_label};
use crate::error::Error;
use crate::host::HostEnv;
use crate::runner::{Call, CommandRunner, PROBE_TIMEOUT};

/// The program and leading arguments that open a URL on this desktop, or `None` when there
/// is no desktop to open it on (SSH session, CI, or Linux without a display).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opener {
    pub program: &'static str,
    pub args: &'static [&'static str],
}

/// Detect the opener from `env` (the testable seam; `main` passes the process env).
pub fn opener(env: &dyn HostEnv) -> Option<Opener> {
    let truthy = |name: &str| {
        env.flag(name).is_some_and(|v| {
            let v = v.trim().to_ascii_lowercase();
            !v.is_empty() && v != "false" && v != "0"
        })
    };
    if truthy("CI") || truthy("GITHUB_ACTIONS") {
        return None;
    }
    if env.is_set("SSH_CONNECTION") || env.is_set("SSH_TTY") {
        return None;
    }
    let o = |program, args| Some(Opener { program, args });
    match env.os() {
        "macos" => o("open", &[]),
        "windows" => o("rundll32", &["url.dll,FileProtocolHandler"]),
        "linux" => {
            let wsl = env.is_set("WSL_DISTRO_NAME")
                || env.kernel_osrelease().is_some_and(|r| {
                    let r = r.to_ascii_lowercase();
                    r.contains("microsoft") || r.contains("wsl")
                });
            if wsl {
                o("wslview", &[])
            } else if env.is_set("DISPLAY") || env.is_set("WAYLAND_DISPLAY") {
                o("xdg-open", &[])
            } else {
                None
            }
        }
        _ => None,
    }
}

/// `opv open`: print the key's place in 1Password and its item link, then open the link
/// with `opener` unless it is `None`.
pub fn run(
    fleet: &Fleet,
    target: &str,
    env: Option<&str>,
    opener: Option<Opener>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let (product, key, env_name) = explain::locate(fleet, target, env)?;
    let url = item_url(fleet, env_name, r)?;
    let place = if fleet.is_simple() {
        format!("field {key}")
    } else {
        format!("section {product}, field {key}")
    };
    let mut line = |s: String| writeln!(out, "{s}").map_err(write_err);
    line(format!(
        "{} in {env_name}: {place}",
        key_label(&product, &key)
    ))?;
    line(format!("open: {url}"))?;
    let Some(o) = opener else {
        return line("no desktop to open it on here: open the link above yourself".into());
    };
    let mut args: Vec<&str> = o.args.to_vec();
    args.push(&url);
    let opened = r
        .probe(&Call::new(o.program, &args), PROBE_TIMEOUT)
        .is_ok_and(|res| res.status == 0);
    if opened {
        line(format!("opened with {}", o.program))
    } else {
        // The opener's own stderr is not opv's result (NR-31).
        let _ = crate::runner::take_failure_excerpt();
        line(format!(
            "{} could not open it: open the link above yourself",
            o.program
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testutil::*;
    use crate::host::FakeEnv;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    const WHOAMI: &[u8] = br#"{"url":"my.1password.com","email":"x-FIXTUREVALUE@example.com","account_uuid":"ACC1","user_type":"USER"}"#;
    const XDG: Option<Opener> = Some(Opener {
        program: "xdg-open",
        args: &[],
    });

    fn open_out(opener: Option<Opener>, rest: Vec<Output>) -> (String, FakeRunner) {
        let r = FakeRunner::new(std::iter::once(Output::success(WHOAMI.to_vec())).chain(rest));
        let mut out = Vec::new();
        run(
            &fleet(),
            "allumata/OPENAI_API_KEY",
            Some("prod"),
            opener,
            &r,
            &mut out,
        )
        .unwrap();
        (text_of(&out), r)
    }

    #[test]
    fn open_prints_the_item_link_with_the_account() {
        let (out, _) = open_out(None, vec![]);
        assert!(
            out.contains(
                "open: https://start.1password.com/open/i?a=ACC1&v=vprd&i=iprd&h=my.1password.com"
            ),
            "{out}"
        );
    }

    #[test]
    fn open_names_the_section_and_field() {
        let (out, _) = open_out(None, vec![]);
        assert!(
            out.contains("section allumata, field OPENAI_API_KEY"),
            "{out}"
        );
    }

    #[test]
    fn open_runs_the_opener_with_the_link_as_its_only_argument() {
        let (_, r) = open_out(XDG, vec![Output::success(Vec::new())]);
        assert_eq!(
            argvs(&r).last().unwrap(),
            "xdg-open https://start.1password.com/open/i?a=ACC1&v=vprd&i=iprd&h=my.1password.com"
        );
    }

    #[test]
    fn open_never_reads_the_item() {
        let (_, r) = open_out(XDG, vec![Output::success(Vec::new())]);
        assert!(!called(&r, "op", &["item"]));
    }

    #[test]
    fn open_without_a_desktop_only_prints() {
        let (_, r) = open_out(None, vec![]);
        assert_eq!(r.calls.borrow().len(), 1, "only op whoami");
    }

    #[test]
    fn open_output_has_no_identity_or_value() {
        let (out, _) = open_out(XDG, vec![Output::failure(3)]);
        assert_no_values(&out);
    }

    #[test]
    fn open_reports_a_failed_opener() {
        let (out, _) = open_out(XDG, vec![Output::failure(3)]);
        assert!(out.contains("xdg-open could not open it"), "{out}");
    }

    #[test]
    fn opener_is_none_over_ssh() {
        let env = FakeEnv::new("macos").var("SSH_CONNECTION");
        assert_eq!(opener(&env), None);
    }

    #[test]
    fn opener_is_none_under_ci() {
        let env = FakeEnv::new("macos").var_val("CI", "true");
        assert_eq!(opener(&env), None);
    }

    #[test]
    fn opener_is_none_on_headless_linux() {
        assert_eq!(opener(&FakeEnv::new("linux")), None);
    }

    #[test]
    fn opener_is_xdg_open_on_a_linux_desktop() {
        let env = FakeEnv::new("linux").var("DISPLAY");
        assert_eq!(opener(&env).map(|o| o.program), Some("xdg-open"));
    }

    #[test]
    fn opener_is_wslview_under_wsl() {
        let env = FakeEnv::new("linux").var("WSL_DISTRO_NAME");
        assert_eq!(opener(&env).map(|o| o.program), Some("wslview"));
    }

    #[test]
    fn opener_on_windows_is_no_shell() {
        let o = opener(&FakeEnv::new("windows")).unwrap();
        assert_eq!(
            (o.program, o.args),
            ("rundll32", &["url.dll,FileProtocolHandler"][..])
        );
    }
}
