//! `doctor` use case (FR-3).
//!
//! Checks, one line each, always all of them: configuration valid; `op --version`;
//! the 1Password session via [`onepassword::diagnose`] (`op whoami`, and `op account list`
//! when it fails; free of rate-limit cost per D0), the same classification a failed item
//! read uses (FR-26); `flyctl version` and
//! `flyctl auth whoami` (exit status only) when some environment has a `fly` section.
//! Environments without one are listed as skipped for Fly. Returns the error of the first
//! failing check.
//!
//! A tool version opv was not tested with (op older than 2.40.0, flyctl outside 0.4.x from
//! 0.4.112) is a `warn` line, never a failure.
//!
//! Tool output is never echoed: only a version string that matches a strict pattern, and
//! from `op whoami` only the account type (`SERVICE_ACCOUNT`, ...), never identity or
//! tokens; from `op account list` only the number of accounts. No item is read.
//!
//! A failing check prints the next command for the detected platform and shell (FR-26):
//! the sign-in command, `op account add`, or the install command.
//!
//! The output ends with one `Next step` line (FR-22): the first failing check and the safe
//! command that addresses it (the first remediation line of that check), or `nothing
//! pending`. Text only, never a prompt (FR-9).

use std::io::{self, Write};

use super::write_err;
use crate::adapters::{fly, onepassword};
use crate::domain::Fleet;
use crate::error::Error;
use crate::host::{Host, Tool};
use crate::runner::{CommandRunner, Output};

/// The 1Password CLI binary (same name the 1Password adapter runs).
const OP: &str = "op";

/// Oldest `op` release opv is tested with.
pub const OP_TESTED_MIN: (u64, u64, u64) = (2, 40, 0);
/// The `flyctl` release opv is tested with (its import parser is ported, see fly.rs). Later
/// patches of the same minor pass without a warning; another minor or an older patch warns.
pub const FLYCTL_TESTED: (u64, u64, u64) = (0, 4, 112);

/// Same major and minor as [`FLYCTL_TESTED`], at or above its patch.
fn flyctl_tested(v: (u64, u64, u64)) -> bool {
    let (a, b, c) = FLYCTL_TESTED;
    v.0 == a && v.1 == b && v.2 >= c
}

/// Name of the configuration check (its message is parser output, see [`next_step`]).
const CONFIG_CHECK: &str = "config";

/// A check result: ok, ok with a warning, or failed.
enum Check {
    Ok(String),
    Warn(String),
}

pub fn run_scoped(
    config: Result<Fleet, Error>,
    env: Option<&str>,
    product: Option<&str>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let config = match env {
        Some(e) => config.and_then(|f| super::local::select(&f, e, product, false)),
        None if product.is_some() => Err(Error::Config("--product requires --env".into())),
        None => config,
    };
    // Scoped to environments without a target: local runs are all they are for, so a
    // Windows op.exe is a failure there and only a warning elsewhere (#54).
    let local_only = env.is_some()
        && config
            .as_ref()
            .is_ok_and(|f| f.environments.values().all(|e| e.target().is_none()));
    run_on(config, r, &Host::detect, local_only, out)
}

pub fn run(
    config: Result<Fleet, Error>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_on(config, r, &Host::detect, false, out)
}

/// [`run`] on a given host (tests).
pub fn run_with(
    config: Result<Fleet, Error>,
    r: &dyn CommandRunner,
    host: &Host,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_on(config, r, &|| *host, false, out)
}

/// The host is detected only when a check needs it (a failure or a credential decision).
fn run_on(
    config: Result<Fleet, Error>,
    r: &dyn CommandRunner,
    host: &dyn Fn() -> Host,
    local_only: bool,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let mut first: Option<Error> = None;
    let mut next: Option<String> = None;
    let mut line = |out: &mut dyn Write, check: &str, res: Result<Check, Error>| {
        let text = match res {
            Ok(Check::Ok(detail)) => format!("ok    {check}: {detail}"),
            Ok(Check::Warn(detail)) => format!("warn  {check}: {detail}"),
            Err(e) => {
                let t = format!("FAIL  {check}: {e}");
                next.get_or_insert_with(|| next_step(check, &e));
                first.get_or_insert(e);
                t
            }
        };
        writeln!(out, "{text}").map_err(write_err)
    };

    // (any environment has fly, environments without fly)
    let fly_envs = match &config {
        Ok(f) => Some((
            f.environments.values().any(|e| e.target().is_some()),
            f.environments
                .iter()
                .filter(|(_, e)| e.target().is_none())
                .map(|(n, _)| n.clone())
                .collect::<Vec<_>>(),
        )),
        Err(_) => None,
    };
    line(
        out,
        CONFIG_CHECK,
        config.map(|f| Check::Ok(config_summary(&f))),
    )?;
    let op_check = op_version(r, host);
    let op_present = op_check.is_ok();
    line(out, "op", op_check)?;
    line(out, "op auth", op_auth(r, host).map(Check::Ok))?;
    match fly_envs {
        Some((true, without)) => {
            line(out, "flyctl", flyctl_version(r, host))?;
            line(out, "fly auth", fly_auth(r, host))?;
            if !without.is_empty() {
                writeln!(
                    out,
                    "skip  fly: no fly section in environment(s) {} (run, config export and item skeleton only)",
                    without.join(", ")
                )
                .map_err(write_err)?;
            }
        }
        Some((false, _)) => {
            for check in ["flyctl", "fly auth"] {
                writeln!(out, "skip  {check}: no environment has a fly section")
                    .map_err(write_err)?;
            }
        }
        None => {
            for check in ["flyctl", "fly auth"] {
                writeln!(out, "skip  {check}: not checked (configuration invalid)")
                    .map_err(write_err)?;
            }
        }
    }
    if cfg!(windows) {
    } else if op_present {
        line(out, "op local run", local_run(r, local_only))?;
    } else {
        writeln!(
            out,
            "skip  op local run: op not available (see the op line above)"
        )
        .map_err(write_err)?;
    }
    line(out, "opv", opv_on_path(r))?;
    let next = next.unwrap_or_else(|| "Next step: nothing pending".into());
    writeln!(out, "{next}").map_err(write_err)?;
    match first {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// `valid (N environment(s), M product(s))`, or under the simple profile, whose one
/// product is hidden (FR-20), `valid (N environment(s), M key(s))`.
fn config_summary(f: &Fleet) -> String {
    let envs = f.environments.len();
    if f.is_simple() {
        let keys: usize = f.products.values().map(|p| p.keys.len()).sum();
        format!("valid ({envs} environment(s), {keys} key(s))")
    } else {
        format!(
            "valid ({envs} environment(s), {} product(s))",
            f.products.len()
        )
    }
}

/// The `Next step` line for the first failing check (FR-22).
///
/// A configuration failure gets a fixed step: its message is parser output (a TOML error
/// carries a `  |` source gutter), not a layout opv controls. For doctor's own tool and auth
/// checks, whose messages opv writes, the step is that check's first remediation line (the
/// install, sign-in, `op account add` or log-in command the failure already prints, FR-26),
/// or the fix-and-re-run hint when it has none. Never tool output or a value (SR-1).
fn next_step(check: &str, e: &Error) -> String {
    if check == CONFIG_CHECK {
        return format!(
            "Next step ({check}): fix secrets.toml (see the config line above) and re-run `opv doctor`"
        );
    }
    let text = e.to_string();
    let hint = text
        .lines()
        .skip(1)
        .find_map(|l| l.strip_prefix("  "))
        .map(|l| l.strip_prefix("next: ").unwrap_or(l).trim());
    match hint {
        Some(h) if !h.is_empty() => format!("Next step ({check}): {h}"),
        _ => format!("Next step ({check}): fix the failure reported above and re-run `opv doctor`"),
    }
}

fn spawn(r: &dyn CommandRunner, program: &str, args: &[&str]) -> Result<Output, Error> {
    let call = crate::runner::Call::new(program, args);
    r.probe(&call, crate::runner::PROBE_TIMEOUT)
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => Error::Dependency(format!("{program} not found on PATH")),
            kind => Error::Dependency(format!("failed to run {program} ({kind})")),
        })
}

/// [`spawn`] whose "not found" names the install command for this platform (FR-26).
fn spawn_tool(
    r: &dyn CommandRunner,
    tool: Tool,
    host: &dyn Fn() -> Host,
    args: &[&str],
) -> Result<Output, Error> {
    let program = match tool {
        Tool::Op => OP,
        Tool::Flyctl => fly::PROGRAM,
    };
    spawn(r, program, args).map_err(|e| match e {
        Error::Dependency(m) if m.ends_with("not found on PATH") => {
            Error::Dependency(format!("{m}\n  {}", host().install_hint(tool)))
        }
        e => e,
    })
}

fn op_version(r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Result<Check, Error> {
    let o = spawn_tool(r, Tool::Op, host, &["--version"])?;
    if o.status != 0 {
        return Err(Error::Dependency(format!(
            "op --version failed (exit {})",
            o.status
        )));
    }
    let (a, b, c) = OP_TESTED_MIN;
    Ok(match version_in(&o.stdout) {
        Some(v) if parse_version(&v).is_some_and(|n| n >= OP_TESTED_MIN) => {
            Check::Ok(format!("version {v}"))
        }
        Some(v) => Check::Warn(format!(
            "version {v}; opv is tested with op {a}.{b}.{c} or newer\n  {}",
            host().install_hint(Tool::Op)
        )),
        None => Check::Warn(format!(
            "present, version not recognised; opv is tested with op {a}.{b}.{c} or newer\n  {}",
            host().install_hint(Tool::Op)
        )),
    })
}

/// The 1Password session, classified exactly as a failed item read is (FR-26).
fn op_auth(r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Result<String, Error> {
    use onepassword::Session;
    match onepassword::diagnose(r, host)? {
        Session::SignedIn(t) => Ok(format!("signed in ({t})")),
        Session::Unknown => Err(Error::Dependency(
            "op whoami did not run to completion; the 1Password session could not be checked"
                .into(),
        )),
        s => {
            Err(onepassword::session_error(s, &host(), None)
                .expect("every other session is an error"))
        }
    }
}

fn flyctl_version(r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Result<Check, Error> {
    let o = spawn_tool(r, Tool::Flyctl, host, &["version"])?;
    if o.status != 0 {
        return Err(Error::Dependency(format!(
            "{} version failed (exit {})",
            fly::PROGRAM,
            o.status
        )));
    }
    let (a, b, c) = FLYCTL_TESTED;
    Ok(match version_in(&o.stdout) {
        Some(v) if parse_version(&v).is_some_and(flyctl_tested) => {
            Check::Ok(format!("version {v}"))
        }
        Some(v) => Check::Warn(format!(
            "version {v}; opv is tested with flyctl {a}.{b}.{c} or a later {a}.{b}.x patch (its secrets import format may differ)\n  {}",
            host().install_hint(Tool::Flyctl)
        )),
        None => Check::Warn(format!(
            "present, version not recognised; opv is tested with flyctl {a}.{b}.{c} or a later {a}.{b}.x patch\n  {}",
            host().install_hint(Tool::Flyctl)
        )),
    })
}

/// Whether `opv run` can work here: the first `op` on PATH must be native, because a Windows
/// `op.exe` reached from WSL cannot start a Linux child (#54). Local-only scopes fail on it;
/// everything else warns, since deployment commands still work through `op.exe`.
fn local_run(r: &dyn CommandRunner, local_only: bool) -> Result<Check, Error> {
    const WINDOWS_OP: &str = "op is the Windows op.exe, which cannot start a Linux child, so \
                              `opv run` will fail here\n  install the Linux 1Password CLI in WSL and sign in: \
                              see docs/local-development.md (WSL)";
    match r.local_run_supported() {
        Ok(()) => Ok(Check::Ok(
            "native op; opv run can start local commands".into(),
        )),
        Err(e) if e.kind() == io::ErrorKind::Unsupported && local_only => {
            Err(Error::Dependency(WINDOWS_OP.into()))
        }
        Err(e) if e.kind() == io::ErrorKind::Unsupported => Ok(Check::Warn(WINDOWS_OP.into())),
        Err(e) if local_only => Err(Error::Dependency(format!(
            "cannot inspect op on PATH ({})",
            e.kind()
        ))),
        Err(e) => Ok(Check::Warn(format!(
            "cannot inspect op on PATH ({})",
            e.kind()
        ))),
    }
}

/// Task I: every `opv` on PATH, one check line. The npm `bin` wrapper runs the canonical
/// binary, so a wrapper beside the binary is the intended state and reads `ok`. A second
/// native copy, or a wrapper whose package version differs from the binary, is a warning
/// naming the command that fixes it. Never fails the run: a candidate that cannot be read
/// still leaves the others reported.
fn opv_on_path(r: &dyn CommandRunner) -> Result<Check, Error> {
    use crate::host::OpvCopy;
    let copies = crate::host::opv_copies_on_path();
    let mut binaries: Vec<(std::path::PathBuf, String)> = Vec::new();
    let mut wrappers: Vec<(std::path::PathBuf, Option<String>)> = Vec::new();
    for copy in copies {
        match copy {
            OpvCopy::Binary(p) => {
                let program = p.to_string_lossy().into_owned();
                let call = crate::runner::Call::new(program.as_str(), &["--version"]);
                let version = match r.probe(&call, crate::runner::PROBE_TIMEOUT) {
                    Ok(o) if o.status == 0 => version_in(o.stdout.as_slice())
                        .unwrap_or_else(|| "version not recognised".into()),
                    _ => "version not recognised".into(),
                };
                binaries.push((p, version));
            }
            OpvCopy::NpmWrapper { path, version } => wrappers.push((path, version)),
        }
    }
    let Some((first, first_version)) = binaries.first() else {
        return Ok(match wrappers.first() {
            None => Check::Ok("not found on PATH".into()),
            Some((p, v)) => Check::Ok(format!(
                "{} {} (npm wrapper running its bundled copy; run: npm rebuild -g @matthew-cochran/opv)",
                p.display(),
                v.as_deref().unwrap_or("version not recognised")
            )),
        });
    };
    let mut fixes: Vec<String> = binaries
        .iter()
        .skip(1)
        .map(|(p, _)| removal_command(p))
        .collect();
    let stale_wrapper = wrappers.iter().any(|(_, v)| {
        v.as_deref()
            .is_some_and(|v| v != first_version.trim_start_matches('v'))
    });
    if stale_wrapper || wrappers.len() > 1 {
        fixes.push("npm update -g @matthew-cochran/opv".into());
    }
    if fixes.is_empty() {
        let also = if wrappers.is_empty() {
            ""
        } else {
            " (also run by the npm wrapper)"
        };
        return Ok(Check::Ok(format!(
            "{} {first_version}{also}",
            first.display()
        )));
    }
    let mut listed: Vec<String> = binaries
        .iter()
        .map(|(p, v)| format!("{} {v}", p.display()))
        .collect();
    listed.extend(wrappers.iter().map(|(p, v)| {
        format!(
            "{} {} (npm wrapper)",
            p.display(),
            v.as_deref().unwrap_or("version not recognised")
        )
    }));
    Ok(Check::Warn(format!(
        "{}; make them one install: {}",
        listed.join(", "),
        fixes.join(", ")
    )))
}

/// The command that removes one opv copy on this platform.
fn removal_command(p: &std::path::Path) -> String {
    if cfg!(windows) {
        format!("del \"{}\"", p.display())
    } else {
        format!("rm {}", p.display())
    }
}

/// `2.40.0` / `v0.4.112` → (major, minor, patch). Missing parts count as 0; anything else
/// (more than three parts, non-digits) is `None`.
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let mut parts = v.split('.').map(|p| p.parse::<u64>().ok());
    let major = parts.next()??;
    let minor = parts.next().unwrap_or(Some(0))?;
    let patch = parts.next().unwrap_or(Some(0))?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// `flyctl auth whoami`: exit status only, via the same check a failed flyctl call uses
/// (FR-26). Its stdout names the account (an email), so it is dropped unread.
fn fly_auth(r: &dyn CommandRunner, host: &dyn Fn() -> Host) -> Result<Check, Error> {
    match fly::auth_whoami(r) {
        Ok(true) => Ok(Check::Ok("signed in".into())),
        // FR-26: app-scoped deploy tokens cannot run `auth whoami`, so with a Fly token in
        // the environment a failure here is not proof of being logged out.
        Ok(false) => match host().fly_token {
            Some(var) => Ok(Check::Warn(format!(
                "{} auth whoami failed with {var} set (an app-scoped deploy token cannot \
                 run it); fly commands will show whether the token can access the app",
                fly::PROGRAM
            ))),
            None => Err(fly::not_logged_in(&host(), None)),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Error::Dependency(format!(
            "{} not found on PATH\n  {}",
            fly::PROGRAM,
            host().install_hint(Tool::Flyctl)
        ))),
        Err(e) => Err(Error::Dependency(format!(
            "failed to run {} ({})",
            fly::PROGRAM,
            e.kind()
        ))),
    }
}

/// The first whitespace-separated token that looks like a version (`2.40.0`, `v0.4.112`),
/// or `None`. Nothing else from tool output is ever printed.
fn version_in(stdout: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(stdout).ok()?;
    s.split_whitespace()
        .find(|t| {
            let digits = t.strip_prefix('v').unwrap_or(t);
            digits.len() <= 32
                && digits.starts_with(|c: char| c.is_ascii_digit())
                && digits.contains('.')
                && digits.chars().all(|c| c.is_ascii_digit() || c == '.')
        })
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::app::testutil::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    const WHOAMI: &str = r#"{"url":"https://my.1password.com","email":"ci-FIXTUREVALUE@example.com","user_uuid":"UFIXTUREVALUE","account_uuid":"AFIXTUREVALUE","user_type":"SERVICE_ACCOUNT"}"#;

    const FLY_WHOAMI: &str = "ops-FIXTUREVALUE@example.com\n";

    fn good() -> Vec<Output> {
        vec![
            Output::success(b"2.40.0\n".to_vec()),
            Output::success(WHOAMI.as_bytes().to_vec()),
            Output::success(
                b"flyctl v0.4.112 linux/amd64 Commit: ca63052e BuildDate: x\n".to_vec(),
            ),
            Output::success(FLY_WHOAMI.as_bytes().to_vec()),
        ]
    }

    fn linux() -> Host {
        Host::from_env(&crate::host::FakeEnv::new("linux").shell("/bin/bash"))
    }

    /// config, op, op auth, flyctl, fly auth, (off Windows) op local run, and opv.
    const CHECK_LINES: usize = if cfg!(windows) { 6 } else { 7 };

    /// Doctor scoped to environments without a target (`doctor --env dev`), on Linux.
    #[cfg(not(windows))]
    fn doctor_local_only(r: &FakeRunner) -> (Result<(), Error>, String) {
        let mut out = Vec::new();
        let res = run_on(Ok(fleet()), r, &|| linux(), true, &mut out);
        (res, text_of(&out))
    }

    #[cfg(not(windows))]
    fn windows_op(r: &FakeRunner) -> &FakeRunner {
        *r.local_run_error.borrow_mut() = Some(io::ErrorKind::Unsupported);
        r
    }

    fn doctor(config: Result<Fleet, Error>, r: &FakeRunner) -> (Result<(), Error>, String) {
        let mut out = Vec::new();
        let res = run_with(config, r, &linux(), &mut out);
        (res, text_of(&out))
    }

    /// The check lines only (remediation lines under a check are indented; the closing
    /// `Next step` line is not a check).
    fn checks(out: &str) -> Vec<&str> {
        out.lines()
            .filter(|l| !l.starts_with("  ") && !l.starts_with("Next step"))
            .collect()
    }

    fn next_line(out: &str) -> &str {
        out.lines().last().unwrap()
    }

    #[test]
    fn all_checks_pass_one_line_each() {
        let r = FakeRunner::new(good());
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        let lines = checks(&out);
        assert_eq!(lines.len(), CHECK_LINES, "{out}");
        assert!(
            lines[0].starts_with("ok") && lines[0].contains("config"),
            "{out}"
        );
        assert!(
            lines[1].contains("op") && lines[1].contains("2.40.0"),
            "{out}"
        );
        assert!(lines[2].contains("SERVICE_ACCOUNT"), "{out}");
        assert!(
            lines[3].contains("flyctl") && lines[3].contains("v0.4.112"),
            "{out}"
        );
        assert!(
            lines[4].starts_with("ok") && lines[4].contains("fly auth"),
            "{out}"
        );
        assert_eq!(
            argvs(&r),
            vec![
                "op --version",
                "op whoami --format json",
                "flyctl version",
                "flyctl auth whoami"
            ]
        );
    }

    /// `op whoami` output names the account; only the account type is printed.
    #[test]
    fn whoami_identity_is_never_printed() {
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_no_values(&out);
        assert!(!out.contains("example.com"), "{out}");
        assert!(!out.contains("1password.com"), "{out}");
    }

    /// Doctor never reads an item (that would cost a rate-limited request).
    #[test]
    fn doctor_never_reads_an_item() {
        let r = FakeRunner::new(good());
        doctor(Ok(fleet()), &r).0.unwrap();
        assert!(!r.argv_contains("item"));
    }

    #[test]
    fn op_missing_is_dependency_and_every_check_still_prints() {
        let r = FakeRunner::new([]);
        r.push_io_error(io::ErrorKind::NotFound);
        r.push_io_error(io::ErrorKind::NotFound);
        r.responses.borrow_mut().push_back(Ok(good().remove(2)));
        r.responses.borrow_mut().push_back(Ok(good().remove(3)));
        let (res, out) = doctor(Ok(fleet()), &r);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Dependency(_)), "{e}");
        let lines = checks(&out);
        assert_eq!(lines.len(), CHECK_LINES, "{out}");
        assert!(lines[3].starts_with("ok"), "{out}");
        assert!(lines[1].starts_with("FAIL"), "{out}");
        assert!(lines[2].starts_with("FAIL  op auth"), "{out}");
        // FR-26: the install command for the detected OS, under the failing check.
        assert!(
            out.contains(
                "op CLI not found on PATH\n  install op from https://developer.1password.com"
            ),
            "{out}"
        );
    }

    #[test]
    fn op_not_signed_in_is_auth() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(br#"[{"url":"x"}]"#.to_vec()));
        let r = FakeRunner::new(g);
        let (res, out) = doctor(Ok(fleet()), &r);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Auth(_)), "{e}");
        assert_eq!(e.exit_code(), 7);
        let lines = checks(&out);
        assert!(
            lines[2].starts_with("FAIL  op auth: authentication error: not signed in"),
            "{out}"
        );
        assert!(out.contains("\n  sign in: eval $(op signin)\n"), "{out}");
        assert_eq!(lines.len(), CHECK_LINES, "{out}");
        // Doctor and the read path share one classification: whoami, then account list.
        assert_eq!(
            argvs(&r)[1..3],
            ["op whoami --format json", "op account list --format json"]
        );
    }

    #[test]
    fn flyctl_missing_is_dependency() {
        let r = FakeRunner::new(good().into_iter().take(2));
        r.push_io_error(io::ErrorKind::NotFound);
        r.push_io_error(io::ErrorKind::NotFound);
        let (res, out) = doctor(Ok(fleet()), &r);
        assert!(matches!(res, Err(Error::Dependency(_))), "{res:?}");
        assert!(out.lines().nth(3).unwrap().starts_with("FAIL"), "{out}");
    }

    /// Invalid config is reported first (the first failing category) but the tool checks
    /// still run and print.
    #[test]
    fn invalid_config_is_config_error_and_other_checks_still_print() {
        let r = FakeRunner::new(good());
        let (res, out) = doctor(Err(Error::Config("invalid secrets.toml: boom".into())), &r);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        let lines = checks(&out);
        assert_eq!(lines.len(), CHECK_LINES, "{out}");
        assert!(
            lines[0].starts_with("FAIL") && lines[0].contains("boom"),
            "{out}"
        );
        assert!(lines[1].starts_with("ok"), "{out}");
    }

    /// FR-3: Fly authentication by exit status; its stdout (an email) is never printed.
    #[test]
    fn fly_auth_passes_without_printing_identity() {
        let r = FakeRunner::new(good());
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        assert!(checks(&out).contains(&"ok    fly auth: signed in"), "{out}");
        assert_no_values(&out);
        assert!(!out.contains("example.com"), "{out}");
    }

    #[test]
    fn fly_not_signed_in_is_auth_and_identity_not_printed() {
        let mut g = good();
        g[3] = Output {
            status: 1,
            stdout: zeroize::Zeroizing::new(FLY_WHOAMI.as_bytes().to_vec()),
        };
        let r = FakeRunner::new(g);
        let (res, out) = doctor(Ok(fleet()), &r);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Auth(_)), "{e}");
        assert!(
            out.lines().nth(4).unwrap().starts_with("FAIL  fly auth"),
            "{out}"
        );
        assert_no_values(&out);
        assert_no_values(&e.to_string());
    }

    /// FR-26: with a Fly token set, a failing `flyctl auth whoami` is a warning (app-scoped
    /// deploy tokens cannot run it), not an authentication failure.
    #[test]
    fn fly_auth_failure_with_fly_token_is_a_warning() {
        let mut g = good();
        g[3] = Output::failure(1);
        let r = FakeRunner::new(g);
        let h = Host::from_env(
            &crate::host::FakeEnv::new("linux")
                .shell("/bin/bash")
                .var("FLY_API_TOKEN"),
        );
        let mut out = Vec::new();
        run_with(Ok(fleet()), &r, &h, &mut out).unwrap();
        let out = text_of(&out);
        assert!(
            out.lines()
                .any(|l| l.starts_with("warn  fly auth:") && l.contains("FLY_API_TOKEN")),
            "{out}"
        );
        assert!(!out.contains("auth login"), "{out}");
    }

    /// I8: tested versions print no warning.
    #[test]
    fn tested_versions_do_not_warn() {
        let r = FakeRunner::new(good());
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        assert!(!out.contains("warn"), "{out}");
    }

    /// I8: an older op, or a flyctl outside 0.4.x from 0.4.112, warns but does not fail.
    #[test]
    fn untested_versions_warn_but_pass() {
        for (op, fly, warn_op, warn_fly) in [
            ("2.39.9\n", "flyctl v0.4.112 linux/amd64\n", true, false),
            ("2.30.0\n", "flyctl v0.4.111 linux/amd64\n", true, true),
            ("2.41.0\n", "flyctl v0.3.0 linux/amd64\n", false, true),
            ("3.0.0\n", "flyctl v0.4.112\n", false, false),
        ] {
            let mut g = good();
            g[0] = Output::success(op.as_bytes().to_vec());
            g[2] = Output::success(fly.as_bytes().to_vec());
            let r = FakeRunner::new(g);
            let (res, out) = doctor(Ok(fleet()), &r);
            res.unwrap();
            let lines = checks(&out);
            assert_eq!(lines[1].starts_with("warn  op:"), warn_op, "{out}");
            assert_eq!(lines[3].starts_with("warn  flyctl:"), warn_fly, "{out}");
            if warn_op {
                assert!(lines[1].contains("2.40.0"), "{out}");
            }
            if warn_fly {
                assert!(lines[3].contains("0.4.112"), "{out}");
            }
        }
    }

    #[test]
    fn later_flyctl_patch_does_not_warn() {
        let mut g = good();
        g[2] = Output::success(b"flyctl v0.4.113 linux/amd64\n".to_vec());
        let r = FakeRunner::new(g);
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        assert!(checks(&out)[3].starts_with("ok    flyctl:"), "{out}");
    }

    #[test]
    fn next_flyctl_minor_warns() {
        let mut g = good();
        g[2] = Output::success(b"flyctl v0.5.0 linux/amd64\n".to_vec());
        let r = FakeRunner::new(g);
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        assert!(checks(&out)[3].starts_with("warn  flyctl:"), "{out}");
    }

    #[test]
    fn parse_version_cases() {
        assert_eq!(parse_version("2.40.0"), Some((2, 40, 0)));
        assert_eq!(parse_version("v0.4.112"), Some((0, 4, 112)));
        assert_eq!(parse_version("2.40"), Some((2, 40, 0)));
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("x"), None);
        assert!(parse_version("2.9.0") < Some(OP_TESTED_MIN));
    }

    /// I5: Fly checks are skipped when no environment has a fly section, and environments
    /// without one are named when others have it.
    #[test]
    fn fly_checks_follow_fly_sections() {
        let no_fly = crate::config::parse(
            "[profile]\nkind = \"fleet\"\n[environments.dev]\nvault_id = \"v\"\nitem_id = \"i\"\n",
        )
        .unwrap();
        let r = FakeRunner::new(good().into_iter().take(2));
        let (res, out) = doctor(Ok(no_fly), &r);
        res.unwrap();
        assert!(
            out.contains("skip  flyctl: no environment has a fly section"),
            "{out}"
        );
        assert_eq!(r.calls.borrow().len(), 2, "{:?}", argvs(&r));

        let mixed = fleet_with("[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n");
        let r = FakeRunner::new(good());
        let (res, out) = doctor(Ok(mixed), &r);
        res.unwrap();
        assert!(out.contains("ok    fly auth"), "{out}");
        assert!(
            out.contains("skip  fly: no fly section in environment(s) dev"),
            "{out}"
        );
    }

    #[test]
    fn simple_profile_config_line_counts_keys_not_products() {
        let simple = crate::config::load("tests/fixtures/simple.toml").unwrap();
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Ok(simple), &r);
        assert_eq!(
            checks(&out)[0],
            "ok    config: valid (2 environment(s), 5 key(s))",
            "{out}"
        );
    }

    #[test]
    fn fleet_config_line_still_counts_products() {
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            checks(&out)[0],
            "ok    config: valid (2 environment(s), 1 product(s))",
            "{out}"
        );
    }

    #[test]
    fn next_step_is_the_last_line_when_all_checks_pass() {
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(next_line(&out), "Next step: nothing pending", "{out}");
    }

    #[test]
    fn next_step_appears_exactly_once() {
        let r = FakeRunner::new([]);
        for _ in 0..4 {
            r.push_io_error(io::ErrorKind::NotFound);
        }
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            out.lines().filter(|l| l.starts_with("Next step")).count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn next_step_names_install_command_when_op_is_missing() {
        let r = FakeRunner::new([]);
        r.push_io_error(io::ErrorKind::NotFound);
        r.push_io_error(io::ErrorKind::NotFound);
        r.responses.borrow_mut().push_back(Ok(good().remove(2)));
        r.responses.borrow_mut().push_back(Ok(good().remove(3)));
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            next_line(&out),
            "Next step (op): install op from https://developer.1password.com/docs/cli/get-started/ \
             (apt, dnf or the zip for this Linux distribution)",
            "{out}"
        );
    }

    #[test]
    fn next_step_names_signin_command_when_op_is_not_signed_in() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(br#"[{"url":"x"}]"#.to_vec()));
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            next_line(&out),
            "Next step (op auth): sign in: eval $(op signin)",
            "{out}"
        );
    }

    #[test]
    fn next_step_names_account_add_when_no_account_exists() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(b"[]".to_vec()));
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert!(
            next_line(&out).starts_with("Next step (op auth): add one: op account add"),
            "{out}"
        );
    }

    #[test]
    fn next_step_names_fly_login_when_fly_is_logged_out() {
        let mut g = good();
        g[3] = Output::failure(1);
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            next_line(&out),
            "Next step (fly auth): log in: flyctl auth login",
            "{out}"
        );
    }

    #[test]
    fn next_step_names_the_first_failing_check() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(br#"[{"url":"x"}]"#.to_vec()));
        g[4] = Output::failure(1); // fly auth fails too
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert!(next_line(&out).starts_with("Next step (op auth):"), "{out}");
    }

    const CONFIG_STEP: &str =
        "Next step (config): fix secrets.toml (see the config line above) and re-run `opv doctor`";

    #[test]
    fn next_step_for_invalid_config_is_fix_and_rerun() {
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Err(Error::Config("invalid secrets.toml: boom".into())), &r);
        assert_eq!(next_line(&out), CONFIG_STEP, "{out}");
    }

    /// A real TOML syntax error carries a `  |` source gutter; it is never the step.
    #[test]
    fn next_step_for_toml_syntax_error_is_the_fixed_config_step() {
        let e = crate::config::parse("[profile\nkind = \"fleet\"\n").unwrap_err();
        assert!(e.to_string().contains("  |"), "{e}");
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Err(e), &r);
        assert_eq!(next_line(&out), CONFIG_STEP, "{out}");
    }

    #[test]
    fn next_step_for_unknown_field_error_is_the_fixed_config_step() {
        let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
        let e = crate::config::parse(&text.replace(
            "guidance = \"OpenAI platform / API keys\"",
            "guidance = \"OpenAI platform / API keys\"\nbogus = 1",
        ))
        .unwrap_err();
        assert!(e.to_string().contains("bogus"), "{e}");
        let r = FakeRunner::new(good());
        let (_, out) = doctor(Err(e), &r);
        assert_eq!(next_line(&out), CONFIG_STEP, "{out}");
    }

    #[test]
    fn next_step_for_failing_version_check_is_fix_and_rerun() {
        let mut g = good();
        g[0] = Output::failure(2);
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        assert_eq!(
            next_line(&out),
            "Next step (op): fix the failure reported above and re-run `opv doctor`",
            "{out}"
        );
    }

    #[test]
    fn next_step_never_prompts() {
        let mut g = good();
        g[1] = Output::failure(1);
        g.insert(2, Output::success(br#"[{"url":"x"}]"#.to_vec()));
        let r = FakeRunner::new(g);
        let (_, out) = doctor(Ok(fleet()), &r);
        let next = next_line(&out);
        assert!(
            !next.contains('?') && !next.to_lowercase().contains("[y/n]"),
            "{next}"
        );
    }

    #[test]
    fn next_step_under_ci_names_service_account_token() {
        let mut g = good();
        g[1] = Output::failure(1);
        let r = FakeRunner::new(g);
        let h = Host::from_env(
            &crate::host::FakeEnv::new("linux")
                .shell("/bin/bash")
                .var("CI"),
        );
        let mut out = Vec::new();
        let _ = run_with(Ok(fleet()), &r, &h, &mut out);
        let out = text_of(&out);
        assert!(
            next_line(&out).starts_with("Next step (op auth): set OP_SERVICE_ACCOUNT_TOKEN"),
            "{out}"
        );
    }

    /// Unparseable tool output is not echoed (it could be anything).
    #[test]
    fn odd_version_output_is_not_echoed() {
        let mut g = good();
        g[0] = Output::success(b"weird FIXTUREVALUE output\n".to_vec());
        let r = FakeRunner::new(g);
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        assert_no_values(&out);
    }

    #[test]
    fn scoped_development_doctor_never_queries_fly_in_mixed_file() {
        let mut f = fleet();
        let mut env = f.environments["staging"].clone();
        env.target = None;
        f.environments.insert("dev".into(), env);
        let r = FakeRunner::new(good().into_iter().take(2));
        let mut out = Vec::new();
        run_scoped(Ok(f), Some("dev"), Some("allumata"), &r, &mut out).unwrap();
        assert!(r.calls.borrow().iter().all(|c| c.program == "op"));
    }
    #[cfg(not(windows))]
    #[test]
    fn native_op_passes_the_local_run_check() {
        let (_, out) = doctor(Ok(fleet()), &FakeRunner::new(good()));
        assert!(out.contains("ok    op local run: native op"), "{out}");
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_op_warns_when_deployment_environments_are_in_scope() {
        let r = FakeRunner::new(good());
        let (res, _) = doctor(Ok(fleet()), windows_op(&r));
        assert!(res.is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_op_fails_a_local_only_scope() {
        let r = FakeRunner::new(good());
        let (res, _) = doctor_local_only(windows_op(&r));
        assert!(matches!(res, Err(Error::Dependency(_))));
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_op_failure_still_prints_every_check_and_a_next_step() {
        let r = FakeRunner::new(good());
        let (_, out) = doctor_local_only(windows_op(&r));
        assert!(
            out.ends_with(
                "Next step (op local run): install the Linux 1Password CLI in WSL and sign in: see docs/local-development.md (WSL)\n"
            ),
            "{out}"
        );
    }

    fn binary(p: &str) -> crate::host::OpvCopy {
        crate::host::OpvCopy::Binary(std::path::PathBuf::from(p))
    }

    fn wrapper(p: &str, v: Option<&str>) -> crate::host::OpvCopy {
        crate::host::OpvCopy::NpmWrapper {
            path: std::path::PathBuf::from(p),
            version: v.map(str::to_owned),
        }
    }

    /// Doctor output with `copies` on PATH and `versions` answering each binary probe.
    fn doctor_with_opv_copies(copies: Vec<crate::host::OpvCopy>, versions: &[&str]) -> String {
        let r = FakeRunner::new(
            good().into_iter().chain(
                versions
                    .iter()
                    .map(|v| Output::success(format!("opv {v}\n").into_bytes())),
            ),
        );
        let mut out = Vec::new();
        let res =
            crate::host::with_test_path(copies, || run_with(Ok(fleet()), &r, &linux(), &mut out));
        res.unwrap();
        text_of(&out)
    }

    #[test]
    fn doctor_lists_one_opv_on_path_with_its_version() {
        let out = doctor_with_opv_copies(vec![binary("/opt/opv/bin/opv")], &["1.2.3"]);
        assert!(out.contains("ok    opv: /opt/opv/bin/opv 1.2.3"), "{out}");
    }

    #[test]
    fn doctor_accepts_the_npm_wrapper_beside_the_matching_binary() {
        let out = doctor_with_opv_copies(
            vec![
                binary("/home/x/.local/bin/opv"),
                wrapper("/usr/bin/opv", Some("1.2.3")),
            ],
            &["1.2.3"],
        );
        assert!(
            out.contains("ok    opv: /home/x/.local/bin/opv 1.2.3 (also run by the npm wrapper)"),
            "{out}"
        );
    }

    #[test]
    fn doctor_warns_on_two_opv_copies() {
        let out = doctor_with_opv_copies(
            vec![
                binary("/home/x/.local/bin/opv"),
                binary("/home/x/.cargo/bin/opv"),
            ],
            &["1.2.3", "1.1.0"],
        );
        assert!(
            out.lines()
                .any(|l| l.starts_with("warn  opv:") && l.contains("rm /home/x/.cargo/bin/opv")),
            "{out}"
        );
    }

    #[test]
    fn doctor_warns_when_the_npm_wrapper_is_a_different_version() {
        let out = doctor_with_opv_copies(
            vec![
                binary("/home/x/.local/bin/opv"),
                wrapper("/usr/bin/opv", Some("1.1.0")),
            ],
            &["1.2.3"],
        );
        assert!(
            out.lines()
                .any(|l| l.starts_with("warn  opv:")
                    && l.contains("npm update -g @matthew-cochran/opv")),
            "{out}"
        );
    }

    #[test]
    fn doctor_does_not_run_the_npm_wrapper_to_read_its_version() {
        // One probe answer only: a second probe would exhaust the fake runner.
        let out = doctor_with_opv_copies(
            vec![
                binary("/home/x/.local/bin/opv"),
                wrapper("/usr/bin/opv", Some("1.2.3")),
            ],
            &["1.2.3"],
        );
        assert!(!out.contains("fail"), "{out}");
    }
}
