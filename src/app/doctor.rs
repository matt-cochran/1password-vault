//! `doctor` use case (FR-3).
//!
//! Checks, one line each, always all of them: configuration valid; `op --version`;
//! `op whoami` (authentication; free of rate-limit cost per D0); `flyctl version` and
//! `flyctl auth whoami` (exit status only) when some environment has a `fly` section.
//! Environments without one are listed as skipped for Fly. Returns the error of the first
//! failing check.
//!
//! A tool version opv was not tested with (op older than 2.40.0, flyctl other than
//! 0.4.112) is a `warn` line, never a failure.
//!
//! Tool output is never echoed: only a version string that matches a strict pattern, and
//! from `op whoami` only the account type (`SERVICE_ACCOUNT`, ...), never identity or
//! tokens. No item is read.

use std::io::{self, Write};

use super::write_err;
use crate::adapters::fly;
use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::{CommandRunner, Output};

/// The 1Password CLI binary (same name the 1Password adapter runs).
const OP: &str = "op";

/// Oldest `op` release opv is tested with.
pub const OP_TESTED_MIN: (u64, u64, u64) = (2, 40, 0);
/// The `flyctl` release opv is tested with (its import parser is ported, see fly.rs).
pub const FLYCTL_TESTED: (u64, u64, u64) = (0, 4, 112);

/// A check result: ok, ok with a warning, or failed.
enum Check {
    Ok(String),
    Warn(String),
}

pub fn run(
    config: Result<Fleet, Error>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let mut first: Option<Error> = None;
    let mut line = |out: &mut dyn Write, check: &str, res: Result<Check, Error>| {
        let text = match res {
            Ok(Check::Ok(detail)) => format!("ok    {check}: {detail}"),
            Ok(Check::Warn(detail)) => format!("warn  {check}: {detail}"),
            Err(e) => {
                let t = format!("FAIL  {check}: {e}");
                first.get_or_insert(e);
                t
            }
        };
        writeln!(out, "{text}").map_err(write_err)
    };

    // (any environment has fly, environments without fly)
    let fly_envs = match &config {
        Ok(f) => Some((
            f.environments.values().any(|e| e.fly.is_some()),
            f.environments
                .iter()
                .filter(|(_, e)| e.fly.is_none())
                .map(|(n, _)| n.clone())
                .collect::<Vec<_>>(),
        )),
        Err(_) => None,
    };
    line(
        out,
        "config",
        config.map(|f| {
            Check::Ok(format!(
                "valid ({} environment(s), {} product(s))",
                f.environments.len(),
                f.products.len()
            ))
        }),
    )?;
    line(out, "op", op_version(r))?;
    line(out, "op auth", op_whoami(r).map(Check::Ok))?;
    match fly_envs {
        Some((true, without)) => {
            line(out, "flyctl", flyctl_version(r))?;
            line(out, "fly auth", fly_auth(r).map(Check::Ok))?;
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
    match first {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn spawn(r: &dyn CommandRunner, program: &str, args: &[&str]) -> Result<Output, Error> {
    r.run(program, args, None, &[]).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => Error::Dependency(format!("{program} not found on PATH")),
        kind => Error::Dependency(format!("failed to run {program} ({kind})")),
    })
}

fn op_version(r: &dyn CommandRunner) -> Result<Check, Error> {
    let o = spawn(r, OP, &["--version"])?;
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
            "version {v}; opv is tested with op {a}.{b}.{c} or newer"
        )),
        None => Check::Warn(format!(
            "present, version not recognised; opv is tested with op {a}.{b}.{c} or newer"
        )),
    })
}

fn op_whoami(r: &dyn CommandRunner) -> Result<String, Error> {
    let o = spawn(r, OP, &["whoami", "--format", "json"])?;
    if o.status != 0 {
        return Err(Error::Auth(format!(
            "op whoami failed (exit {}): not signed in to 1Password (set \
             OP_SERVICE_ACCOUNT_TOKEN or run `op signin`)",
            o.status
        )));
    }
    let kind = serde_json::from_slice::<serde_json::Value>(&o.stdout)
        .ok()
        .and_then(|v| v.get("user_type")?.as_str().map(str::to_owned))
        .filter(|t| {
            !t.is_empty() && t.len() <= 32 && t.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        });
    Ok(match kind {
        Some(t) => format!("signed in ({t})"),
        None => "signed in".into(),
    })
}

fn flyctl_version(r: &dyn CommandRunner) -> Result<Check, Error> {
    let o = spawn(r, fly::PROGRAM, &["version"])?;
    if o.status != 0 {
        return Err(Error::Dependency(format!(
            "{} version failed (exit {})",
            fly::PROGRAM,
            o.status
        )));
    }
    let (a, b, c) = FLYCTL_TESTED;
    Ok(match version_in(&o.stdout) {
        Some(v) if parse_version(&v) == Some(FLYCTL_TESTED) => Check::Ok(format!("version {v}")),
        Some(v) => Check::Warn(format!(
            "version {v}; opv is tested with flyctl {a}.{b}.{c} (its secrets import format may differ)"
        )),
        None => Check::Warn(format!(
            "present, version not recognised; opv is tested with flyctl {a}.{b}.{c}"
        )),
    })
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

/// `flyctl auth whoami`: exit status only. Its stdout names the account (an email), so it
/// is dropped unread (zeroized with the `Output`).
fn fly_auth(r: &dyn CommandRunner) -> Result<String, Error> {
    let o = spawn(r, fly::PROGRAM, &["auth", "whoami"])?;
    if o.status != 0 {
        return Err(Error::Auth(format!(
            "{} auth whoami failed (exit {}): not signed in to Fly (set FLY_API_TOKEN or run \
             `flyctl auth login`)",
            fly::PROGRAM,
            o.status
        )));
    }
    Ok("signed in".into())
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

    fn doctor(config: Result<Fleet, Error>, r: &FakeRunner) -> (Result<(), Error>, String) {
        let mut out = Vec::new();
        let res = run(config, r, &mut out);
        (res, text_of(&out))
    }

    #[test]
    fn all_checks_pass_one_line_each() {
        let r = FakeRunner::new(good());
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 5, "{out}");
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
        assert_eq!(out.lines().count(), 5, "{out}");
        assert!(out.lines().nth(3).unwrap().starts_with("ok"), "{out}");
        assert!(out.lines().nth(1).unwrap().starts_with("FAIL"), "{out}");
    }

    #[test]
    fn op_not_signed_in_is_auth() {
        let mut g = good();
        g[1] = Output::failure(1);
        let r = FakeRunner::new(g);
        let (res, out) = doctor(Ok(fleet()), &r);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Auth(_)), "{e}");
        assert_eq!(e.exit_code(), 7);
        assert!(out.lines().nth(2).unwrap().starts_with("FAIL"), "{out}");
        assert_eq!(out.lines().count(), 5, "{out}");
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
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 5, "{out}");
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
        assert_eq!(
            out.lines().last().unwrap(),
            "ok    fly auth: signed in",
            "{out}"
        );
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

    /// I8: tested versions print no warning.
    #[test]
    fn tested_versions_do_not_warn() {
        let r = FakeRunner::new(good());
        let (res, out) = doctor(Ok(fleet()), &r);
        res.unwrap();
        assert!(!out.contains("warn"), "{out}");
    }

    /// I8: an older op or a different flyctl warns but does not fail.
    #[test]
    fn untested_versions_warn_but_pass() {
        for (op, fly, warn_op, warn_fly) in [
            ("2.39.9\n", "flyctl v0.4.112 linux/amd64\n", true, false),
            ("2.30.0\n", "flyctl v0.4.113 linux/amd64\n", true, true),
            ("2.41.0\n", "flyctl v0.3.0 linux/amd64\n", false, true),
            ("3.0.0\n", "flyctl v0.4.112\n", false, false),
        ] {
            let mut g = good();
            g[0] = Output::success(op.as_bytes().to_vec());
            g[2] = Output::success(fly.as_bytes().to_vec());
            let r = FakeRunner::new(g);
            let (res, out) = doctor(Ok(fleet()), &r);
            res.unwrap();
            let lines: Vec<&str> = out.lines().collect();
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
}
