//! `doctor` use case (FR-3).
//!
//! Checks, one line each, always all of them: configuration valid; `op --version`;
//! `op whoami` (authentication; free of rate-limit cost per D0); `flyctl version` when the
//! configuration declares a Fly app. Returns the error of the first failing check.
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

pub fn run(
    config: Result<Fleet, Error>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let mut first: Option<Error> = None;
    let mut line = |out: &mut dyn Write, check: &str, res: Result<String, Error>| {
        let text = match res {
            Ok(detail) => format!("ok    {check}: {detail}"),
            Err(e) => {
                let t = format!("FAIL  {check}: {e}");
                first.get_or_insert(e);
                t
            }
        };
        writeln!(out, "{text}").map_err(write_err)
    };

    let wants_fly = match &config {
        Ok(f) => Some(f.environments.values().any(|e| !e.fly_app.is_empty())),
        Err(_) => None,
    };
    line(
        out,
        "config",
        config.map(|f| {
            format!(
                "valid ({} environment(s), {} product(s))",
                f.environments.len(),
                f.products.len()
            )
        }),
    )?;
    line(out, "op", op_version(r))?;
    line(out, "op auth", op_whoami(r))?;
    match wants_fly {
        Some(true) => line(out, "flyctl", flyctl_version(r))?,
        Some(false) => writeln!(out, "skip  flyctl: no Fly app configured").map_err(write_err)?,
        None => {
            writeln!(out, "skip  flyctl: not checked (configuration invalid)").map_err(write_err)?
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

fn op_version(r: &dyn CommandRunner) -> Result<String, Error> {
    let o = spawn(r, OP, &["--version"])?;
    if o.status != 0 {
        return Err(Error::Dependency(format!(
            "op --version failed (exit {})",
            o.status
        )));
    }
    Ok(version_in(&o.stdout).map_or_else(|| "present".into(), |v| format!("version {v}")))
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

fn flyctl_version(r: &dyn CommandRunner) -> Result<String, Error> {
    let o = spawn(r, fly::PROGRAM, &["version"])?;
    if o.status != 0 {
        return Err(Error::Dependency(format!(
            "{} version failed (exit {})",
            fly::PROGRAM,
            o.status
        )));
    }
    Ok(version_in(&o.stdout).map_or_else(|| "present".into(), |v| format!("version {v}")))
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

    fn good() -> Vec<Output> {
        vec![
            Output::success(b"2.40.0\n".to_vec()),
            Output::success(WHOAMI.as_bytes().to_vec()),
            Output::success(
                b"flyctl v0.4.112 linux/amd64 Commit: ca63052e BuildDate: x\n".to_vec(),
            ),
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
        assert_eq!(lines.len(), 4, "{out}");
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
        assert_eq!(
            argvs(&r),
            vec!["op --version", "op whoami --format json", "flyctl version"]
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
        let (res, out) = doctor(Ok(fleet()), &r);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Dependency(_)), "{e}");
        assert_eq!(out.lines().count(), 4, "{out}");
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
        assert_eq!(e.exit_code(), 3);
        assert!(out.lines().nth(2).unwrap().starts_with("FAIL"), "{out}");
        assert_eq!(out.lines().count(), 4, "{out}");
    }

    #[test]
    fn flyctl_missing_is_dependency() {
        let r = FakeRunner::new(good().into_iter().take(2));
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
        assert_eq!(lines.len(), 4, "{out}");
        assert!(
            lines[0].starts_with("FAIL") && lines[0].contains("boom"),
            "{out}"
        );
        assert!(lines[1].starts_with("ok"), "{out}");
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
