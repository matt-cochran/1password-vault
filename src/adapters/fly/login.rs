//! Fly deploy credentials (FR-40): the item's `FLY_API_TOKEN` is handed to every `flyctl`
//! call of the run in the child's environment only (never argv, never a file, SR-3/SR-4).
//! `FLY_ACCESS_TOKEN`, which flyctl prefers when set, gets the same token so the
//! environment's deploy identity always wins over one in the user's shell.

use std::collections::BTreeMap;
use std::io;

use super::{FLYCTL, PROGRAM};
use crate::domain::{Kind, SecretValue};
use crate::error::{Code, Error};
use crate::host::Host;
use crate::provider::{CredentialField, DeployLogin};
use crate::runner::{Call, CommandRunner, Outcome};

/// The field a Fly `deploy_credentials` item holds.
pub const FIELDS: &[CredentialField] = &[CredentialField {
    label: "FLY_API_TOKEN",
    kind: Kind::Secret,
}];

/// The field [`mint_deploy_credential`] returns its token under.
pub const TOKEN_FIELD: &str = "FLY_API_TOKEN";

/// How long a minted Fly deploy token stays valid: 90 days (`--expiry 2160h`).
pub const TOKEN_EXPIRY_HOURS: u32 = 2160;

/// How a person revokes a token [`mint_deploy_credential`] created, for the error when it
/// could not be stored (SR-4).
pub const CLEANUP_HINT: &str =
    "run `flyctl tokens list --app <app>` to see its ID, then `flyctl tokens revoke <id>`";

/// Read-only preflight before minting a deploy credential (FR-40): `flyctl auth whoami`,
/// exit status only (its stdout names the account and is dropped unread, SR-1). Not signed
/// in is `Error::Auth` (`Code::AuthRequired`) with `flyctl auth login`; a missing CLI is
/// `Error::Dependency`.
pub fn mint_preflight(r: &dyn CommandRunner) -> Result<(), Error> {
    let host = Host::detect();
    match super::auth_whoami(r) {
        Ok(true) => Ok(()),
        Ok(false) => Err(Error::Auth(
            format!(
                "not logged in to Fly ({PROGRAM} auth whoami failed)\n  log in: {PROGRAM} auth login"
            )
            .into(),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Error::Dependency(
            format!("{PROGRAM} not found on PATH\n  {}", host.install_hint(FLYCTL)).into(),
        )),
        Err(e) if e.kind() == io::ErrorKind::TimedOut => Err(super::whoami_unanswered(&e)),
        Err(e) => Err(Error::Dependency(
            format!("failed to run {PROGRAM} ({})", e.kind()).into(),
        )),
    }
}

/// Mint a least-privilege Fly deploy token (FR-40): one
/// `flyctl tokens create deploy --app <app> --name <name> --expiry 2160h` (90 days). The
/// token is returned under [`TOKEN_FIELD`]; stdout is read once, trimmed and held only in a
/// zeroizing [`SecretValue`], and is never put in argv or an error (SR-1/SR-3). An empty
/// token is refused.
pub fn mint_deploy_credential(
    r: &dyn CommandRunner,
    app: &str,
    name: &str,
) -> Result<BTreeMap<String, SecretValue>, Error> {
    let expiry = format!("{TOKEN_EXPIRY_HOURS}h");
    let args = [
        "tokens", "create", "deploy", "--app", app, "--name", name, "--expiry", &expiry,
    ];
    let what = format!("{PROGRAM} tokens create deploy");
    let out = match r.write(&Call::new(PROGRAM, &args)) {
        Ok(Outcome::Done(out)) => out,
        Ok(Outcome::Refused(out)) => {
            // The sign-in was checked just before (`mint_preflight`): what is left is the
            // app itself or this account's rights on it.
            return Err(Error::Target(
                format!(
                    "{what} failed for app {app} (exit {}); no token was stored\n  the \
                     logged-in Fly account was checked just before, so the app is missing \
                     or this account cannot create tokens for it",
                    out.status
                )
                .into(),
            )
            .with_do(format!(
                "check that app {app} exists and that the logged-in Fly account is an admin \
                 of its organization ({PROGRAM} apps list shows the apps it can see)"
            )));
        }
        Ok(Outcome::Unknown {
            status: Some(status),
            ..
        }) => {
            return Err(Error::Unknown(
                format!(
                    "{what} failed (exit {status}); a token named {name:?} may or may not have \
                     been created\n  next: check `{PROGRAM} tokens list --app {app}`, then re-run \
                     the same command"
                )
                .into(),
            ));
        }
        Ok(Outcome::Unknown { reason, .. }) => {
            return Err(Error::Unknown(
                format!(
                    "{what}: {}; a token named {name:?} may or may not have been created\n  \
                     next: re-run the same command",
                    crate::runner::unknown_text(PROGRAM, reason)
                )
                .into(),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(Error::Dependency(
                format!("{PROGRAM} not found on PATH").into(),
            ));
        }
        Err(e) => {
            return Err(Error::Target(
                format!("{what} could not start {PROGRAM} ({})", e.kind()).into(),
            ));
        }
    };
    let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
    // From here on, any output that might echo it is scrubbed (SR-1).
    crate::scrub::register_secret(&token);
    if token.is_empty() {
        return Err(Error::Target(
            format!("{what} returned no token; no token was stored").into(),
        ));
    }
    Ok(BTreeMap::from([(
        TOKEN_FIELD.to_string(),
        SecretValue::new(token),
    )]))
}

/// A Fly token for one run.
#[derive(Default)]
pub struct FlyLogin {
    token: Option<SecretValue>,
}

impl DeployLogin for FlyLogin {
    fn sign_in(
        &mut self,
        mut values: BTreeMap<String, SecretValue>,
        _r: &dyn CommandRunner,
    ) -> Result<(), Error> {
        self.token = Some(values.remove("FLY_API_TOKEN").ok_or_else(|| {
            Error::Auth(
                "deploy credentials: the deploy_credentials item has no FLY_API_TOKEN field; \
                 nothing was changed"
                    .into(),
            )
            .with_code(Code::DeployCredentialsFailed)
            .with_do(
                "add a FLY_API_TOKEN field holding a Fly deploy token to the environment's \
                 deploy_credentials item in 1Password",
            )
        })?);
        Ok(())
    }

    fn env(&self, program: &str) -> Vec<(&'static str, &str)> {
        match (&self.token, program == PROGRAM) {
            (Some(t), true) => vec![
                ("FLY_API_TOKEN", t.expose()),
                ("FLY_ACCESS_TOKEN", t.expose()),
            ],
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    const MARKER_TOKEN: &str = "fo1_FIXTUREVALUE-token";

    fn signed_in() -> FlyLogin {
        let mut l = FlyLogin::default();
        let values = BTreeMap::from([(
            "FLY_API_TOKEN".to_string(),
            SecretValue::new(MARKER_TOKEN.into()),
        )]);
        l.sign_in(values, &FakeRunner::default()).unwrap();
        l
    }

    #[test]
    fn token_goes_to_flyctl_env() {
        let l = signed_in();
        assert!(l.env(PROGRAM).contains(&("FLY_API_TOKEN", MARKER_TOKEN)));
    }

    #[test]
    fn token_never_reaches_other_programs() {
        let l = signed_in();
        assert!(l.env("op").is_empty() && l.env("az").is_empty());
    }
}
