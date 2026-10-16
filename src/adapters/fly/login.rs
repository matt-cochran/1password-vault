//! Fly deploy credentials (FR-40): the item's `FLY_API_TOKEN` is handed to every `flyctl`
//! call of the run in the child's environment only (never argv, never a file, SR-3/SR-4).
//! `FLY_ACCESS_TOKEN`, which flyctl prefers when set, gets the same token so the
//! environment's deploy identity always wins over one in the user's shell.

use std::collections::BTreeMap;

use super::{CREDENTIAL_VARS, PROGRAM};
use crate::cause::{
    Cause, CommandId, CreateKind, DiagnoseContext, Principal, Refind, System, VarName, VendorCmd,
};
use crate::domain::{Kind, SecretValue};
use crate::error::Error;
use crate::host::Host;
use crate::provider::{CredentialField, DeployLogin};
use crate::runner::{Call, CommandRunner, CreateOutcome};

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

/// Read-only preflight before minting a deploy credential (FR-40). A Fly token in the
/// shell (`FLY_API_TOKEN`, `FLY_ACCESS_TOKEN`) overrides the person's own login for every
/// flyctl call, so no `flyctl auth login` can help: minting needs the person's own session
/// without it (06.05, `Cause::NeedsOwnSession`). Otherwise `flyctl auth whoami`, exit status
/// only (its stdout names the account and is dropped unread, SR-1); a failure is diagnosed
/// from its reply (design §5), never assumed to be a sign-out (06.11).
pub fn mint_preflight(r: &dyn CommandRunner) -> Result<(), Error> {
    mint_preflight_on(r, &Host::detect())
}

fn mint_preflight_on(r: &dyn CommandRunner, host: &Host) -> Result<(), Error> {
    if let Some(var) = host.token(CREDENTIAL_VARS) {
        return Err(Cause::NeedsOwnSession {
            command: CommandId(MINT_COMMAND.to_string()),
            identity: Principal::ShellToken {
                var: VarName::new(var),
            },
        }
        .into());
    }
    let ctx = DiagnoseContext::default();
    match super::auth_whoami(r) {
        Ok(true) => Ok(()),
        Ok(false) => Err(super::failed_call(&ctx)),
        Err(e) => Err(super::call_error(r, &|| *host, &e, &ctx)),
    }
}

/// The command a minted credential comes from, as messages name it.
const MINT_COMMAND: &str = "target credentials --create";

/// The vendor read that shows whether a deploy token named `name` exists on `app`: the one
/// check before anything is minted again (X5).
fn tokens_list(app: &str) -> VendorCmd {
    VendorCmd {
        program: PROGRAM.to_string(),
        args: ["tokens", "list", "--app", app]
            .map(str::to_string)
            .to_vec(),
    }
}

/// Mint a least-privilege Fly deploy token (FR-40): one
/// `flyctl tokens create deploy --app <app> --name <name> --expiry 2160h` (90 days), run as
/// a create ([`CommandRunner::create`], never retried). The token is returned under
/// [`TOKEN_FIELD`]; stdout is read once, trimmed and held only in a zeroizing
/// [`SecretValue`], and is never put in argv or an error (SR-1/SR-3). An empty token is
/// refused.
///
/// When the outcome is unknown (a timeout, a kill, a lost reply), a token may exist whose
/// secret was never stored: the step is to look for it with `flyctl tokens list --app <app>`
/// and revoke it, never to mint again (06.10, X5).
pub fn mint_deploy_credential(
    r: &dyn CommandRunner,
    app: &str,
    name: &str,
) -> Result<BTreeMap<String, SecretValue>, Error> {
    let expiry = format!("{TOKEN_EXPIRY_HOURS}h");
    let args = [
        "tokens", "create", "deploy", "--app", app, "--name", name, "--expiry", &expiry,
    ];
    let refind = Refind::Vendor(tokens_list(app));
    let ctx = DiagnoseContext {
        create: Some((CreateKind::DeployToken, name.to_string(), refind.clone())),
        write: true,
        ..super::app_context(app)
    };
    let out = match r.create(&Call::new(PROGRAM, &args), CreateKind::DeployToken) {
        Ok(CreateOutcome::Done(out)) => out,
        // A definite refusal: nothing was made; the reply says why (design §5).
        Ok(CreateOutcome::Refused(_)) => return Err(super::failed_call(&ctx)),
        Ok(CreateOutcome::OutcomeUnknown(seen)) => {
            let _ = crate::runner::take_failure_excerpt();
            return Err(Cause::CreateOutcomeUnknown {
                system: System::Fly,
                kind: CreateKind::DeployToken,
                name: name.to_string(),
                refind,
                seen,
            }
            .into());
        }
        Err(e) => return Err(super::call_error(r, &Host::detect, &e, &ctx)),
    };
    let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
    // From here on, any output that might echo it is scrubbed (SR-1).
    crate::scrub::register_secret(&token);
    if token.is_empty() {
        // flyctl answered with no token: nothing to store (A1, the runner's observation).
        return Err(
            match crate::runner::take_unusable_reply(&Call::new(PROGRAM, &args)) {
                Some(seen) => Cause::UnexpectedOutput {
                    system: System::Fly,
                    at: None,
                    problem: crate::cause::OutputProblem::Empty {
                        what: "deploy token",
                    },
                    // flyctl applied the create (exit 0); only its reply is unusable.
                    during: crate::cause::During::AppliedWrite,
                    seen,
                }
                .into(),
                None => Cause::Bug {
                    site: "fly: a flyctl token reply the runner did not observe",
                }
                .into(),
            },
        );
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
        // The item was read with every field the provider declares (read_deploy_credentials
        // refuses one without them), so a missing one is opv's bug.
        self.token = Some(values.remove("FLY_API_TOKEN").ok_or_else(|| {
            Error::from(Cause::Bug {
                site: "fly: deploy sign-in given values without a declared field",
            })
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
