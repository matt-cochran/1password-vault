//! GitHub deploy credentials (FR-40, FR-46): the item's `GH_TOKEN` (a fine-grained token
//! with Secrets and Variables write on the listed repositories) is handed to every `gh`
//! call of the run in the child's environment only (never argv, never a file, SR-3/SR-4).

use std::collections::BTreeMap;

use super::PROGRAM;
use crate::domain::{Kind, SecretValue};
use crate::error::Error;
use crate::provider::{CredentialField, DeployLogin};
use crate::runner::CommandRunner;

/// The field a GitHub `deploy_credentials` item holds.
pub const FIELDS: &[CredentialField] = &[CredentialField {
    label: "GH_TOKEN",
    kind: Kind::Secret,
}];

/// A GitHub token for one run.
#[derive(Default)]
pub struct GithubLogin {
    token: Option<SecretValue>,
}

impl DeployLogin for GithubLogin {
    fn sign_in(
        &mut self,
        mut values: BTreeMap<String, SecretValue>,
        _r: &dyn CommandRunner,
    ) -> Result<(), Error> {
        // The item was read with every field the provider declares (read_deploy_credentials
        // refuses one without them), so a missing one is opv's bug.
        self.token = Some(values.remove("GH_TOKEN").ok_or_else(|| {
            Error::from(crate::cause::Cause::Bug {
                site: "github: deploy sign-in given values without a declared field",
            })
        })?);
        Ok(())
    }

    fn env(&self, program: &str) -> Vec<(&'static str, &str)> {
        match (&self.token, program == PROGRAM) {
            (Some(t), true) => vec![("GH_TOKEN", t.expose())],
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::fake::FakeRunner;

    const MARKER_TOKEN: &str = "ghp_FIXTUREVALUE-token";

    fn signed_in() -> GithubLogin {
        let mut l = GithubLogin::default();
        let values = BTreeMap::from([(
            "GH_TOKEN".to_string(),
            SecretValue::new(MARKER_TOKEN.into()),
        )]);
        l.sign_in(values, &FakeRunner::default()).unwrap();
        l
    }

    #[test]
    fn token_goes_to_gh_env() {
        let l = signed_in();
        assert_eq!(l.env(PROGRAM), [("GH_TOKEN", MARKER_TOKEN)]);
    }

    #[test]
    fn token_never_reaches_op() {
        let l = signed_in();
        assert!(l.env("op").is_empty());
    }

    #[test]
    fn token_never_reaches_other_programs() {
        let l = signed_in();
        assert!(l.env("az").is_empty());
    }

    #[test]
    fn sign_in_refuses_a_missing_token() {
        let mut l = GithubLogin::default();
        assert!(l.sign_in(BTreeMap::new(), &FakeRunner::default()).is_err());
    }

    #[test]
    fn a_deploy_item_without_a_token_is_deploy_credentials_failed() {
        let mut l = GithubLogin::default();
        let e = l
            .sign_in(BTreeMap::new(), &FakeRunner::default())
            .unwrap_err();
        // The item is read with every declared field, so a missing one is opv's bug.
        assert_eq!(e.code_str(), "internal_error");
    }
}
