//! Fly deploy credentials (FR-40): the item's `FLY_API_TOKEN` is handed to every `flyctl`
//! call of the run in the child's environment only (never argv, never a file, SR-3/SR-4).
//! `FLY_ACCESS_TOKEN`, which flyctl prefers when set, gets the same token so the
//! environment's deploy identity always wins over one in the user's shell.

use std::collections::BTreeMap;

use super::PROGRAM;
use crate::domain::{Kind, SecretValue};
use crate::error::Error;
use crate::provider::{CredentialField, DeployLogin};
use crate::runner::CommandRunner;

/// The field a Fly `deploy_credentials` item holds.
pub const FIELDS: &[CredentialField] = &[CredentialField {
    label: "FLY_API_TOKEN",
    kind: Kind::Secret,
}];

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
        self.token =
            Some(values.remove("FLY_API_TOKEN").ok_or_else(|| {
                Error::Source("deploy credentials: FLY_API_TOKEN is missing".into())
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
