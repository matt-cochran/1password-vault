//! HTTP deploy credentials (design `http-target` §4.1): the item's `base_url`, `token`
//! (concealed, the bare token; opv adds `Bearer `) and the Cloudflare Access service token
//! (`cf_access_client_id`, `cf_access_client_secret`). The three credentials are
//! [`SecretValue`]s registered with the scrubber and handed to the runner's HTTPS call as
//! header pairs only — never argv, an error, a log or a file (SR-3, SR-8, T21).

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::url::{Destination, parse_base_url};
use crate::cause::{Cause, FieldRule, InputKind};
use crate::domain::{Kind, SecretValue};
use crate::error::Error;
use crate::provider::{CredentialField, DeployLogin};
use crate::runner::CommandRunner;
use crate::runner_https::PROGRAM;

/// The fields an HTTP `deploy_credentials` item holds (§4.1): `base_url` is text, the three
/// credentials are concealed, and all four are required (T21).
pub const FIELDS: &[CredentialField] = &[
    CredentialField {
        label: "base_url",
        kind: Kind::Config,
    },
    CredentialField {
        label: "token",
        kind: Kind::Secret,
    },
    CredentialField {
        label: "cf_access_client_id",
        kind: Kind::Secret,
    },
    CredentialField {
        label: "cf_access_client_secret",
        kind: Kind::Secret,
    },
];

/// A refusal of one item field, naming the field and the rule, never the value (§4.1).
fn field_refused(field: &str, rule: FieldRule) -> Error {
    Cause::InputInvalid {
        path: PathBuf::new(),
        kind: InputKind::DeployCredentials,
        at: None,
        field: field.to_string(),
        rule,
    }
    .into()
}

/// The HTTP target signed in with one environment's deploy credentials: the parsed
/// destination and the three HTTPS header values.
pub struct HttpLogin {
    /// The configuration's `http.host`, which the item's `base_url` must agree with (§4.2).
    host: String,
    destination: Option<Destination>,
    /// `Bearer <token>`; opv adds the scheme, the item holds the bare token (§4.1).
    authorization: Option<SecretValue>,
    cf_access_client_id: Option<SecretValue>,
    cf_access_client_secret: Option<SecretValue>,
}

impl HttpLogin {
    /// A login for the target whose configuration host is `host`.
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            destination: None,
            authorization: None,
            cf_access_client_id: None,
            cf_access_client_secret: None,
        }
    }

    /// The destination parsed from the item's `base_url`, once signed in (§4.2).
    pub fn destination(&self) -> Option<&Destination> {
        self.destination.as_ref()
    }
}

impl DeployLogin for HttpLogin {
    fn sign_in(
        &mut self,
        mut values: BTreeMap<String, SecretValue>,
        _r: &dyn CommandRunner,
    ) -> Result<(), Error> {
        let take = |values: &mut BTreeMap<String, SecretValue>, label: &str| {
            values
                .remove(label)
                .ok_or_else(|| field_refused(label, FieldRule::Missing))
        };
        let base_url = take(&mut values, "base_url")?;
        let token = take(&mut values, "token")?;
        let client_id = take(&mut values, "cf_access_client_id")?;
        let client_secret = take(&mut values, "cf_access_client_secret")?;
        // The concealed values are secrets from the moment they are held (so any later
        // diagnostic masks them), and a control character in one is refused before it can
        // split a header (SR-1, T21).
        for (field, value) in [
            ("token", &token),
            ("cf_access_client_id", &client_id),
            ("cf_access_client_secret", &client_secret),
        ] {
            crate::scrub::register_secret(value.expose());
            if value.expose().chars().any(char::is_control) {
                return Err(field_refused(
                    field,
                    FieldRule::Type {
                        expected: "free of control characters",
                    },
                ));
            }
        }
        let destination = parse_base_url(base_url.expose(), &self.host)
            .map_err(|_| field_refused("base_url", FieldRule::Syntax))?;
        // Sized once: a growing String would leave an unwiped copy of the token behind.
        let mut bearer = String::with_capacity("Bearer ".len() + token.expose().len());
        bearer.push_str("Bearer ");
        bearer.push_str(token.expose());
        let authorization = SecretValue::new(bearer);
        self.destination = Some(destination);
        self.authorization = Some(authorization);
        self.cf_access_client_id = Some(client_id);
        self.cf_access_client_secret = Some(client_secret);
        Ok(())
    }

    fn env(&self, program: &str) -> Vec<(&'static str, &str)> {
        match (
            program == PROGRAM,
            &self.authorization,
            &self.cf_access_client_id,
            &self.cf_access_client_secret,
        ) {
            (true, Some(auth), Some(id), Some(secret)) => vec![
                ("Authorization", auth.expose()),
                ("CF-Access-Client-Id", id.expose()),
                ("CF-Access-Client-Secret", secret.expose()),
            ],
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
#[path = "login_tests.rs"]
mod tests;
