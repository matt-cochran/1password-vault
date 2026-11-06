//! The sealed target's deploy credential (design `sealed-target` §6.2, D3, D13, T2, T16): a
//! 1Password SSH Key item whose `private key` signs the bundle in process.
//!
//! The item is read once at sign-in, as for every target. The key is parsed (OpenSSH form
//! preferred, PKCS#8 otherwise: the reader takes `ssh_formats.openssh.value` when the item
//! has it) and its public half must equal `sealed.signer` **before any value of the
//! environment is read**: a mismatch is `InputInvalid { DeployCredentials, "public key" }`
//! (exit 2), never `CredentialRejected` (a local comparison has no failed call to observe,
//! J7). From then on the key stays in this login as a zeroizing [`SecretValue`] and reaches
//! only the runner's seal effect ([`crate::runner::seal`]), through `EnvRunner`'s
//! per-program environment: never argv, a file, an error or a log (SR-3, SR-8).

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::bundle::crypto::parse_signing_key;
use crate::cause::{Cause, FieldRule, InputKind};
use crate::domain::{Kind, SecretValue};
use crate::error::Error;
use crate::provider::{CredentialField, DeployLogin};
use crate::runner::CommandRunner;
use crate::runner::seal::{KEY, PROGRAM};

/// The SSH Key item's field opv reads (D3, D13). 1Password types it `SSHKEY`; the reader
/// takes it as a concealed value.
pub const FIELDS: &[CredentialField] = &[CredentialField {
    label: "private key",
    kind: Kind::Secret,
}];

/// A refusal of one item field, naming the field and the rule, never the value.
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

/// The sealed target signed in with its SSH Key deploy credential.
pub struct SealedLogin {
    /// `SHA256:…` of the configuration's `sealed.signer` (T2).
    signer: String,
    /// The private key as the item holds it; parsed again only inside the seal effect.
    key: Option<SecretValue>,
}

impl SealedLogin {
    /// A login whose key must be the one `sealed.signer` names (`signer`, its fingerprint).
    pub fn new(signer: impl Into<String>) -> Self {
        Self {
            signer: signer.into(),
            key: None,
        }
    }
}

impl DeployLogin for SealedLogin {
    fn sign_in(
        &mut self,
        mut values: BTreeMap<String, SecretValue>,
        _r: &dyn CommandRunner,
    ) -> Result<(), Error> {
        let label = FIELDS[0].label;
        let pem = values
            .remove(label)
            .ok_or_else(|| field_refused(label, FieldRule::Missing))?;
        let key = parse_signing_key(pem.expose()).map_err(|_| {
            field_refused(
                label,
                FieldRule::Type {
                    expected: "an unencrypted ed25519 private key (OpenSSH or PKCS#8)",
                },
            )
        })?;
        // T2: the key must be the configured signer before anything else is read.
        if key.fingerprint() != self.signer {
            return Err(field_refused(
                "public key",
                FieldRule::Type {
                    expected: "the public key that sealed.signer names",
                },
            ));
        }
        self.key = Some(pem);
        Ok(())
    }

    fn env(&self, program: &str) -> Vec<(&'static str, &str)> {
        match (&self.key, program == PROGRAM) {
            (Some(key), true) => vec![(KEY, key.expose())],
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
#[path = "login_tests.rs"]
mod tests;
