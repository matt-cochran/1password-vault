//! A fresh Ed25519 OpenSSH keypair for keys whose rules say `ssh_ed25519 = true` (#294).
//!
//! The private key is stored exactly as `ssh-keygen` writes it (multiline OpenSSH PEM, one
//! trailing newline); the public key and its `SHA256:…` fingerprint are derived from it and
//! are the only key material opv prints, like the `age1…` recipient of an `age_identity`
//! key (design `docs/design/ssh-signing-key.md`).

use crate::cause::Cause;
use crate::domain::SecretValue;
use crate::error::Error;

/// The public half of a generated Ed25519 key: the `ssh-ed25519 AAAA…` line and its
/// OpenSSH `SHA256:…` fingerprint. Public data only, so `Debug` is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshPublic {
    /// The `ssh-ed25519 AAAA…` public key, as `ssh-keygen` writes it.
    pub openssh: String,
    /// The `SHA256:…` fingerprint of that key.
    pub fingerprint: String,
}

/// A fresh, always-valid key that fails to encode or re-parse is an internal invariant
/// violation, never a value-dependent refusal.
fn encode_failed() -> Error {
    Cause::Bug {
        site: "generate_ssh",
    }
    .into()
}

/// A fresh Ed25519 OpenSSH private key, as `ssh-keygen` writes it, and its public half.
///
/// The 32-byte seed comes from the operating system's CSPRNG into a zeroizing buffer; a
/// random-source failure is the existing [`super::random_source_failed`]. The encoded
/// `Zeroizing<String>` moves into [`SecretValue`], so the key is owned and zeroized there.
pub fn make_ed25519() -> Result<(SecretValue, SshPublic), Error> {
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut seed[..]).map_err(|_| super::random_source_failed())?;
    let keypair = ssh_key::private::Ed25519Keypair::from_seed(&seed);
    let private = ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ed25519(keypair), "")
        .map_err(|_| encode_failed())?;
    let public = private.public_key();
    let ssh_public = SshPublic {
        openssh: public.to_openssh().map_err(|_| encode_failed())?,
        fingerprint: public.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
    };
    let mut openssh = private
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|_| encode_failed())?;
    Ok((SecretValue::new(std::mem::take(&mut *openssh)), ssh_public))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{Algorithm, HashAlg, PrivateKey};

    #[test]
    fn stored_private_key_parses_back_as_ed25519() {
        let (value, _public) = make_ed25519().unwrap();
        let parsed = PrivateKey::from_openssh(value.expose()).unwrap();
        assert_eq!(parsed.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn stored_private_key_is_unencrypted() {
        let (value, _public) = make_ed25519().unwrap();
        let parsed = PrivateKey::from_openssh(value.expose()).unwrap();
        assert!(!parsed.is_encrypted());
    }

    #[test]
    fn stored_private_key_ends_with_exactly_one_trailing_newline() {
        let (value, _public) = make_ed25519().unwrap();
        let trailing = value.expose().len() - value.expose().trim_end_matches('\n').len();
        assert_eq!(trailing, 1);
    }

    #[test]
    fn stored_private_key_public_half_equals_reported_public_key() {
        let (value, public) = make_ed25519().unwrap();
        let parsed = PrivateKey::from_openssh(value.expose()).unwrap();
        assert_eq!(parsed.public_key().to_openssh().unwrap(), public.openssh);
    }

    #[test]
    fn reported_fingerprint_is_sha256_of_reported_public_key() {
        let (_value, public) = make_ed25519().unwrap();
        let parsed = ssh_key::PublicKey::from_openssh(&public.openssh).unwrap();
        assert_eq!(
            parsed.fingerprint(HashAlg::Sha256).to_string(),
            public.fingerprint
        );
    }

    #[test]
    fn two_generations_give_different_keys() {
        let (_first, a) = make_ed25519().unwrap();
        let (_second, b) = make_ed25519().unwrap();
        assert_ne!(a.openssh, b.openssh);
    }
}
