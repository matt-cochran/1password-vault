//! The version ledger (FR-54, FR-58, #36): exact change detection in `plan` for a store
//! that cannot show its values (Fly digests, GitHub `updatedAt`), without staging or reading
//! one.
//!
//! The ledger is a placement's delivery evidence (D11): after each confirmed write the
//! deliverer records, in the placement's state item, that name's store version and a keyed
//! fingerprint of the value (HMAC-SHA256 under the item's evidence key).
//! [`Ledger::from_evidence`] turns those lines into a ledger. Later, `plan` lists the store
//! (read-only) and fingerprints the current 1Password value: the same version with the same
//! fingerprint is exactly unchanged, the same version with another fingerprint exactly
//! changed, another version changed outside opv (drift). One store per placement, never a
//! second copy in the values item.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::domain::plan::{CurrentState, StoreEntry};
use crate::domain::secret::SecretValue;

/// One placement's ledger. `Debug` prints names only.
#[derive(Default)]
pub struct Ledger {
    key: Option<SecretValue>,
    /// name → (store version, fingerprint hex).
    entries: BTreeMap<String, (String, String)>,
    /// Names whose line is a person's attestation (#201), not opv's own evidence.
    attested: std::collections::BTreeSet<String>,
}

impl fmt::Debug for Ledger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ledger")
            .field("key", &self.key.as_ref().map(|_| "<REDACTED>"))
            .field("names", &self.entries.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// HMAC-SHA256 of `message` under `key` (RFC 2104), as lower-case hex.
pub fn hmac_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    let out = hex::encode(outer.finalize());
    k.fill(0);
    out
}

impl Ledger {
    /// The ledger of one placement: each evidence line's store version and fingerprint,
    /// under the placement's evidence key (FR-54, FR-58, D11). A line with an empty store
    /// version or fingerprint is not an entry.
    pub fn from_evidence(
        key: Option<SecretValue>,
        evidence: &[crate::domain::delivery::Evidence],
    ) -> Ledger {
        Ledger {
            key,
            entries: evidence
                .iter()
                .filter(|e| !e.store_version.is_empty() && !e.fingerprint.is_empty())
                .map(|e| {
                    (
                        e.name.clone(),
                        (e.store_version.clone(), e.fingerprint.clone()),
                    )
                })
                .collect(),
            attested: evidence
                .iter()
                .filter(|e| e.attested())
                .map(|e| e.name.clone())
                .collect(),
        }
    }

    /// Whether `name`'s line is a person's attestation at the store's version `version_now`
    /// (#201): the ledger then judges it identical, but attested, not proven.
    pub fn attested(&self, name: &str, version_now: &str) -> bool {
        self.attested.contains(name)
            && self
                .entries
                .get(name)
                .is_some_and(|(v, _)| v == version_now)
    }

    /// Each recorded name with the store version opv's own sync left it at (#95). Never a
    /// fingerprint or the key: history shows names and versions only.
    pub fn versions(&self) -> BTreeMap<String, String> {
        self.entries
            .iter()
            .map(|(name, (version, _))| (name.clone(), version.clone()))
            .collect()
    }

    fn fingerprint(&self, value: &SecretValue) -> Option<String> {
        self.key
            .as_ref()
            .map(|k| hmac_hex(k.expose().as_bytes(), value.expose().as_bytes()))
    }

    /// How the store's current value of `name` compares with `desired`, when the ledger can
    /// tell: the store still holds the version opv wrote (`version_now`). `None` otherwise.
    pub fn check(
        &self,
        name: &str,
        version_now: &str,
        desired: &SecretValue,
    ) -> Option<CurrentState> {
        let (version, fp) = self.entries.get(name)?;
        if version != version_now {
            return None;
        }
        let now = self.fingerprint(desired)?;
        use subtle::ConstantTimeEq as _;
        Some(if bool::from(now.as_bytes().ct_eq(fp.as_bytes())) {
            CurrentState::Same
        } else {
            CurrentState::Differs
        })
    }

    /// Names the store lists with another version than the one opv recorded: changed
    /// outside opv since its last sync (drift).
    pub fn drift(&self, listed: &[StoreEntry]) -> Vec<String> {
        listed
            .iter()
            .filter_map(|e| {
                let (version, _) = self.entries.get(&e.name)?;
                (e.version.as_deref().is_some_and(|v| v != version)).then(|| e.name.clone())
            })
            .collect()
    }
}

/// A new ledger key: 32 random bytes, base64.
pub fn random_key() -> String {
    use base64::Engine as _;
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the OS random source");
    let k = base64::engine::general_purpose::STANDARD.encode(bytes);
    bytes.fill(0);
    k
}

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod tests;
