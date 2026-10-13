//! The version ledger (FR-54, #36): exact change detection in `plan` for a store that
//! cannot show its values (Fly digests, GitHub `updatedAt`), without staging or reading one.
//!
//! The comparison happens when it is allowed: right after `sync` writes a value, it knows
//! both the value and the version the store gave it. It records, per name, that version and
//! a keyed fingerprint of the value (HMAC-SHA256 with a random key) in the environment's own
//! item, section [`STATE_SECTION`]. Later, `plan` lists the store (read-only) and fingerprints
//! the current 1Password value: the same version with the same fingerprint is exactly
//! unchanged, the same version with another fingerprint exactly changed, another version
//! changed outside opv (drift). The key lives in the same item, so whoever can read a
//! fingerprint can already read the value: nothing new is exposed, and a ledger read on its
//! own cannot be used to test guesses.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest, Sha256};

use crate::domain::convention::{Layout, Op};
use crate::domain::plan::{CurrentState, StoreEntry};
use crate::domain::secret::SecretValue;

/// The item section that holds the ledger. Reserved: never a product, never tidied.
pub const STATE_SECTION: &str = "opv · state";
/// The field holding the ledger's key (concealed, 32 random bytes, base64).
pub const KEY_FIELD: &str = "ledger key";
/// The format tag of an entry's value: `v1:<version>:<fingerprint>`.
const FORMAT: &str = "v1";

/// The ledger read from an item. `Debug` prints names only.
#[derive(Default)]
pub struct Ledger {
    key: Option<SecretValue>,
    /// name → (store version, fingerprint hex).
    entries: BTreeMap<String, (String, String)>,
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
    /// The ledger in `layout`'s [`STATE_SECTION`]; empty when there is none.
    pub fn from_layout(layout: &Layout) -> Ledger {
        let mut ledger = Ledger::default();
        for f in layout
            .fields
            .iter()
            .filter(|f| f.section_label() == Some(STATE_SECTION))
        {
            if f.label == KEY_FIELD {
                if !f.value.expose().is_empty() {
                    ledger.key = Some(SecretValue::new(f.value.expose().to_string()));
                }
                continue;
            }
            let mut parts = f.value.expose().splitn(3, ':');
            if let (Some(FORMAT), Some(version), Some(fp)) =
                (parts.next(), parts.next(), parts.next())
            {
                ledger
                    .entries
                    .insert(f.label.clone(), (version.to_string(), fp.to_string()));
            }
        }
        ledger
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

    /// The item edits that record `written` (name, the store's version after the write, the
    /// value written): a key is created when the ledger has none (`new_key` supplies 32
    /// random bytes as base64), each entry added or updated. Fields are found by label in
    /// `layout`'s [`STATE_SECTION`].
    pub fn ops(
        &self,
        layout: &Layout,
        written: &[(String, String, &SecretValue)],
        new_key: &dyn Fn() -> String,
    ) -> Vec<Op> {
        let mut ops = Vec::new();
        // Zeroized on drop: the HMAC key is as secret as the values it fingerprints.
        let key = match &self.key {
            Some(k) => zeroize::Zeroizing::new(k.expose().to_string()),
            None => {
                let k = zeroize::Zeroizing::new(new_key());
                ops.push(set_or_add(layout, KEY_FIELD, true, &k));
                k
            }
        };
        for (name, version, value) in written {
            let fp = hmac_hex(key.as_bytes(), value.expose().as_bytes());
            ops.push(set_or_add(
                layout,
                name,
                false,
                &format!("{FORMAT}:{version}:{fp}"),
            ));
        }
        ops
    }
}

/// `SetValue` on the [`STATE_SECTION`] field labelled `label`, or `Add` it.
fn set_or_add(layout: &Layout, label: &str, concealed: bool, value: &str) -> Op {
    match layout
        .fields
        .iter()
        .position(|f| f.section_label() == Some(STATE_SECTION) && f.label == label)
    {
        Some(index) => Op::SetValue {
            index,
            value: SecretValue::new(value.to_string()),
        },
        None => Op::Add {
            section: Some(STATE_SECTION.to_string()),
            label: label.to_string(),
            concealed,
            value: Some(SecretValue::new(value.to_string())),
        },
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
