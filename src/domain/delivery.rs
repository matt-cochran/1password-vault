//! Delivery receipts (#106): the value-free core of "this binding set was delivered and the
//! target still holds it". See `docs/design/delivery-receipts.md`.
//!
//! A [`Receipt`] holds names, ids and times only: never a value or a value-derived digest
//! (SR-1). The private per-name [`Evidence`] (store versions and keyed fingerprints) never
//! leaves the private state item and is deliberately not serializable. Pure: no target, no
//! I/O.

use std::collections::BTreeSet;
use std::fmt;

pub const SCHEMA: &str = "opv.delivery/1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Source {
    pub item_id: String,
    pub field: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct BindingRef {
    pub name: String,
    pub source: Source,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Scope {
    pub account_id: String,
    pub environment: String,
    pub product: String,
    pub provider: String,
    pub locator: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Receipt {
    pub schema: String,
    pub revision: String,
    pub scope: Scope,
    pub bindings: Vec<BindingRef>,
    pub delivered_at: String,
    pub plan_id: Option<String>,
    pub opv_version: String,
}

/// Private per-name evidence. Never serialized; Debug prints the name only.
#[derive(Clone, PartialEq, Eq)]
pub struct Evidence {
    pub name: String,
    pub store_version: String,
    pub fingerprint: String,
    pub source: Source,
}

impl fmt::Debug for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Evidence")
            .field("name", &self.name)
            .finish()
    }
}

/// `"drv-"` followed by the lowercase RFC 4648 base32 (no padding) of the 16 bytes: 26
/// characters after the prefix.
pub fn new_revision(random: [u8; 16]) -> String {
    format!("drv-{}", base32_lower(&random))
}

/// `"v1|<store_version>|<fingerprint>|<item_id>|<field>"`; `None` when any part is empty or
/// contains `'|'` or a newline.
pub fn encode_evidence(e: &Evidence) -> Option<String> {
    if !valid_part(&e.store_version)
        || !valid_part(&e.fingerprint)
        || !valid_part(&e.source.item_id)
        || !valid_part(&e.source.field)
    {
        return None;
    }
    Some(format!(
        "v1|{}|{}|{}|{}",
        e.store_version, e.fingerprint, e.source.item_id, e.source.field
    ))
}

/// The inverse for the line of `name`; `None` for anything else (another format tag, wrong
/// part count, empty part).
pub fn decode_evidence(name: &str, line: &str) -> Option<Evidence> {
    let mut parts = line.split('|');
    if parts.next()? != "v1" {
        return None;
    }
    let store_version = parts.next()?;
    let fingerprint = parts.next()?;
    let item_id = parts.next()?;
    let field = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    if store_version.is_empty() || fingerprint.is_empty() || item_id.is_empty() || field.is_empty()
    {
        return None;
    }
    Some(Evidence {
        name: name.to_string(),
        store_version: store_version.to_string(),
        fingerprint: fingerprint.to_string(),
        source: Source {
            item_id: item_id.to_string(),
            field: field.to_string(),
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NameCheck {
    pub name: String,
    pub state: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Verification {
    pub revision: Option<String>,
    pub state: &'static str,
    pub reason: Option<String>,
    pub names: Vec<NameCheck>,
}

/// What a read-only check sees now, per name.
pub struct Observed<'a> {
    pub name: &'a str,
    pub listed_version: Option<&'a str>,
    pub fingerprint_now: Option<&'a str>,
}

/// Compare a recorded receipt and its private evidence against a scope, the expected binding
/// set and what a read-only check sees now. See the module documentation and
/// `docs/design/delivery-receipts.md` for the states.
pub fn verify(
    recorded: Option<(&Receipt, &[Evidence])>,
    scope: &Scope,
    expected: &[BindingRef],
    observed: &[Observed<'_>],
) -> Verification {
    let Some((receipt, evidence)) = recorded else {
        return Verification {
            revision: None,
            state: "not_delivered",
            reason: Some("no delivery recorded".to_string()),
            names: Vec::new(),
        };
    };

    if let Some(field) = first_scope_difference(&receipt.scope, scope) {
        return Verification {
            revision: None,
            state: "not_delivered",
            reason: Some(format!("recorded for another {field}")),
            names: Vec::new(),
        };
    }

    let recorded_set: BTreeSet<&BindingRef> = receipt.bindings.iter().collect();
    let expected_set: BTreeSet<&BindingRef> = expected.iter().collect();
    if recorded_set != expected_set {
        return Verification {
            revision: None,
            state: "not_delivered",
            reason: Some("the binding set changed".to_string()),
            names: Vec::new(),
        };
    }

    let names: Vec<NameCheck> = expected
        .iter()
        .map(|binding| NameCheck {
            name: binding.name.clone(),
            state: name_state(&binding.name, evidence, observed),
        })
        .collect();

    let changed = names.iter().any(|n| {
        matches!(
            n.state,
            "missing_on_target" | "drifted_on_target" | "source_changed"
        )
    });
    let all_verified = !names.is_empty() && names.iter().all(|n| n.state == "verified");
    let state = if all_verified {
        "verified"
    } else if changed {
        "changed"
    } else {
        "unverifiable"
    };
    let not_verified = names.iter().filter(|n| n.state != "verified").count();
    let reason = if state == "verified" {
        None
    } else {
        Some(format!(
            "{not_verified} of {} names not verified",
            names.len()
        ))
    };

    Verification {
        revision: Some(receipt.revision.clone()),
        state,
        reason,
        names,
    }
}

fn name_state(name: &str, evidence: &[Evidence], observed: &[Observed<'_>]) -> &'static str {
    let Some(ev) = evidence.iter().find(|e| e.name == name) else {
        return "unverifiable";
    };
    let Some(obs) = observed.iter().find(|o| o.name == name) else {
        return "missing_on_target";
    };
    let Some(listed) = obs.listed_version else {
        return "missing_on_target";
    };
    if listed != ev.store_version {
        return "drifted_on_target";
    }
    let Some(fingerprint) = obs.fingerprint_now else {
        return "unverifiable";
    };
    if fingerprint != ev.fingerprint {
        return "source_changed";
    }
    "verified"
}

fn first_scope_difference(recorded: &Scope, current: &Scope) -> Option<&'static str> {
    if recorded.account_id != current.account_id {
        Some("account_id")
    } else if recorded.environment != current.environment {
        Some("environment")
    } else if recorded.product != current.product {
        Some("product")
    } else if recorded.provider != current.provider {
        Some("provider")
    } else if recorded.locator != current.locator {
        Some("locator")
    } else {
        None
    }
}

fn valid_part(s: &str) -> bool {
    !s.is_empty() && !s.contains('|') && !s.contains('\n')
}

fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(
            ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
    }
    out
}

#[cfg(test)]
#[path = "delivery_tests.rs"]
mod tests;
