use super::*;
use crate::domain::delivery::{Evidence, Source};

/// RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
#[test]
fn hmac_matches_rfc_4231_case_2() {
    assert_eq!(
        hmac_hex(b"Jefe", b"what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

/// RFC 4231 test case 6: a key longer than the block size is hashed first.
#[test]
fn hmac_matches_rfc_4231_case_6() {
    assert_eq!(
        hmac_hex(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        ),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

const KEY: &str = "a2V5LWZvci10ZXN0cy1vbmx5LW5vdC1yYW5kb20tMDAw";

fn v(s: &str) -> SecretValue {
    SecretValue::new(s.into())
}

// ---- Ledger from delivery evidence (FR-54, FR-58, D11) ---------------------------

fn evidence(name: &str, store_version: &str, fingerprint: &str) -> Evidence {
    Evidence {
        name: name.into(),
        store_version: store_version.into(),
        fingerprint: fingerprint.into(),
        source: Source {
            item_id: "item".into(),
            field: "field".into(),
        },
    }
}

fn listed(name: &str, version: &str) -> StoreEntry {
    StoreEntry {
        name: name.into(),
        version: Some(version.into()),
        pending: false,
        stamp: None,
    }
}

#[test]
fn evidence_at_the_recorded_version_and_value_is_same() {
    let line = evidence("FLY_NAME", "d1", &hmac_hex(KEY.as_bytes(), b"VALUE_A"));
    let l = Ledger::from_evidence(Some(v(KEY)), &[line]);
    assert_eq!(
        l.check("FLY_NAME", "d1", &v("VALUE_A")),
        Some(CurrentState::Same)
    );
}

#[test]
fn evidence_at_the_recorded_version_with_another_value_differs() {
    let line = evidence("FLY_NAME", "d1", &hmac_hex(KEY.as_bytes(), b"VALUE_A"));
    let l = Ledger::from_evidence(Some(v(KEY)), &[line]);
    assert_eq!(
        l.check("FLY_NAME", "d1", &v("VALUE_B")),
        Some(CurrentState::Differs)
    );
}

#[test]
fn evidence_at_another_version_cannot_be_judged() {
    let line = evidence("FLY_NAME", "d1", &hmac_hex(KEY.as_bytes(), b"VALUE_A"));
    let l = Ledger::from_evidence(Some(v(KEY)), &[line]);
    assert_eq!(l.check("FLY_NAME", "d2", &v("VALUE_A")), None);
}

#[test]
fn evidence_without_a_key_cannot_be_judged() {
    let line = evidence("FLY_NAME", "d1", &hmac_hex(KEY.as_bytes(), b"VALUE_A"));
    let l = Ledger::from_evidence(None, &[line]);
    assert_eq!(l.check("FLY_NAME", "d1", &v("VALUE_A")), None);
}

#[test]
fn drift_lists_only_names_at_another_version() {
    let lines = [
        evidence("FLY_NAME", "d1", &hmac_hex(KEY.as_bytes(), b"VALUE_A")),
        evidence("STILL", "d5", &hmac_hex(KEY.as_bytes(), b"VALUE_B")),
    ];
    let l = Ledger::from_evidence(Some(v(KEY)), &lines);
    assert_eq!(
        l.drift(&[listed("FLY_NAME", "d9"), listed("STILL", "d5")]),
        ["FLY_NAME"]
    );
}

#[test]
fn versions_maps_each_evidence_name_to_its_store_version() {
    let lines = [
        evidence("FLY_NAME", "d1", &hmac_hex(KEY.as_bytes(), b"VALUE_A")),
        evidence("OTHER", "d2", &hmac_hex(KEY.as_bytes(), b"VALUE_B")),
    ];
    let l = Ledger::from_evidence(Some(v(KEY)), &lines);
    assert_eq!(
        l.versions(),
        BTreeMap::from([
            ("FLY_NAME".to_string(), "d1".to_string()),
            ("OTHER".to_string(), "d2".to_string()),
        ])
    );
}

#[test]
fn an_evidence_line_without_a_store_version_is_not_an_entry() {
    let line = evidence("FLY_NAME", "", &hmac_hex(KEY.as_bytes(), b"VALUE_A"));
    let l = Ledger::from_evidence(Some(v(KEY)), &[line]);
    assert!(l.versions().is_empty());
}

#[test]
fn an_evidence_line_without_a_fingerprint_is_not_an_entry() {
    let line = evidence("FLY_NAME", "d1", "");
    let l = Ledger::from_evidence(Some(v(KEY)), &[line]);
    assert!(l.versions().is_empty());
}

#[test]
fn a_name_without_evidence_cannot_be_judged() {
    let line = evidence("FLY_NAME", "d1", &hmac_hex(KEY.as_bytes(), b"VALUE_A"));
    let l = Ledger::from_evidence(Some(v(KEY)), &[line]);
    assert_eq!(l.check("OTHER", "d1", &v("VALUE_A")), None);
}

#[test]
fn debug_never_shows_the_key_or_a_fingerprint() {
    let fp = hmac_hex(KEY.as_bytes(), b"VALUE_A");
    let shown = format!(
        "{:?}",
        Ledger::from_evidence(Some(v(KEY)), &[evidence("FLY_NAME", "d1", &fp)])
    );
    assert!(!shown.contains(KEY) && !shown.contains(&fp), "{shown}");
}
