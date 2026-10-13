use super::*;
use crate::domain::convention::{Found, Section};

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

fn state_field(i: usize, label: &str, value: &str) -> Found {
    Found {
        id: format!("s{i}"),
        section: Some(Section {
            id: "state".into(),
            label: STATE_SECTION.into(),
        }),
        ty: "STRING".into(),
        label: label.into(),
        builtin: false,
        value: SecretValue::new(value.into()),
    }
}

/// A ledger that recorded `VALUE_A` for FLY_NAME at version `d1`.
fn layout_with_entry() -> Layout {
    let fp = hmac_hex(KEY.as_bytes(), b"VALUE_A");
    Layout {
        sections: vec![Section {
            id: "state".into(),
            label: STATE_SECTION.into(),
        }],
        fields: vec![
            state_field(0, KEY_FIELD, KEY),
            state_field(1, "FLY_NAME", &format!("v1:d1:{fp}")),
        ],
    }
}

fn v(s: &str) -> SecretValue {
    SecretValue::new(s.into())
}

#[test]
fn the_same_version_and_value_is_exactly_same() {
    let l = Ledger::from_layout(&layout_with_entry());
    assert_eq!(
        l.check("FLY_NAME", "d1", &v("VALUE_A")),
        Some(CurrentState::Same)
    );
}

#[test]
fn the_same_version_and_another_value_exactly_differs() {
    let l = Ledger::from_layout(&layout_with_entry());
    assert_eq!(
        l.check("FLY_NAME", "d1", &v("VALUE_B")),
        Some(CurrentState::Differs)
    );
}

#[test]
fn another_version_cannot_be_judged() {
    let l = Ledger::from_layout(&layout_with_entry());
    assert_eq!(l.check("FLY_NAME", "d2", &v("VALUE_A")), None);
}

#[test]
fn a_name_the_ledger_never_saw_cannot_be_judged() {
    let l = Ledger::from_layout(&layout_with_entry());
    assert_eq!(l.check("OTHER", "d1", &v("VALUE_A")), None);
}

#[test]
fn another_version_on_the_store_is_drift() {
    let l = Ledger::from_layout(&layout_with_entry());
    let listed = [StoreEntry {
        name: "FLY_NAME".into(),
        version: Some("d9".into()),
        pending: false,
        stamp: None,
    }];
    assert_eq!(l.drift(&listed), ["FLY_NAME"]);
}

#[test]
fn a_ledger_without_a_key_gets_one_when_written() {
    let l = Ledger::default();
    let value = v("VALUE_A");
    let ops = l.ops(
        &Layout::default(),
        &[("FLY_NAME".into(), "d1".into(), &value)],
        &|| KEY.to_string(),
    );
    assert!(matches!(&ops[0], Op::Add { label, concealed: true, .. } if label == KEY_FIELD));
}

#[test]
fn a_recorded_entry_is_updated_in_place() {
    let layout = layout_with_entry();
    let l = Ledger::from_layout(&layout);
    let value = v("VALUE_B");
    let ops = l.ops(
        &layout,
        &[("FLY_NAME".into(), "d2".into(), &value)],
        &|| unreachable!(),
    );
    assert!(matches!(&ops[..], [Op::SetValue { index: 1, .. }]));
}

#[test]
fn what_is_written_then_reads_back_as_same() {
    let l = Ledger::default();
    let value = v("VALUE_A");
    let ops = l.ops(
        &Layout::default(),
        &[("FLY_NAME".into(), "d1".into(), &value)],
        &|| KEY.to_string(),
    );
    let fields: Vec<Found> = ops
        .iter()
        .enumerate()
        .filter_map(|(i, op)| match op {
            Op::Add {
                label,
                value: Some(val),
                ..
            } => Some(state_field(i, label, val.expose())),
            _ => None,
        })
        .collect();
    let back = Ledger::from_layout(&Layout {
        sections: Vec::new(),
        fields,
    });
    assert_eq!(
        back.check("FLY_NAME", "d1", &value),
        Some(CurrentState::Same)
    );
}

#[test]
fn debug_never_shows_the_key_or_a_fingerprint() {
    let shown = format!("{:?}", Ledger::from_layout(&layout_with_entry()));
    assert!(!shown.contains(KEY) && !shown.contains("v1:"), "{shown}");
}
