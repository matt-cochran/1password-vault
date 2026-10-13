//! Behaviour tests for the value-free delivery receipts core (#106). Pure.

use super::*;

const NAME: &str = "FLEET__API__TOKEN";
const OTHER: &str = "FLEET__API__DB_URL";
const REVISION: &str = "drv-aaaqeayeaudaocajbifqydiob4";
const VERSION: &str = "d1";
const OTHER_VERSION: &str = "d2";
const FP: &str = "fp-1";
const OTHER_FP: &str = "fp-2";

fn source() -> Source {
    Source {
        item_id: "item-1".into(),
        field: "api/TOKEN".into(),
    }
}

fn binding(name: &str) -> BindingRef {
    BindingRef {
        name: name.into(),
        source: source(),
    }
}

fn scope() -> Scope {
    Scope {
        account_id: "acct-1".into(),
        environment: "prod".into(),
        product: "api".into(),
        provider: "fly".into(),
        locator: "myapp".into(),
    }
}

fn receipt() -> Receipt {
    Receipt {
        schema: SCHEMA.into(),
        revision: REVISION.into(),
        scope: scope(),
        bindings: vec![binding(NAME)],
        delivered_at: "2026-10-13T12:00:00Z".into(),
        plan_id: Some("7f3c9a1e".into()),
        opv_version: "0.7.0".into(),
    }
}

fn evidence(name: &str) -> Evidence {
    Evidence {
        name: name.into(),
        store_version: VERSION.into(),
        fingerprint: FP.into(),
        source: source(),
    }
}

fn observed<'a>(
    name: &'a str,
    listed_version: Option<&'a str>,
    fingerprint_now: Option<&'a str>,
) -> Observed<'a> {
    Observed {
        name,
        listed_version,
        fingerprint_now,
    }
}

// ---- schema ----------------------------------------------------------------------

#[test]
fn schema_names_the_delivery_document() {
    assert_eq!(SCHEMA, "opv.delivery/1");
}

// ---- new_revision ----------------------------------------------------------------

#[test]
fn new_revision_starts_with_the_drv_prefix() {
    assert!(new_revision([0u8; 16]).starts_with("drv-"));
}

#[test]
fn new_revision_is_thirty_characters() {
    assert_eq!(new_revision([0u8; 16]).len(), 30);
}

#[test]
fn new_revision_uses_only_lowercase_base32_letters() {
    let input: [u8; 16] = std::array::from_fn(|i| i as u8);
    assert!(
        new_revision(input)[4..]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    );
}

#[test]
fn new_revision_encodes_sixteen_bytes_as_base32() {
    let input: [u8; 16] = std::array::from_fn(|i| i as u8);
    assert_eq!(new_revision(input), "drv-aaaqeayeaudaocajbifqydiob4");
}

#[test]
fn new_revision_is_deterministic() {
    assert_eq!(new_revision([7u8; 16]), new_revision([7u8; 16]));
}

// ---- encode / decode evidence ----------------------------------------------------

#[test]
fn evidence_round_trips_through_encode_and_decode() {
    let e = evidence(NAME);
    assert_eq!(
        decode_evidence(&e.name, &encode_evidence(&e).unwrap()),
        Some(e)
    );
}

#[test]
fn encode_writes_the_v1_line() {
    assert_eq!(
        encode_evidence(&evidence(NAME)),
        Some("v1|d1|fp-1|item-1|api/TOKEN".to_string())
    );
}

#[test]
fn encode_rejects_an_empty_store_version() {
    let mut e = evidence(NAME);
    e.store_version = String::new();
    assert_eq!(encode_evidence(&e), None);
}

#[test]
fn encode_rejects_an_empty_fingerprint() {
    let mut e = evidence(NAME);
    e.fingerprint = String::new();
    assert_eq!(encode_evidence(&e), None);
}

#[test]
fn encode_rejects_an_empty_item_id() {
    let mut e = evidence(NAME);
    e.source.item_id = String::new();
    assert_eq!(encode_evidence(&e), None);
}

#[test]
fn encode_rejects_an_empty_field() {
    let mut e = evidence(NAME);
    e.source.field = String::new();
    assert_eq!(encode_evidence(&e), None);
}

#[test]
fn encode_rejects_a_pipe_in_a_part() {
    let mut e = evidence(NAME);
    e.store_version = "d|1".into();
    assert_eq!(encode_evidence(&e), None);
}

#[test]
fn encode_rejects_a_newline_in_a_part() {
    let mut e = evidence(NAME);
    e.fingerprint = "fp\n1".into();
    assert_eq!(encode_evidence(&e), None);
}

#[test]
fn decode_rejects_another_format_tag() {
    assert_eq!(decode_evidence(NAME, "v2|d1|fp-1|item-1|api/TOKEN"), None);
}

#[test]
fn decode_rejects_too_few_parts() {
    assert_eq!(decode_evidence(NAME, "v1|d1|fp-1|item-1"), None);
}

#[test]
fn decode_rejects_too_many_parts() {
    assert_eq!(
        decode_evidence(NAME, "v1|d1|fp-1|item-1|api/TOKEN|extra"),
        None
    );
}

#[test]
fn decode_rejects_an_empty_part() {
    assert_eq!(decode_evidence(NAME, "v1||fp-1|item-1|api/TOKEN"), None);
}

#[test]
fn decode_keeps_the_name_it_is_given() {
    assert_eq!(
        decode_evidence("other", "v1|d1|fp-1|item-1|api/TOKEN").map(|e| e.name),
        Some("other".to_string())
    );
}

// ---- verify: rule 1, nothing recorded --------------------------------------------

#[test]
fn verify_reports_not_delivered_when_nothing_recorded() {
    let v = verify(None, &scope(), &[binding(NAME)], &[]);
    assert_eq!(v.state, "not_delivered");
}

#[test]
fn verify_reports_no_revision_when_nothing_recorded() {
    let v = verify(None, &scope(), &[], &[]);
    assert_eq!(v.revision, None);
}

#[test]
fn verify_explains_when_nothing_recorded() {
    let v = verify(None, &scope(), &[], &[]);
    assert_eq!(v.reason.as_deref(), Some("no delivery recorded"));
}

#[test]
fn verify_has_no_names_when_nothing_recorded() {
    let v = verify(None, &scope(), &[binding(NAME)], &[]);
    assert!(v.names.is_empty());
}

// ---- verify: rule 2, scope mismatch ----------------------------------------------

#[test]
fn verify_reports_another_scope_as_not_delivered() {
    let r = receipt();
    let e = [evidence(NAME)];
    let mut s = scope();
    s.product = "web".into();
    let v = verify(Some((&r, &e)), &s, &[binding(NAME)], &[]);
    assert_eq!(v.state, "not_delivered");
}

#[test]
fn verify_reports_no_revision_for_another_scope() {
    let r = receipt();
    let e = [evidence(NAME)];
    let mut s = scope();
    s.product = "web".into();
    let v = verify(Some((&r, &e)), &s, &[binding(NAME)], &[]);
    assert_eq!(v.revision, None);
}

#[test]
fn verify_has_no_names_for_another_scope() {
    let r = receipt();
    let e = [evidence(NAME)];
    let mut s = scope();
    s.product = "web".into();
    let v = verify(Some((&r, &e)), &s, &[binding(NAME)], &[]);
    assert!(v.names.is_empty());
}

#[test]
fn verify_names_a_different_product_in_the_reason() {
    let r = receipt();
    let e = [evidence(NAME)];
    let mut s = scope();
    s.product = "web".into();
    let v = verify(Some((&r, &e)), &s, &[binding(NAME)], &[]);
    assert_eq!(v.reason.as_deref(), Some("recorded for another product"));
}

#[test]
fn verify_names_a_different_account_in_the_reason() {
    let r = receipt();
    let e = [evidence(NAME)];
    let mut s = scope();
    s.account_id = "acct-2".into();
    let v = verify(Some((&r, &e)), &s, &[binding(NAME)], &[]);
    assert_eq!(v.reason.as_deref(), Some("recorded for another account_id"));
}

#[test]
fn verify_names_a_different_environment_in_the_reason() {
    let r = receipt();
    let e = [evidence(NAME)];
    let mut s = scope();
    s.environment = "staging".into();
    let v = verify(Some((&r, &e)), &s, &[binding(NAME)], &[]);
    assert_eq!(
        v.reason.as_deref(),
        Some("recorded for another environment")
    );
}

#[test]
fn verify_names_a_different_provider_in_the_reason() {
    let r = receipt();
    let e = [evidence(NAME)];
    let mut s = scope();
    s.provider = "azure".into();
    let v = verify(Some((&r, &e)), &s, &[binding(NAME)], &[]);
    assert_eq!(v.reason.as_deref(), Some("recorded for another provider"));
}

#[test]
fn verify_names_a_different_locator_in_the_reason() {
    let r = receipt();
    let e = [evidence(NAME)];
    let mut s = scope();
    s.locator = "otherapp".into();
    let v = verify(Some((&r, &e)), &s, &[binding(NAME)], &[]);
    assert_eq!(v.reason.as_deref(), Some("recorded for another locator"));
}

#[test]
fn verify_names_the_first_differing_scope_field() {
    let r = receipt();
    let e = [evidence(NAME)];
    let mut s = scope();
    s.account_id = "acct-2".into();
    s.product = "web".into();
    let v = verify(Some((&r, &e)), &s, &[binding(NAME)], &[]);
    assert_eq!(v.reason.as_deref(), Some("recorded for another account_id"));
}

// ---- verify: rule 3, binding set changed -----------------------------------------

#[test]
fn verify_reports_a_changed_binding_set_as_not_delivered() {
    let r = receipt();
    let e = [evidence(NAME)];
    let obs = [observed(OTHER, Some(VERSION), Some(FP))];
    let v = verify(Some((&r, &e)), &scope(), &[binding(OTHER)], &obs);
    assert_eq!(v.state, "not_delivered");
}

#[test]
fn verify_reports_the_reason_for_a_changed_binding_set() {
    let r = receipt();
    let e = [evidence(NAME)];
    let v = verify(Some((&r, &e)), &scope(), &[binding(OTHER)], &[]);
    assert_eq!(v.reason.as_deref(), Some("the binding set changed"));
}

#[test]
fn verify_reports_no_revision_for_a_changed_binding_set() {
    let r = receipt();
    let e = [evidence(NAME)];
    let v = verify(Some((&r, &e)), &scope(), &[binding(OTHER)], &[]);
    assert_eq!(v.revision, None);
}

#[test]
fn verify_has_no_names_for_a_changed_binding_set() {
    let r = receipt();
    let e = [evidence(NAME)];
    let v = verify(Some((&r, &e)), &scope(), &[binding(OTHER)], &[]);
    assert!(v.names.is_empty());
}

#[test]
fn verify_treats_binding_order_as_irrelevant() {
    let mut r = receipt();
    r.bindings = vec![binding(NAME), binding(OTHER)];
    let e = [evidence(NAME), evidence(OTHER)];
    let obs = [
        observed(NAME, Some(VERSION), Some(FP)),
        observed(OTHER, Some(VERSION), Some(FP)),
    ];
    let expected = [binding(OTHER), binding(NAME)];
    let v = verify(Some((&r, &e)), &scope(), &expected, &obs);
    assert_eq!(v.state, "verified");
}

// ---- verify: rule 4, revision and name states ------------------------------------

#[test]
fn verify_returns_the_recorded_revision_when_scope_and_bindings_match() {
    let r = receipt();
    let e = [evidence(NAME)];
    let obs = [observed(NAME, Some(VERSION), Some(FP))];
    let v = verify(Some((&r, &e)), &scope(), &[binding(NAME)], &obs);
    assert_eq!(v.revision.as_deref(), Some(REVISION));
}

#[test]
fn verify_marks_a_matching_name_verified() {
    let r = receipt();
    let e = [evidence(NAME)];
    let obs = [observed(NAME, Some(VERSION), Some(FP))];
    let v = verify(Some((&r, &e)), &scope(), &[binding(NAME)], &obs);
    assert_eq!(v.names[0].state, "verified");
}

#[test]
fn verify_marks_a_name_without_evidence_unverifiable() {
    let r = receipt();
    let obs = [observed(NAME, Some(VERSION), Some(FP))];
    let v = verify(Some((&r, &[])), &scope(), &[binding(NAME)], &obs);
    assert_eq!(v.names[0].state, "unverifiable");
}

#[test]
fn verify_prefers_missing_evidence_over_a_missing_target() {
    let r = receipt();
    let v = verify(Some((&r, &[])), &scope(), &[binding(NAME)], &[]);
    assert_eq!(v.names[0].state, "unverifiable");
}

#[test]
fn verify_marks_a_name_missing_from_the_target() {
    let r = receipt();
    let e = [evidence(NAME)];
    let v = verify(Some((&r, &e)), &scope(), &[binding(NAME)], &[]);
    assert_eq!(v.names[0].state, "missing_on_target");
}

#[test]
fn verify_marks_a_name_without_a_listed_version_missing_on_target() {
    let r = receipt();
    let e = [evidence(NAME)];
    let obs = [observed(NAME, None, Some(FP))];
    let v = verify(Some((&r, &e)), &scope(), &[binding(NAME)], &obs);
    assert_eq!(v.names[0].state, "missing_on_target");
}

#[test]
fn verify_marks_a_different_listed_version_drifted_on_target() {
    let r = receipt();
    let e = [evidence(NAME)];
    let obs = [observed(NAME, Some(OTHER_VERSION), Some(FP))];
    let v = verify(Some((&r, &e)), &scope(), &[binding(NAME)], &obs);
    assert_eq!(v.names[0].state, "drifted_on_target");
}

#[test]
fn verify_marks_an_unlisted_fingerprint_unverifiable() {
    let r = receipt();
    let e = [evidence(NAME)];
    let obs = [observed(NAME, Some(VERSION), None)];
    let v = verify(Some((&r, &e)), &scope(), &[binding(NAME)], &obs);
    assert_eq!(v.names[0].state, "unverifiable");
}

#[test]
fn verify_marks_a_changed_fingerprint_source_changed() {
    let r = receipt();
    let e = [evidence(NAME)];
    let obs = [observed(NAME, Some(VERSION), Some(OTHER_FP))];
    let v = verify(Some((&r, &e)), &scope(), &[binding(NAME)], &obs);
    assert_eq!(v.names[0].state, "source_changed");
}

#[test]
fn verify_prefers_drift_over_source_change() {
    let r = receipt();
    let e = [evidence(NAME)];
    let obs = [observed(NAME, Some(OTHER_VERSION), Some(OTHER_FP))];
    let v = verify(Some((&r, &e)), &scope(), &[binding(NAME)], &obs);
    assert_eq!(v.names[0].state, "drifted_on_target");
}

// ---- verify: overall state -------------------------------------------------------

#[test]
fn verify_overall_state_is_verified_when_every_name_verifies() {
    let r = receipt();
    let e = [evidence(NAME)];
    let obs = [observed(NAME, Some(VERSION), Some(FP))];
    let v = verify(Some((&r, &e)), &scope(), &[binding(NAME)], &obs);
    assert_eq!(v.state, "verified");
}

#[test]
fn verify_reason_is_absent_when_verified() {
    let r = receipt();
    let e = [evidence(NAME)];
    let obs = [observed(NAME, Some(VERSION), Some(FP))];
    let v = verify(Some((&r, &e)), &scope(), &[binding(NAME)], &obs);
    assert_eq!(v.reason, None);
}

#[test]
fn verify_overall_state_is_changed_when_a_name_is_missing() {
    let r = receipt();
    let e = [evidence(NAME)];
    let v = verify(Some((&r, &e)), &scope(), &[binding(NAME)], &[]);
    assert_eq!(v.state, "changed");
}

#[test]
fn verify_overall_state_is_changed_when_a_name_drifted() {
    let r = receipt();
    let e = [evidence(NAME)];
    let obs = [observed(NAME, Some(OTHER_VERSION), Some(FP))];
    let v = verify(Some((&r, &e)), &scope(), &[binding(NAME)], &obs);
    assert_eq!(v.state, "changed");
}

#[test]
fn verify_overall_state_is_changed_when_a_source_changed() {
    let r = receipt();
    let e = [evidence(NAME)];
    let obs = [observed(NAME, Some(VERSION), Some(OTHER_FP))];
    let v = verify(Some((&r, &e)), &scope(), &[binding(NAME)], &obs);
    assert_eq!(v.state, "changed");
}

#[test]
fn verify_overall_state_is_unverifiable_when_evidence_is_missing() {
    let r = receipt();
    let v = verify(Some((&r, &[])), &scope(), &[binding(NAME)], &[]);
    assert_eq!(v.state, "unverifiable");
}

#[test]
fn verify_overall_state_is_unverifiable_without_names() {
    let mut r = receipt();
    r.bindings = Vec::new();
    let v = verify(Some((&r, &[])), &scope(), &[], &[]);
    assert_eq!(v.state, "unverifiable");
}

#[test]
fn verify_reason_names_the_count_of_unverified_names() {
    let mut r = receipt();
    r.bindings = vec![binding(NAME), binding(OTHER)];
    let e = [evidence(NAME), evidence(OTHER)];
    let obs = [
        observed(NAME, Some(VERSION), Some(FP)),
        observed(OTHER, None, Some(FP)),
    ];
    let v = verify(
        Some((&r, &e)),
        &scope(),
        &[binding(NAME), binding(OTHER)],
        &obs,
    );
    assert_eq!(v.reason.as_deref(), Some("1 of 2 names not verified"));
}

// ---- Evidence Debug --------------------------------------------------------------

#[test]
fn evidence_debug_contains_its_name() {
    let text = format!("{:?}", evidence(NAME));
    assert!(text.contains(NAME));
}

#[test]
fn evidence_debug_never_shows_the_store_version() {
    let text = format!("{:?}", evidence(NAME));
    assert!(!text.contains(VERSION));
}

#[test]
fn evidence_debug_never_shows_the_fingerprint() {
    let text = format!("{:?}", evidence(NAME));
    assert!(!text.contains(FP));
}
