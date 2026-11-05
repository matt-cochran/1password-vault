//! Provision templates (design `owner-value-ingestion.md` §3.2, §4.5, §5.3, §10 test 72):
//! leaf parsing, the compact writer, the round-trip, render order and the stored-shape
//! reading. One behavioural assertion per test. Names and values are fake.

use std::collections::BTreeMap;

use crate::domain::provision::{Generator, KeyRef, MemberSource, ProvisionSet};
use crate::domain::provision_template::{
    Cycle, LeafError, MAX_INTERMEDIATE_BYTES, Mismatch, Node, Ref, RenderError, Template, extract,
    fit, leaf, render, render_order, round_trip, write,
};
use crate::domain::secret::SecretValue;

fn key(s: &str) -> KeyRef {
    KeyRef::parse(s).unwrap()
}

fn member(s: &str) -> Ref {
    Ref::Member(key(s))
}

fn output(p: &str, o: &str) -> Ref {
    Ref::Output {
        producer: p.into(),
        output: o.into(),
    }
}

fn site(id: Ref, identity: Ref, gateway: Ref) -> Node {
    Node::Table(vec![
        ("siteId".into(), Node::Ref(id)),
        ("identitySecret".into(), Node::Ref(identity)),
        ("gatewaySecret".into(), Node::Ref(gateway)),
    ])
}

/// The bundle template of the three-site set (§3.1), with fake names.
fn bundle() -> Template {
    let gw = || member("shop/SITES_GATEWAY_KEY");
    Template::new(Node::Table(vec![
        ("version".into(), Node::Integer(1)),
        (
            "sites".into(),
            Node::Array(vec![
                site(
                    output("site-issuer", "platform_site_id"),
                    member("shop/PLATFORM_IDENTITY_SECRET"),
                    gw(),
                ),
                site(
                    output("site-issuer", "agency_site_id"),
                    member("shop/AGENCY_IDENTITY_SECRET"),
                    gw(),
                ),
                site(
                    output("site-issuer", "owner_site_id"),
                    member("shop/OWNER_IDENTITY_SECRET"),
                    gw(),
                ),
            ]),
        ),
    ]))
}

/// The fake inputs test 72's expected bytes were computed from.
fn bundle_values() -> BTreeMap<Ref, SecretValue> {
    let v = |s: &str| SecretValue::new(s.to_string());
    BTreeMap::from([
        (
            output("site-issuer", "platform_site_id"),
            v("00000000-0000-4000-8000-000000000001"),
        ),
        (
            output("site-issuer", "agency_site_id"),
            v("00000000-0000-4000-8000-000000000002"),
        ),
        (
            output("site-issuer", "owner_site_id"),
            v("00000000-0000-4000-8000-000000000003"),
        ),
        (member("shop/PLATFORM_IDENTITY_SECRET"), v(&"1".repeat(64))),
        (member("shop/AGENCY_IDENTITY_SECRET"), v(&"2".repeat(64))),
        (member("shop/OWNER_IDENTITY_SECRET"), v(&"3".repeat(64))),
        (member("shop/SITES_GATEWAY_KEY"), v(&"f".repeat(64))),
    ])
}

/// Test 72's expected bytes, produced by the owner script's `build_aggregate` (the infra
/// repo's `fly/shared-host/zonetico_journeeze_staging.py:379-384` at adcfa5e7:
/// `json.dumps(document, separators=(',', ':'), ensure_ascii=False)`). Its six lines were
/// copied verbatim into a scratch file and run once with `python3 -I` on three sites whose
/// `siteId`s are `00000000-0000-4000-8000-00000000000{1,2,3}`, `identitySecret`s 64 × `1`,
/// `2`, `3` and `gatewaySecret` 64 × `f` (the inputs of [`bundle_values`]); the printed line
/// is embedded here, split only for width.
const BUILD_AGGREGATE: &str = concat!(
    r#"{"version":1,"sites":["#,
    r#"{"siteId":"00000000-0000-4000-8000-000000000001","#,
    r#""identitySecret":"1111111111111111111111111111111111111111111111111111111111111111","#,
    r#""gatewaySecret":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},"#,
    r#"{"siteId":"00000000-0000-4000-8000-000000000002","#,
    r#""identitySecret":"2222222222222222222222222222222222222222222222222222222222222222","#,
    r#""gatewaySecret":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},"#,
    r#"{"siteId":"00000000-0000-4000-8000-000000000003","#,
    r#""identitySecret":"3333333333333333333333333333333333333333333333333333333333333333","#,
    r#""gatewaySecret":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}]}"#,
);

/// A one-site template whose `siteId` is the escaping probe below.
fn one_site() -> Template {
    Template::new(Node::Table(vec![
        ("version".into(), Node::Integer(1)),
        (
            "sites".into(),
            Node::Array(vec![site(
                output("site-issuer", "platform_site_id"),
                member("shop/PLATFORM_IDENTITY_SECRET"),
                member("shop/SITES_GATEWAY_KEY"),
            )]),
        ),
    ]))
}

/// A `siteId` needing every kind of escape: quote, backslash, slash, the short escapes, two
/// other control bytes, DEL, a space, é, U+2028 and an astral character.
const PROBE: &str = "q\"b\\s/\n\r\t\u{8}\u{c}\u{1}\u{1f}\u{7f} \u{e9}\u{2028}\u{1f600}";

/// What `build_aggregate` printed for one site with `siteId` [`PROBE`] (same scratch run as
/// [`BUILD_AGGREGATE`]; the run printed its `json.dumps`, decoded here).
const PROBE_AGGREGATE: &str = concat!(
    r#"{"version":1,"sites":[{"siteId":"q\"b\\s/\n\r\t\b\f\u0001\u001f"#,
    "\u{7f} \u{e9}\u{2028}\u{1f600}",
    r#"","identitySecret":"1111111111111111111111111111111111111111111111111111111111111111","#,
    r#""gatewaySecret":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}]}"#,
);

fn probe_values() -> BTreeMap<Ref, SecretValue> {
    let mut v = bundle_values();
    v.insert(
        output("site-issuer", "platform_site_id"),
        SecretValue::new(PROBE.into()),
    );
    v
}

fn rendered(t: &Template, values: &BTreeMap<Ref, SecretValue>) -> Vec<u8> {
    render(t, |r| values.get(r)).unwrap().to_vec()
}

fn members_of<'a>(
    values: &'a BTreeMap<Ref, SecretValue>,
) -> impl Fn(&KeyRef) -> Option<&'a SecretValue> + 'a {
    move |k| values.get(&Ref::Member(k.clone()))
}

// ---- leaves (§3.2) -------------------------------------------------------------------

#[test]
fn a_string_without_a_reference_is_a_literal() {
    assert_eq!(leaf("plain $ {x}"), Ok(Node::String("plain $ {x}".into())));
}

#[test]
fn a_whole_member_reference_is_a_member_leaf() {
    assert_eq!(
        leaf("${shop/SITES_GATEWAY_KEY}"),
        Ok(Node::Ref(member("shop/SITES_GATEWAY_KEY")))
    );
}

#[test]
fn a_whole_output_reference_is_an_output_leaf() {
    assert_eq!(
        leaf("${site-issuer.owner_site_id}"),
        Ok(Node::Ref(output("site-issuer", "owner_site_id")))
    );
}

/// Test 9 (domain half; the load half is in `config/sets_tests.rs`).
#[test]
fn a_reference_inside_a_longer_string_is_interpolation() {
    assert_eq!(leaf("x${shop/A}"), Err(LeafError::Interpolated));
}

#[test]
fn two_references_in_one_string_are_interpolation() {
    assert_eq!(leaf("${shop/A}${shop/B}"), Err(LeafError::Interpolated));
}

#[test]
fn a_reference_naming_neither_form_is_malformed() {
    assert_eq!(leaf("${justaname}"), Err(LeafError::Malformed));
}

#[test]
fn an_unclosed_reference_is_interpolation() {
    assert_eq!(leaf("${shop/A"), Err(LeafError::Interpolated));
}

#[test]
fn references_are_listed_in_declared_order_with_repeats() {
    assert_eq!(bundle().references().len(), 9);
}

#[test]
fn a_template_uses_the_outputs_it_references() {
    assert!(bundle().uses_output("site-issuer", "agency_site_id"));
}

// ---- writer (§5.3, test 72) ----------------------------------------------------------

/// Test 72.
#[test]
fn the_rendered_bundle_is_byte_identical_to_build_aggregate() {
    assert_eq!(
        rendered(&bundle(), &bundle_values()),
        BUILD_AGGREGATE.as_bytes()
    );
}

#[test]
fn escaping_matches_build_aggregate_for_every_kind_of_character() {
    assert_eq!(
        rendered(&one_site(), &probe_values()),
        PROBE_AGGREGATE.as_bytes()
    );
}

#[test]
fn a_rendering_is_sized_exactly_once() {
    let values = bundle_values();
    let out = write(&bundle(), |r| values.get(r)).unwrap();
    assert_eq!(out.capacity(), out.len());
}

#[test]
fn literals_render_in_declared_order() {
    let t = Template::new(Node::Table(vec![
        ("z".into(), Node::Bool(true)),
        ("a".into(), Node::Integer(-7)),
        ("m".into(), Node::String("lit".into())),
    ]));
    assert_eq!(
        rendered(&t, &BTreeMap::new()),
        br#"{"z":true,"a":-7,"m":"lit"}"#
    );
}

#[test]
fn a_reference_without_a_value_does_not_render() {
    let values: BTreeMap<Ref, SecretValue> = BTreeMap::new();
    assert_eq!(
        render(&bundle(), |r| values.get(r)).err(),
        Some(RenderError::Missing {
            reference: output("site-issuer", "platform_site_id")
        })
    );
}

#[test]
fn an_intermediate_over_the_bound_does_not_round_trip() {
    let mut values = bundle_values();
    values.insert(
        output("site-issuer", "agency_site_id"),
        SecretValue::new("a".repeat(MAX_INTERMEDIATE_BYTES + 1)),
    );
    assert_eq!(
        render(&bundle(), |r| values.get(r)).err(),
        Some(RenderError::RoundTrip(Mismatch::IntermediateBounds {
            reference: output("site-issuer", "agency_site_id")
        }))
    );
}

// ---- round-trip ----------------------------------------------------------------------

#[test]
fn a_rendering_round_trips_to_its_sources() {
    let values = probe_values();
    let out = rendered(&one_site(), &values);
    assert_eq!(round_trip(&one_site(), &out, |r| values.get(r)), Ok(()));
}

#[test]
fn a_document_whose_leaf_differs_from_its_source_does_not_round_trip() {
    let values = bundle_values();
    let mut other = bundle_values();
    other.insert(
        member("shop/OWNER_IDENTITY_SECRET"),
        SecretValue::new("4".repeat(64)),
    );
    let out = rendered(&bundle(), &other);
    assert_eq!(
        round_trip(&bundle(), &out, |r| values.get(r)),
        Err(Mismatch::LeafDiffers {
            reference: member("shop/OWNER_IDENTITY_SECRET")
        })
    );
}

// ---- stored shape (§4.5, §4.7) -------------------------------------------------------

#[test]
fn a_stored_bundle_yields_each_members_leaf() {
    let leaves = extract(&bundle(), BUILD_AGGREGATE.as_bytes()).unwrap();
    assert_eq!(
        leaves
            .member(&key("shop/AGENCY_IDENTITY_SECRET"))
            .map(|v| v.expose().to_string()),
        Some("2".repeat(64))
    );
}

#[test]
fn a_stored_bundle_yields_each_intermediate_leaf() {
    let leaves = extract(&bundle(), BUILD_AGGREGATE.as_bytes()).unwrap();
    assert_eq!(
        leaves
            .output("site-issuer", "owner_site_id")
            .map(|v| v.expose().to_string()),
        Some("00000000-0000-4000-8000-000000000003".to_string())
    );
}

#[test]
fn escapes_read_back_to_the_original_leaf() {
    let leaves = extract(&one_site(), PROBE_AGGREGATE.as_bytes()).unwrap();
    assert_eq!(
        leaves
            .output("site-issuer", "platform_site_id")
            .map(|v| v.expose().to_string()),
        Some(PROBE.to_string())
    );
}

#[test]
fn a_pretty_printed_bundle_with_reordered_keys_has_the_shape() {
    let stored = r#"{ "sites": [
        {"gatewaySecret": "g", "siteId": "s1", "identitySecret": "i1"},
        {"siteId": "s2", "identitySecret": "i2", "gatewaySecret": "g"},
        {"siteId": "s3", "identitySecret": "i3", "gatewaySecret": "g"}
    ], "version": 1 }"#;
    assert!(extract(&bundle(), stored.as_bytes()).is_ok());
}

#[test]
fn a_stored_bundle_with_another_version_is_not_its_shape() {
    let stored = BUILD_AGGREGATE.replace(r#""version":1"#, r#""version":2"#);
    assert_eq!(
        extract(&bundle(), stored.as_bytes()).err(),
        Some(Mismatch::NotItsShape)
    );
}

#[test]
fn a_stored_bundle_with_a_missing_site_is_not_its_shape() {
    let stored = rendered(&one_site(), &bundle_values());
    assert_eq!(
        extract(&bundle(), &stored).err(),
        Some(Mismatch::NotItsShape)
    );
}

#[test]
fn a_stored_bundle_with_an_extra_field_is_not_its_shape() {
    let stored = BUILD_AGGREGATE.replacen(r#"{"siteId""#, r#"{"extra":"x","siteId""#, 1);
    assert_eq!(
        extract(&bundle(), stored.as_bytes()).err(),
        Some(Mismatch::NotItsShape)
    );
}

#[test]
fn a_duplicate_key_is_not_its_shape() {
    let stored = BUILD_AGGREGATE.replacen(r#"{"version":1,"#, r#"{"version":1,"version":1,"#, 1);
    assert_eq!(
        extract(&bundle(), stored.as_bytes()).err(),
        Some(Mismatch::NotItsShape)
    );
}

#[test]
fn trailing_bytes_are_not_json() {
    let stored = format!("{BUILD_AGGREGATE}x");
    assert_eq!(
        extract(&bundle(), stored.as_bytes()).err(),
        Some(Mismatch::NotJson)
    );
}

#[test]
fn a_float_version_is_not_its_shape() {
    let stored = BUILD_AGGREGATE.replace(r#""version":1"#, r#""version":1.0"#);
    assert_eq!(
        extract(&bundle(), stored.as_bytes()).err(),
        Some(Mismatch::NotItsShape)
    );
}

#[test]
fn a_shared_gateway_leaf_that_differs_between_sites_disagrees() {
    let stored = BUILD_AGGREGATE.replacen(&"f".repeat(64), &"e".repeat(64), 1);
    assert_eq!(
        extract(&bundle(), stored.as_bytes()).err(),
        Some(Mismatch::RepeatDisagrees {
            reference: member("shop/SITES_GATEWAY_KEY")
        })
    );
}

#[test]
fn an_empty_intermediate_leaf_is_out_of_bounds() {
    let stored = BUILD_AGGREGATE.replace("00000000-0000-4000-8000-000000000002", "");
    assert_eq!(
        extract(&bundle(), stored.as_bytes()).err(),
        Some(Mismatch::IntermediateBounds {
            reference: output("site-issuer", "agency_site_id")
        })
    );
}

#[test]
fn a_stored_bundle_matching_the_stored_members_fits() {
    let values = bundle_values();
    assert!(fit(&bundle(), BUILD_AGGREGATE.as_bytes(), members_of(&values)).is_ok());
}

#[test]
fn a_stored_bundle_whose_member_leaf_differs_from_the_member_does_not_fit() {
    let mut values = bundle_values();
    values.insert(
        member("shop/PLATFORM_IDENTITY_SECRET"),
        SecretValue::new("9".repeat(64)),
    );
    assert_eq!(
        fit(&bundle(), BUILD_AGGREGATE.as_bytes(), members_of(&values)).err(),
        Some(Mismatch::LeafDiffers {
            reference: member("shop/PLATFORM_IDENTITY_SECRET")
        })
    );
}

#[test]
fn a_missing_member_is_not_compared_by_fit() {
    assert!(fit(&bundle(), BUILD_AGGREGATE.as_bytes(), |_: &KeyRef| None).is_ok());
}

// ---- render order and cycles (§3.2) --------------------------------------------------

fn set_of(members: Vec<(&str, MemberSource)>) -> ProvisionSet {
    ProvisionSet {
        environments: vec!["staging".into()],
        boundary: "b".into(),
        members: members.into_iter().map(|(k, s)| (key(k), s)).collect(),
    }
}

fn refs(to: &str) -> MemberSource {
    MemberSource::Template(Template::new(Node::Array(vec![Node::Ref(member(to))])))
}

#[test]
fn a_template_renders_after_the_template_it_references() {
    let set = set_of(vec![
        ("p/A", refs("p/B")),
        ("p/B", refs("p/C")),
        ("p/C", MemberSource::Generate(Generator::HexBytes(32))),
    ]);
    assert_eq!(render_order(&set), Ok(vec![key("p/B"), key("p/A")]));
}

/// Test 10 (domain half; the load half is in `config/sets_tests.rs`).
#[test]
fn templates_referencing_each_other_are_a_cycle() {
    let set = set_of(vec![("p/A", refs("p/B")), ("p/B", refs("p/A"))]);
    assert!(matches!(render_order(&set), Err(Cycle { .. })));
}

#[test]
fn a_template_referencing_itself_is_a_cycle() {
    let set = set_of(vec![("p/A", refs("p/A"))]);
    assert_eq!(render_order(&set), Err(Cycle { member: key("p/A") }));
}
