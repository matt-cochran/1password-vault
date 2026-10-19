//! Annotations (design Part V, row `annotations`): `[products.<p>.ignore] NAME = {reason,
//! span}` parses, an empty reason is refused, and the span is a stable hash of the evidence
//! line. One atomic test per rule, each asserting one public outcome.

use crate::cause::Cause;
use crate::config::parse;
use crate::domain::model::span_of;

/// The field of the `ConfigInvalid` refusal of `text`, naming product, annotation and
/// field. Panics when the refusal is not a `ConfigInvalid`.
fn field_of(text: &str) -> String {
    match parse(text) {
        Err(e) => match e.cause() {
            Some((Cause::ConfigInvalid { field, .. }, _)) => field.to_string(),
            Some((other, _)) => panic!("expected ConfigInvalid, got {other:?}"),
            None => panic!("expected a catalog cause, got {e:?}"),
        },
        Ok(_) => panic!("expected a refusal"),
    }
}

/// A config with product `api` (one key in `dev`) and one ignore annotation.
fn with_ignore(name: &str, body: &str) -> String {
    format!(
        "[environments.dev]\n\
         boundaries.api = {{ vault_id = \"v\", item_id = \"i\" }}\n\
         [products.api.keys.SECRET]\n\
         kind = \"secret\"\n\
         environments = [\"dev\"]\n\
         [products.api.ignore]\n\
         {name} = {body}\n"
    )
}

#[test]
fn an_ignore_annotation_with_reason_and_span_parses() {
    let fleet = parse(&with_ignore(
        "LEGACY_TOKEN",
        "{ reason = \"false positive\", span = \"0123456789abcdef\" }",
    ))
    .expect("the annotation loads");
    assert!(fleet.products["api"].ignore.contains_key("LEGACY_TOKEN"));
}

#[test]
fn an_empty_reason_is_refused() {
    let field = field_of(&with_ignore(
        "LEGACY_TOKEN",
        "{ reason = \"   \", span = \"0123456789abcdef\" }",
    ));
    assert_eq!(field, "products.api.ignore.LEGACY_TOKEN.reason");
}

#[test]
fn an_annotation_name_off_the_pattern_is_refused() {
    let field = field_of(&with_ignore(
        "legacy-token",
        "{ reason = \"false positive\", span = \"0123456789abcdef\" }",
    ));
    assert_eq!(field, "products.api.ignore.legacy-token");
}

#[test]
fn the_same_evidence_line_gives_the_same_span() {
    assert_eq!(
        span_of("src/a.rs", "let token = read();"),
        span_of("src/a.rs", "let token = read();")
    );
}

#[test]
fn a_changed_evidence_line_gives_a_different_span() {
    assert_ne!(
        span_of("src/a.rs", "let token = read();"),
        span_of("src/a.rs", "let token = write();")
    );
}

#[test]
fn a_whitespace_only_change_gives_the_same_span() {
    assert_eq!(
        span_of("src/a.rs", "  let token = read();  "),
        span_of("src/a.rs", "let token = read();")
    );
}
