//! Key attributes (design Part V, row `key-attrs`): `source`, `expires` and `lifecycle`.
//! One atomic test per refusal, each asserting one public outcome through `config::parse`,
//! plus a full valid set that loads and the `active` lifecycle default.

use crate::cause::Cause;
use crate::config::parse;
use crate::domain::model::{Date, Lifecycle, ValueSource};

/// The field of the `ConfigInvalid` refusal of `text`; it always names product, key and
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

/// A declared key `api/SECRET` in `dev`, with `attrs` appended to its table.
fn key(attrs: &str) -> String {
    format!(
        "[environments.dev]\n\
         boundaries.api = {{ vault_id = \"v\", item_id = \"i\" }}\n\
         [products.api.keys.SECRET]\n\
         kind = \"secret\"\n\
         environments = [\"dev\"]\n\
         {attrs}\n"
    )
}

#[test]
fn a_full_attribute_set_loads() {
    assert!(
        parse(&key(
            "source = \"generated\"\nrules = { base64_bytes = 32 }\n\
             expires = \"2027-01-31\"\nlifecycle = \"retiring\""
        ))
        .is_ok()
    );
}

#[test]
fn lifecycle_defaults_to_active() {
    let fleet = parse(&key("")).expect("the key loads");
    assert_eq!(
        fleet.products["api"].keys["SECRET"].lifecycle,
        Lifecycle::Active
    );
}

#[test]
fn a_person_source_parses() {
    let fleet = parse(&key("source = \"person\"")).expect("the key loads");
    assert_eq!(
        fleet.products["api"].keys["SECRET"].value_source,
        Some(ValueSource::Person)
    );
}

#[test]
fn a_derived_key_with_a_from_source_loads() {
    let text = "[environments.dev]\n\
                boundaries.api = { vault_id = \"v\", item_id = \"i\" }\n\
                [products.api.keys.SOURCE]\n\
                kind = \"secret\"\n\
                environments = [\"dev\"]\n\
                [products.api.keys.SECRET]\n\
                kind = \"secret\"\n\
                environments = [\"dev\"]\n\
                from = \"api/SOURCE\"\n\
                source = \"derived\"\n";
    assert!(parse(text).is_ok());
}

#[test]
fn expires_parses_as_a_calendar_date() {
    let fleet = parse(&key("expires = \"2027-01-31\"")).expect("the date loads");
    assert_eq!(
        fleet.products["api"].keys["SECRET"].expires,
        Date::new(2027, 1, 31)
    );
}

#[test]
fn a_derived_key_without_from_is_refused_naming_the_key() {
    assert_eq!(
        field_of(&key("source = \"derived\"")),
        "products.api.keys.SECRET.from"
    );
}

#[test]
fn a_shared_key_with_an_explicit_non_derived_source_is_refused_naming_the_key() {
    assert_eq!(
        field_of(&key("from = \"api/OTHER\"\nsource = \"person\"")),
        "products.api.keys.SECRET.source"
    );
}

#[test]
fn a_generated_key_without_a_recipe_is_refused_naming_the_key() {
    assert_eq!(
        field_of(&key("source = \"generated\"")),
        "products.api.keys.SECRET.source"
    );
}

#[test]
fn an_unknown_source_value_is_refused_naming_the_key() {
    assert_eq!(
        field_of(&key("source = \"minted\"")),
        "products.api.keys.SECRET.source"
    );
}

#[test]
fn an_unknown_lifecycle_value_is_refused_naming_the_key() {
    assert_eq!(
        field_of(&key("lifecycle = \"paused\"")),
        "products.api.keys.SECRET.lifecycle"
    );
}

#[test]
fn an_invalid_expiry_date_is_refused_naming_the_key() {
    assert_eq!(
        field_of(&key("expires = \"2026-02-30\"")),
        "products.api.keys.SECRET.expires"
    );
}
