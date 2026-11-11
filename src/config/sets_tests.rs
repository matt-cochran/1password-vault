//! `[sets]` and `[producers]` at load (design `owner-value-ingestion.md` §3.2, §10.1 tests
//! 1-11): one behavioural assertion per test.

use std::path::Path;

use crate::cause::{Cause, ConfigCheck, FieldRule, GivenBy};
use crate::config::{parse, parse_file};
use crate::domain::Fleet;
use crate::domain::provision::{Generator, KeyRef, MemberSource};
use crate::domain::provision_template::{Node, Template};
use crate::error::Error;

/// Two products in their own boundaries; `app` has a client id, a token and a key with a
/// byte rule; `other` has one key.
const BASE: &str = r#"[environments.prod]
boundaries.app = {}
boundaries.other = {}

[environments.staging]
boundaries.app = {}
boundaries.other = {}

[products.app.keys.CLIENT_ID]
kind = "secret"

[products.app.keys.REFRESH_TOKEN]
kind = "secret"

[products.app.keys.SESSION_KEY]
kind = "secret"
rules = { hex_bytes = 32 }

[products.app.keys.PLAIN]
kind = "secret"

[products.other.keys.OTHER_KEY]
kind = "secret"
"#;

/// The producer `consent` (one output, one input) without a project file.
const PRODUCER: &str = r#"
[producers.consent]
command = ["python3", "-c", "pass"]
outputs = ["refresh_token"]
inputs = { client_id = "app/CLIENT_ID" }
open_url_hosts = ["accounts.example.com"]
timeout = "10m"
"#;

/// The set `grant`: the token from `consent`, a generated key.
const SET: &str = r#"
[sets.grant]
environments = ["prod"]
members = { "app/REFRESH_TOKEN" = { producer = "consent", output = "refresh_token" }, "app/SESSION_KEY" = { generate = { hex_bytes = 32 } } }
"#;

fn load(extra: &str) -> Result<Fleet, Error> {
    parse(&format!("{BASE}{extra}"))
}

/// The field a `config_invalid` refusal names, dotted; `None` for any other error.
fn refused_field(r: Result<Fleet, Error>) -> Option<String> {
    match r.err()?.cause()? {
        (Cause::ConfigInvalid { field, .. }, _) => Some(field.0.join(".")),
        _ => None,
    }
}

/// The rule of a `config_invalid` refusal; `None` for any other result.
fn refused_rule(r: Result<Fleet, Error>) -> Option<FieldRule> {
    match r.err()?.cause()? {
        (Cause::ConfigInvalid { rule, .. }, _) => Some(rule.clone()),
        _ => None,
    }
}

fn load_in(dir: &Path, text: &str) -> Result<Fleet, Error> {
    let path = dir.join("secrets.toml");
    std::fs::write(&path, text).unwrap();
    parse_file(text, &path, GivenBy::Discovered)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

// ---- loads -----------------------------------------------------------------------

#[test]
fn a_valid_set_and_producer_load() {
    assert!(load(&format!("{PRODUCER}{SET}")).is_ok());
}

#[test]
fn a_loaded_set_records_its_boundary() {
    let fleet = load(&format!("{PRODUCER}{SET}")).unwrap();
    assert_eq!(fleet.sets["grant"].boundary, "app");
}

#[test]
fn a_loaded_member_records_its_generator() {
    let fleet = load(&format!("{PRODUCER}{SET}")).unwrap();
    let key = KeyRef::parse("app/SESSION_KEY").unwrap();
    assert_eq!(
        fleet.sets["grant"].members[&key],
        MemberSource::Generate(Generator::HexBytes(32))
    );
}

#[test]
fn a_loaded_producer_records_its_timeout() {
    let fleet = load(&format!("{PRODUCER}{SET}")).unwrap();
    assert_eq!(fleet.producers["consent"].timeout.as_secs(), 600);
}

#[test]
fn set_of_names_a_members_set() {
    let fleet = load(&format!("{PRODUCER}{SET}")).unwrap();
    assert_eq!(fleet.set_of("app", "REFRESH_TOKEN"), Some("grant"));
}

#[test]
fn a_contract_without_sets_has_none() {
    assert!(load("").unwrap().sets.is_empty());
}

// ---- §10.1 tests 1-8 ------------------------------------------------------------------

/// Test 1.
#[test]
fn members_in_two_boundaries_are_refused() {
    let set = r#"
[sets.split]
environments = ["prod"]
members = { "app/PLAIN" = { generate = { hex_bytes = 32 } }, "other/OTHER_KEY" = { generate = { hex_bytes = 32 } } }
"#;
    assert_eq!(
        refused_field(load(set)).as_deref(),
        Some("sets.split.members.other/OTHER_KEY")
    );
}

/// Test 2.
#[test]
fn a_key_in_two_sets_is_refused() {
    let sets = r#"
[sets.one]
environments = ["prod"]
members = { "app/PLAIN" = { generate = { hex_bytes = 32 } } }

[sets.two]
environments = ["prod"]
members = { "app/PLAIN" = { generate = { base64_bytes = 32 } } }
"#;
    assert_eq!(
        refused_field(load(sets)).as_deref(),
        Some("sets.two.members.app/PLAIN")
    );
}

/// Test 3.
#[test]
fn command_zero_op_is_refused() {
    let producer = PRODUCER.replace(r#"["python3", "-c", "pass"]"#, r#"["op", "read"]"#);
    assert!(matches!(
        refused_rule(load(&format!("{producer}{SET}"))),
        Some(FieldRule::Check {
            check: ConfigCheck::ProducerIsOp { .. }
        })
    ));
}

#[test]
fn command_zero_opv_by_path_is_refused() {
    let producer = PRODUCER.replace(r#"["python3", "-c", "pass"]"#, r#"["/usr/bin/OPV.exe"]"#);
    assert!(matches!(
        refused_rule(load(&format!("{producer}{SET}"))),
        Some(FieldRule::Check {
            check: ConfigCheck::ProducerIsOp { .. }
        })
    ));
}

/// Test 4.
#[test]
fn a_token_shaped_argument_is_refused() {
    let producer = PRODUCER.replace(
        r#"["python3", "-c", "pass"]"#,
        r#"["python3", "x.py", "ops_abcdefghijklmnopqrstuvwxyz"]"#,
    );
    assert_eq!(
        refused_field(load(&format!("{producer}{SET}"))).as_deref(),
        Some("producers.consent.command")
    );
}

/// Test 5.
#[test]
fn a_sha256_mismatch_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("connect.py"), "print('edited')\n").unwrap();
    let producer = PRODUCER.replace(
        r#"["python3", "-c", "pass"]"#,
        &format!(
            r#"["python3", "connect.py"]
sha256 = "{}""#,
            sha256_hex(b"print('reviewed')\n")
        ),
    );
    let e = load_in(dir.path(), &format!("{BASE}{producer}{SET}")).unwrap_err();
    assert_eq!(e.code_str(), "producer_changed");
}

#[test]
fn a_matching_sha256_loads() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("connect.py"), "print('reviewed')\n").unwrap();
    let producer = PRODUCER.replace(
        r#"["python3", "-c", "pass"]"#,
        &format!(
            r#"["python3", "connect.py"]
sha256 = "{}""#,
            sha256_hex(b"print('reviewed')\n")
        ),
    );
    assert!(load_in(dir.path(), &format!("{BASE}{producer}{SET}")).is_ok());
}

#[test]
fn a_project_file_without_sha256_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("connect.py"), "print('reviewed')\n").unwrap();
    let producer = PRODUCER.replace(
        r#"["python3", "-c", "pass"]"#,
        r#"["python3", "connect.py"]"#,
    );
    assert!(matches!(
        refused_rule(load_in(dir.path(), &format!("{BASE}{producer}{SET}"))),
        Some(FieldRule::Check {
            check: ConfigCheck::ProducerShaMissing { .. }
        })
    ));
}

/// Test 6.
#[test]
fn a_timeout_of_sixteen_minutes_is_refused() {
    let producer = PRODUCER.replace(r#"timeout = "10m""#, r#"timeout = "16m""#);
    assert_eq!(
        refused_field(load(&format!("{producer}{SET}"))).as_deref(),
        Some("producers.consent.timeout")
    );
}

#[test]
fn a_timeout_of_fifteen_minutes_loads() {
    let producer = PRODUCER.replace(r#"timeout = "10m""#, r#"timeout = "15m""#);
    assert!(load(&format!("{producer}{SET}")).is_ok());
}

/// Test 7.
#[test]
fn an_input_of_another_boundary_is_refused() {
    let producer = PRODUCER.replace(r#""app/CLIENT_ID""#, r#""other/OTHER_KEY""#);
    assert_eq!(
        refused_field(load(&format!("{producer}{SET}"))).as_deref(),
        Some("producers.consent.inputs.client_id")
    );
}

#[test]
fn an_input_not_wanted_in_the_sets_environment_is_refused() {
    let base = BASE.replace(
        "[products.app.keys.CLIENT_ID]\nkind = \"secret\"\n",
        "[products.app.keys.CLIENT_ID]\nkind = \"secret\"\nenvironments = [\"staging\"]\n",
    );
    let r = parse(&format!("{base}{PRODUCER}{SET}"));
    assert_eq!(
        refused_field(r).as_deref(),
        Some("producers.consent.inputs.client_id")
    );
}

/// Test 8.
#[test]
fn generate_rules_on_a_key_without_a_byte_rule_is_refused() {
    let set = r#"
[sets.plain]
environments = ["prod"]
members = { "app/PLAIN" = { generate = "rules" } }
"#;
    assert_eq!(
        refused_field(load(set)).as_deref(),
        Some("sets.plain.members.app/PLAIN.generate")
    );
}

#[test]
fn generate_rules_on_a_key_with_a_byte_rule_loads() {
    let set = r#"
[sets.keyed]
environments = ["prod"]
members = { "app/SESSION_KEY" = { generate = "rules" } }
"#;
    assert!(load(set).is_ok());
}

#[test]
fn generate_rules_on_an_ssh_ed25519_key_records_the_rules_generator() {
    let set = r#"
[products.app.keys.SSH_KEY]
kind = "secret"
rules = { ssh_ed25519 = true }
file = "ssh-key"

[sets.identities]
environments = ["prod"]
members = { "app/SSH_KEY" = { generate = "rules" } }
"#;
    let key = KeyRef::parse("app/SSH_KEY").unwrap();
    assert_eq!(
        load(set).unwrap().sets["identities"].members[&key],
        MemberSource::Generate(Generator::Rules)
    );
}

#[test]
fn generate_rules_on_an_age_identity_key_records_the_rules_generator() {
    let set = r#"
[products.app.keys.AGE_KEY]
kind = "secret"
rules = { age_identity = true }

[sets.identities]
environments = ["prod"]
members = { "app/AGE_KEY" = { generate = "rules" } }
"#;
    let key = KeyRef::parse("app/AGE_KEY").unwrap();
    assert_eq!(
        load(set).unwrap().sets["identities"].members[&key],
        MemberSource::Generate(Generator::Rules)
    );
}

// ---- other load rules -------------------------------------------------------------------

#[test]
fn op_is_refused_as_command_zero() {
    let producer = PRODUCER.replace(r#"["python3", "-c", "pass"]"#, r#"["op"]"#);
    assert_eq!(
        refused_field(load(&format!("{producer}{SET}"))).as_deref(),
        Some("producers.consent.command")
    );
}

#[test]
fn a_personal_member_is_refused() {
    let base = BASE.replace(
        "[products.app.keys.PLAIN]\nkind = \"secret\"\n",
        "[products.app.keys.PLAIN]\nkind = \"secret\"\npersonal = true\n",
    );
    let set = r#"
[sets.mine]
environments = ["prod"]
members = { "app/PLAIN" = { generate = { hex_bytes = 32 } } }
"#;
    assert_eq!(
        refused_field(parse(&format!("{base}{set}"))).as_deref(),
        Some("sets.mine.members.app/PLAIN")
    );
}

#[test]
fn a_member_not_wanted_in_a_set_environment_is_refused() {
    let base = BASE.replace(
        "[products.app.keys.PLAIN]\nkind = \"secret\"\n",
        "[products.app.keys.PLAIN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n",
    );
    let set = r#"
[sets.wide]
environments = ["prod", "staging"]
members = { "app/PLAIN" = { generate = { hex_bytes = 32 } } }
"#;
    assert_eq!(
        refused_field(parse(&format!("{base}{set}"))).as_deref(),
        Some("sets.wide.members.app/PLAIN")
    );
}

#[test]
fn an_undeclared_member_key_is_refused() {
    let set = r#"
[sets.typo]
environments = ["prod"]
members = { "app/PLAN" = { generate = { hex_bytes = 32 } } }
"#;
    assert_eq!(
        refused_field(load(set)).as_deref(),
        Some("sets.typo.members.app/PLAN")
    );
}

#[test]
fn an_output_the_producer_does_not_declare_is_refused() {
    let set = SET.replace(r#"output = "refresh_token""#, r#"output = "token""#);
    assert_eq!(
        refused_field(load(&format!("{PRODUCER}{set}"))).as_deref(),
        Some("sets.grant.members.app/REFRESH_TOKEN.output")
    );
}

#[test]
fn an_unused_producer_output_is_refused() {
    let producer = PRODUCER.replace(
        r#"outputs = ["refresh_token"]"#,
        r#"outputs = ["refresh_token", "extra"]"#,
    );
    assert_eq!(
        refused_field(load(&format!("{producer}{SET}"))).as_deref(),
        Some("producers.consent.outputs")
    );
}

#[test]
fn a_url_as_an_open_url_host_is_refused() {
    let producer = PRODUCER.replace(
        r#"["accounts.example.com"]"#,
        r#"["https://accounts.example.com"]"#,
    );
    assert_eq!(
        refused_field(load(&format!("{producer}{SET}"))).as_deref(),
        Some("producers.consent.open_url_hosts")
    );
}

#[test]
fn a_generator_byte_count_out_of_range_is_refused() {
    let set = r#"
[sets.small]
environments = ["prod"]
members = { "app/PLAIN" = { generate = { hex_bytes = 8 } } }
"#;
    assert_eq!(
        refused_field(load(set)).as_deref(),
        Some("sets.small.members.app/PLAIN.generate")
    );
}

#[test]
fn a_member_with_producer_and_generate_is_refused() {
    let set = r#"
[sets.both]
environments = ["prod"]
members = { "app/REFRESH_TOKEN" = { producer = "consent", output = "refresh_token", generate = "rules" } }
"#;
    assert!(matches!(
        refused_rule(load(&format!("{PRODUCER}{set}"))),
        Some(FieldRule::ConflictsWith { .. })
    ));
}

// ---- templates (Slice B, §3.2, §10.1 tests 9-11) ---------------------------------------

/// The #262 set's shape (§3.1) with fake names: a site issuer producing three site ids and
/// keys, five generated hex secrets, and a bundle template over ids, identities and the
/// shared gateway key, all in one boundary.
const SITES: &str = r#"[environments.prod]
boundaries.hub = {}

[environments.staging]
boundaries.hub = {}

[products.shop]
boundary = "hub"

[products.shop.keys.PLATFORM_IDENTITY_SECRET]
kind = "secret"
rules = { regex = "[0-9a-f]{64}" }

[products.shop.keys.AGENCY_IDENTITY_SECRET]
kind = "secret"
rules = { regex = "[0-9a-f]{64}" }

[products.shop.keys.OWNER_IDENTITY_SECRET]
kind = "secret"
rules = { regex = "[0-9a-f]{64}" }

[products.shop.keys.SITES_GATEWAY_KEY]
kind = "secret"
rules = { regex = "[0-9a-f]{64}" }

[products.shop.keys.USER_HASH_KEY]
kind = "secret"
immutable = true
rules = { regex = "[0-9a-f]{64}" }

[products.shop.keys.PLATFORM_SITE_KEY]
kind = "secret"
rules = { regex = "pk_[A-Za-z0-9_]{1,61}" }

[products.shop.keys.AGENCY_SITE_KEY]
kind = "secret"
rules = { regex = "pk_[A-Za-z0-9_]{1,61}" }

[products.shop.keys.OWNER_SITE_KEY]
kind = "secret"
rules = { regex = "pk_[A-Za-z0-9_]{1,61}" }

[products.collector]
boundary = "hub"

[products.collector.keys.SITE_SECRETS]
kind = "secret"
rules = { regex = "\\{[ -~]{1,65533}\\}" }

[producers.site-issuer]
command = ["python3", "-c", "pass"]
outputs = ["platform_site_id", "platform_site_key", "agency_site_id", "agency_site_key",
           "owner_site_id", "owner_site_key"]
timeout = "5m"

[sets.sites]
environments = ["staging"]

[sets.sites.members]
"shop/PLATFORM_IDENTITY_SECRET" = { generate = { hex_bytes = 32 } }
"shop/AGENCY_IDENTITY_SECRET"   = { generate = { hex_bytes = 32 } }
"shop/OWNER_IDENTITY_SECRET"    = { generate = { hex_bytes = 32 } }
"shop/SITES_GATEWAY_KEY"        = { generate = { hex_bytes = 32 } }
"shop/USER_HASH_KEY"            = { generate = { hex_bytes = 32 } }
"shop/PLATFORM_SITE_KEY" = { producer = "site-issuer", output = "platform_site_key" }
"shop/AGENCY_SITE_KEY"   = { producer = "site-issuer", output = "agency_site_key" }
"shop/OWNER_SITE_KEY"    = { producer = "site-issuer", output = "owner_site_key" }

[sets.sites.members."collector/SITE_SECRETS".template]
version = 1
sites = [
  { siteId = "${site-issuer.platform_site_id}", identitySecret = "${shop/PLATFORM_IDENTITY_SECRET}", gatewaySecret = "${shop/SITES_GATEWAY_KEY}" },
  { siteId = "${site-issuer.agency_site_id}",   identitySecret = "${shop/AGENCY_IDENTITY_SECRET}",   gatewaySecret = "${shop/SITES_GATEWAY_KEY}" },
  { siteId = "${site-issuer.owner_site_id}",    identitySecret = "${shop/OWNER_IDENTITY_SECRET}",    gatewaySecret = "${shop/SITES_GATEWAY_KEY}" },
]
"#;

fn bundle_key() -> KeyRef {
    KeyRef::parse("collector/SITE_SECRETS").unwrap()
}

/// The loaded bundle template of [`SITES`].
fn sites_template(fleet: &Fleet) -> Template {
    match &fleet.sets["sites"].members[&bundle_key()] {
        MemberSource::Template(t) => t.clone(),
        other => panic!("expected a template, got {other:?}"),
    }
}

/// [`SITES`] with its first site's `siteId` leaf replaced by `leaf`.
fn sites_with_leaf(leaf: &str) -> String {
    SITES.replacen(r#""${site-issuer.platform_site_id}""#, leaf, 1)
}

/// Test 11.
#[test]
fn the_three_site_bundle_set_loads() {
    assert!(parse(SITES).is_ok());
}

#[test]
fn a_loaded_template_keeps_its_declared_key_order() {
    let fleet = parse(SITES).unwrap();
    let Node::Table(root) = sites_template(&fleet).root().clone() else {
        panic!("expected a table");
    };
    let Node::Array(sites) = &root[1].1 else {
        panic!("expected an array");
    };
    let Node::Table(first) = &sites[0] else {
        panic!("expected a table");
    };
    let keys: Vec<&str> = first.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, ["siteId", "identitySecret", "gatewaySecret"]);
}

#[test]
fn a_loaded_template_holds_an_output_leaf() {
    let fleet = parse(SITES).unwrap();
    assert!(sites_template(&fleet).uses_output("site-issuer", "owner_site_id"));
}

#[test]
fn an_output_used_only_by_a_template_counts_as_used() {
    let fleet = parse(SITES).unwrap();
    assert_eq!(fleet.producers["site-issuer"].outputs.len(), 6);
}

/// Test 9.
#[test]
fn a_partially_interpolated_leaf_is_refused() {
    assert_eq!(
        refused_field(parse(&sites_with_leaf(r#""x${shop/SITES_GATEWAY_KEY}""#))).as_deref(),
        Some("sets.sites.members.collector/SITE_SECRETS.template.sites.0.siteId")
    );
}

#[test]
fn a_partially_interpolated_leaf_is_a_type_refusal() {
    assert!(matches!(
        refused_rule(parse(&sites_with_leaf(r#""x${shop/SITES_GATEWAY_KEY}""#))),
        Some(FieldRule::Type { .. })
    ));
}

/// Test 10.
#[test]
fn a_template_reference_cycle_is_refused() {
    let set = r#"
[sets.loop]
environments = ["prod"]

[sets.loop.members."app/PLAIN".template]
inner = "${app/CLIENT_ID}"

[sets.loop.members."app/CLIENT_ID".template]
inner = "${app/PLAIN}"
"#;
    assert!(matches!(
        refused_rule(load(set)),
        Some(FieldRule::Type { expected }) if expected.contains("does not reference itself")
    ));
}

#[test]
fn a_template_referencing_itself_is_refused() {
    let set = r#"
[sets.self]
environments = ["prod"]

[sets.self.members."app/PLAIN".template]
inner = "${app/PLAIN}"
"#;
    assert_eq!(
        refused_field(load(set)).as_deref(),
        Some("sets.self.members.app/PLAIN.template")
    );
}

#[test]
fn a_reference_to_a_key_outside_the_set_is_refused() {
    let set = r#"
[sets.outside]
environments = ["prod"]

[sets.outside.members."app/PLAIN".template]
inner = "${app/CLIENT_ID}"
"#;
    assert!(matches!(
        refused_rule(load(set)),
        Some(FieldRule::Check {
            check: ConfigCheck::Undeclared { .. }
        })
    ));
}

#[test]
fn a_reference_to_an_undeclared_producer_is_refused() {
    assert!(matches!(
        refused_rule(parse(&sites_with_leaf(r#""${nobody.platform_site_id}""#))),
        Some(FieldRule::Check {
            check: ConfigCheck::Undeclared { .. }
        })
    ));
}

#[test]
fn a_reference_to_an_undeclared_output_is_refused() {
    assert!(matches!(
        refused_rule(parse(&sites_with_leaf(r#""${site-issuer.site_id}""#))),
        Some(FieldRule::Check {
            check: ConfigCheck::ProducerOutputUndeclared { .. }
        })
    ));
}

#[test]
fn a_malformed_reference_is_refused() {
    assert!(matches!(
        refused_rule(parse(&sites_with_leaf(r#""${justaname}""#))),
        Some(FieldRule::Type { .. })
    ));
}

#[test]
fn a_float_in_a_template_is_refused() {
    let fleet = parse(&SITES.replace("version = 1\n", "version = 1.0\n"));
    assert_eq!(
        refused_field(fleet).as_deref(),
        Some("sets.sites.members.collector/SITE_SECRETS.template.version")
    );
}

#[test]
fn a_template_with_generate_is_refused() {
    let set = r#"
[sets.both]
environments = ["prod"]

[sets.both.members."app/PLAIN"]
generate = { hex_bytes = 32 }
template = { inner = "lit" }
"#;
    assert!(matches!(
        refused_rule(load(set)),
        Some(FieldRule::ConflictsWith { .. })
    ));
}

#[test]
fn a_template_on_a_config_key_is_refused() {
    let set = r#"
[products.app.keys.SETTING]
kind = "config"

[sets.cfg]
environments = ["prod"]

[sets.cfg.members."app/SETTING".template]
inner = "lit"
"#;
    assert_eq!(
        refused_field(load(set)).as_deref(),
        Some("sets.cfg.members.app/SETTING.template")
    );
}

#[test]
fn a_reference_in_a_table_key_is_refused() {
    let set = r#"
[sets.keyref]
environments = ["prod"]

[sets.keyref.members."app/PLAIN".template]
"${app/PLAIN}" = "lit"
"#;
    assert!(matches!(
        refused_rule(load(set)),
        Some(FieldRule::Type { .. })
    ));
}
