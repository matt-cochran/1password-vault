//! Settings health (#92): one behaviour per test. Every value holds [`MARK`]; no message
//! may contain it.

use super::*;
use crate::domain::SecretValue;

const MARK: &str = "HEALTHMARK";

/// Fleet profile: api/DATABASE_URL and api/STRIPE_KEY (secrets) and api/PUBLIC_URL
/// (config) in dev, staging and prod; api/OPENAI (personal, dev); api/SHARED (secret,
/// allow_same_value); api/OTHER (secret, dev and prod). prod and staging deploy.
fn fleet() -> Fleet {
    crate::config::parse(
        r#"[profile]
kind = "fleet"

[environments.dev]
vault_id = "v1"
item_id = "i1"

[environments.staging]
vault_id = "v2"
item_id = "i2"

[environments.prod]
vault_id = "v3"
item_id = "i3"

[products.api.keys.DATABASE_URL]
kind = "secret"
environments = ["dev", "staging", "prod"]

[products.api.keys.STRIPE_KEY]
kind = "secret"
environments = ["dev", "staging", "prod"]

[products.api.keys.PUBLIC_URL]
kind = "config"
environments = ["dev", "staging", "prod"]

[products.api.keys.OPENAI]
kind = "secret"
environments = ["dev"]
personal = true

[products.api.keys.SHARED]
kind = "secret"
environments = ["dev", "prod"]
allow_same_value = true

[products.api.keys.OTHER]
kind = "secret"
environments = ["dev", "prod"]
"#,
    )
    .unwrap()
}

fn field(key: &str, kind: Kind, value: &str) -> ItemField {
    ItemField {
        section: "api".into(),
        label: key.into(),
        kind,
        value: SecretValue::new(value.to_string()),
        concealed: kind == Kind::Secret,
    }
}

fn secret(key: &str, value: &str) -> ItemField {
    field(key, Kind::Secret, value)
}

/// Findings for `envs` given as (name, deployed, fields).
fn run(envs: &[(&str, bool, Vec<ItemField>)]) -> Vec<HealthFinding> {
    let fleet = fleet();
    let values: Vec<EnvValues<'_>> = envs
        .iter()
        .map(|(name, deployed, fields)| EnvValues {
            name,
            title: None,
            deployed: *deployed,
            fields,
        })
        .collect();
    check(&fleet, &values)
}

fn codes(envs: &[(&str, bool, Vec<ItemField>)]) -> Vec<&'static str> {
    run(envs).into_iter().map(|f| f.code).collect()
}

fn v(s: &str) -> String {
    format!("{s}-{MARK}")
}

// same_value_across_environments ----------------------------------------------------

#[test]
fn a_secret_with_the_same_value_in_two_environments_is_found() {
    let same = v("pw");
    assert_eq!(
        codes(&[
            ("dev", false, vec![secret("DATABASE_URL", &same)]),
            ("prod", true, vec![secret("DATABASE_URL", &same)]),
        ]),
        [SAME_ACROSS]
    );
}

#[test]
fn the_finding_names_both_environments_in_order() {
    let same = v("pw");
    let f = run(&[
        ("dev", false, vec![secret("DATABASE_URL", &same)]),
        ("prod", true, vec![secret("DATABASE_URL", &same)]),
    ]);
    assert_eq!(f[0].environments, ["dev", "prod"]);
}

#[test]
fn only_the_environments_sharing_the_value_are_named() {
    let same = v("pw");
    let f = run(&[
        ("dev", false, vec![secret("DATABASE_URL", &same)]),
        ("staging", true, vec![secret("DATABASE_URL", &v("other"))]),
        ("prod", true, vec![secret("DATABASE_URL", &same)]),
    ]);
    assert_eq!(f[0].environments, ["dev", "prod"]);
}

#[test]
fn different_values_across_environments_are_fine() {
    assert!(
        codes(&[
            ("dev", false, vec![secret("DATABASE_URL", &v("a"))]),
            ("prod", true, vec![secret("DATABASE_URL", &v("b"))]),
        ])
        .is_empty()
    );
}

#[test]
fn a_config_value_may_be_the_same_everywhere() {
    let same = "https://example.org";
    assert!(
        codes(&[
            ("dev", false, vec![field("PUBLIC_URL", Kind::Config, same)]),
            ("prod", true, vec![field("PUBLIC_URL", Kind::Config, same)]),
        ])
        .is_empty()
    );
}

#[test]
fn allow_same_value_silences_the_finding() {
    let same = v("shared");
    assert!(
        codes(&[
            ("dev", false, vec![secret("SHARED", &same)]),
            ("prod", true, vec![secret("SHARED", &same)]),
        ])
        .is_empty()
    );
}

#[test]
fn empty_values_are_never_the_same_value() {
    assert!(
        codes(&[
            ("dev", false, vec![secret("DATABASE_URL", "")]),
            ("prod", true, vec![secret("DATABASE_URL", "")]),
        ])
        .is_empty()
    );
}

#[test]
fn a_field_in_an_environment_the_key_does_not_list_is_ignored() {
    let same = v("pw");
    assert!(
        codes(&[
            ("staging", true, vec![secret("OTHER", &same)]),
            ("prod", true, vec![secret("OTHER", &same)]),
        ])
        .is_empty()
    );
}

// same_value_under_two_keys ---------------------------------------------------------

#[test]
fn two_secrets_with_one_value_in_an_environment_are_found() {
    let same = v("dup");
    assert_eq!(
        codes(&[(
            "dev",
            false,
            vec![secret("DATABASE_URL", &same), secret("STRIPE_KEY", &same)]
        )]),
        [SAME_UNDER_TWO]
    );
}

#[test]
fn the_second_key_is_named() {
    let same = v("dup");
    let f = run(&[(
        "dev",
        false,
        vec![secret("DATABASE_URL", &same), secret("STRIPE_KEY", &same)],
    )]);
    assert_eq!(
        f[0].other,
        Some(("api".to_string(), "STRIPE_KEY".to_string()))
    );
}

#[test]
fn an_undeclared_field_is_never_compared() {
    let same = v("dup");
    assert!(
        codes(&[(
            "dev",
            false,
            vec![secret("DATABASE_URL", &same), secret("NOT_DECLARED", &same)]
        )])
        .is_empty()
    );
}

#[test]
fn a_personal_key_is_never_compared() {
    let same = v("dup");
    assert!(
        codes(&[(
            "dev",
            false,
            vec![secret("DATABASE_URL", &same), secret("OPENAI", &same)]
        )])
        .is_empty()
    );
}

// placeholder_value -------------------------------------------------------------------

#[test]
fn changeme_is_a_placeholder() {
    assert_eq!(
        codes(&[("dev", false, vec![secret("STRIPE_KEY", "changeme")])]),
        [PLACEHOLDER]
    );
}

#[test]
fn a_run_of_x_is_a_placeholder() {
    assert_eq!(
        codes(&[("dev", false, vec![secret("STRIPE_KEY", "xxxxxx")])]),
        [PLACEHOLDER]
    );
}

#[test]
fn angle_brackets_are_a_placeholder() {
    assert_eq!(
        codes(&[("dev", false, vec![secret("STRIPE_KEY", "<stripe key>")])]),
        [PLACEHOLDER]
    );
}

#[test]
fn your_key_here_is_a_placeholder() {
    assert_eq!(
        codes(&[(
            "dev",
            false,
            vec![secret("STRIPE_KEY", "your_api_key_here")]
        )]),
        [PLACEHOLDER]
    );
}

#[test]
fn a_config_word_is_not_a_placeholder() {
    assert!(
        codes(&[(
            "dev",
            false,
            vec![field("PUBLIC_URL", Kind::Config, "none")]
        )])
        .is_empty()
    );
}

#[test]
fn a_real_looking_secret_is_not_a_placeholder() {
    assert!(codes(&[("dev", false, vec![secret("STRIPE_KEY", &v("rk_abc"))])]).is_empty());
}

// whitespace_around_value -------------------------------------------------------------

#[test]
fn a_trailing_space_is_found() {
    assert_eq!(
        codes(&[(
            "dev",
            false,
            vec![secret("STRIPE_KEY", &format!("{} ", v("k")))]
        )]),
        [WHITESPACE]
    );
}

#[test]
fn a_trailing_newline_on_one_line_is_found() {
    assert_eq!(
        codes(&[(
            "dev",
            false,
            vec![secret("STRIPE_KEY", &format!("{}\n", v("k")))]
        )]),
        [WHITESPACE]
    );
}

#[test]
fn a_config_value_with_a_leading_space_is_found() {
    assert_eq!(
        codes(&[(
            "dev",
            false,
            vec![field("PUBLIC_URL", Kind::Config, " https://x.org")]
        )]),
        [WHITESPACE]
    );
}

#[test]
fn a_multi_line_value_is_left_alone() {
    let pem = format!("-----BEGIN KEY-----\n{MARK}\n-----END KEY-----\n");
    assert!(codes(&[("dev", false, vec![secret("STRIPE_KEY", &pem)])]).is_empty());
}

// local_address_in_deployed_environment -----------------------------------------------

#[test]
fn localhost_in_a_deployed_environment_is_found() {
    assert_eq!(
        codes(&[(
            "staging",
            true,
            vec![field("PUBLIC_URL", Kind::Config, "http://localhost:3000")]
        )]),
        [LOCAL_ADDRESS]
    );
}

#[test]
fn a_loopback_address_in_a_secret_is_found() {
    assert_eq!(
        codes(&[(
            "prod",
            true,
            vec![secret(
                "DATABASE_URL",
                &format!("postgres://u:{MARK}@127.0.0.1/db")
            )]
        )]),
        [LOCAL_ADDRESS]
    );
}

#[test]
fn localhost_in_a_local_environment_is_fine() {
    assert!(
        codes(&[(
            "dev",
            false,
            vec![field("PUBLIC_URL", Kind::Config, "http://localhost:3000")]
        )])
        .is_empty()
    );
}

// test_key_in_production / live_key_outside_production --------------------------------

#[test]
fn a_test_key_in_production_is_found() {
    assert_eq!(
        codes(&[("prod", true, vec![secret("STRIPE_KEY", &v("sk_test_"))])]),
        [TEST_KEY]
    );
}

#[test]
fn a_test_key_in_staging_is_fine() {
    assert!(codes(&[("staging", true, vec![secret("STRIPE_KEY", &v("sk_test_"))])]).is_empty());
}

#[test]
fn a_production_title_counts_as_production() {
    let fleet = fleet();
    let fields = vec![secret("STRIPE_KEY", &v("sk_test_"))];
    let found = check(
        &fleet,
        &[EnvValues {
            name: "staging",
            title: Some("Production (EU)"),
            deployed: true,
            fields: &fields,
        }],
    );
    assert_eq!(found[0].code, TEST_KEY);
}

#[test]
fn preprod_is_not_production() {
    let fleet = fleet();
    let fields = vec![secret("STRIPE_KEY", &v("sk_live_"))];
    let found = check(
        &fleet,
        &[EnvValues {
            name: "staging",
            title: Some("Preprod"),
            deployed: true,
            fields: &fields,
        }],
    );
    assert_eq!(found[0].code, LIVE_KEY);
}

#[test]
fn a_live_key_in_development_is_found() {
    assert_eq!(
        codes(&[("dev", false, vec![secret("STRIPE_KEY", &v("sk_live_"))])]),
        [LIVE_KEY]
    );
}

#[test]
fn a_live_key_in_production_is_fine() {
    assert!(codes(&[("prod", true, vec![secret("STRIPE_KEY", &v("sk_live_"))])]).is_empty());
}

// Order and values ----------------------------------------------------------------------

#[test]
fn findings_come_in_code_order() {
    let same = v("pw");
    assert_eq!(
        codes(&[
            (
                "dev",
                false,
                vec![
                    secret("STRIPE_KEY", "changeme"),
                    secret("DATABASE_URL", &same)
                ]
            ),
            ("prod", true, vec![secret("DATABASE_URL", &same)]),
        ]),
        [SAME_ACROSS, PLACEHOLDER]
    );
}

#[test]
fn no_message_ever_holds_a_value() {
    let same = v("pw");
    let found = run(&[
        (
            "dev",
            false,
            vec![
                secret("DATABASE_URL", &same),
                secret("STRIPE_KEY", &same),
                secret("OTHER", &format!("{} ", v("sk_live_"))),
            ],
        ),
        (
            "prod",
            true,
            vec![
                secret("DATABASE_URL", &same),
                secret("STRIPE_KEY", &format!("sk_test_{MARK}")),
                field(
                    "PUBLIC_URL",
                    Kind::Config,
                    &format!("http://localhost/{MARK}"),
                ),
            ],
        ),
    ]);
    assert!(
        found.len() >= 6 && found.iter().all(|f| !f.message.contains(MARK)),
        "{found:?}"
    );
}

#[test]
fn nothing_declared_means_nothing_found() {
    assert!(codes(&[]).is_empty());
}
