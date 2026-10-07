//! `secrets.toml` loading and validation (FR-1, FR-2, §10.2).
//!
//! Validation runs before any secret operation; errors name the offending environment,
//! product, key or rule. The file holds IDs and rules only, never values.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::domain::{Environment, Fleet, Product};
use crate::error::Error;

/// Read and validate the configuration at `path`.
pub fn load(path: impl AsRef<Path>) -> Result<Fleet, Error> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
    parse(&text)
}

/// Parse and validate configuration text.
pub fn parse(text: &str) -> Result<Fleet, Error> {
    let raw: RawConfig =
        toml::from_str(text).map_err(|e| Error::Config(format!("invalid secrets.toml: {e}")))?;
    validate(raw)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    profile: RawProfile,
    environments: BTreeMap<String, RawEnvironment>,
    #[serde(default)]
    products: BTreeMap<String, Product>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvironment {
    vault_id: String,
    item_id: String,
    fly: RawFly,
    #[serde(default)]
    modes: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFly {
    app: String,
    secret_name: String,
}

fn cfg(msg: String) -> Error {
    Error::Config(msg)
}

fn validate(raw: RawConfig) -> Result<Fleet, Error> {
    if raw.profile.kind != "fleet" {
        return Err(cfg(format!(
            "profile.kind must be \"fleet\", got {:?}",
            raw.profile.kind
        )));
    }
    if raw.environments.is_empty() {
        return Err(cfg("no environments defined".into()));
    }

    let mut environments = BTreeMap::new();
    for (name, e) in raw.environments {
        for (field, value) in [
            ("vault_id", &e.vault_id),
            ("item_id", &e.item_id),
            ("fly.app", &e.fly.app),
        ] {
            if value.trim().is_empty() {
                return Err(cfg(format!("environment {name}: {field} is empty")));
            }
        }
        let t = &e.fly.secret_name;
        if !t.contains("{PRODUCT}") || !t.contains("{KEY}") {
            return Err(cfg(format!(
                "environment {name}: fly.secret_name {t:?} must contain {{PRODUCT}} and {{KEY}}"
            )));
        }
        environments.insert(
            name,
            Environment {
                vault_id: e.vault_id,
                item_id: e.item_id,
                fly_app: e.fly.app,
                secret_name_template: e.fly.secret_name,
                modes: e.modes,
            },
        );
    }

    for (product, p) in &raw.products {
        if !is_product_name(product) {
            return Err(cfg(format!(
                "product {product:?}: name must match ^[a-z][a-z0-9_-]*$"
            )));
        }
        for (key, spec) in &p.keys {
            if !is_env_name(key) {
                return Err(cfg(format!(
                    "{product}/{key}: key name must match ^[A-Z][A-Z0-9_]*$"
                )));
            }
            for env in &spec.environments {
                if !environments.contains_key(env) {
                    return Err(cfg(format!(
                        "{product}/{key}: undefined environment {env:?}"
                    )));
                }
            }
            if let Some(re) = &spec.rules.regex {
                regex::Regex::new(re).map_err(|e| {
                    cfg(format!("{product}/{key}: rule regex does not compile: {e}"))
                })?;
            }
        }
    }

    Ok(Fleet {
        environments,
        products: raw.products,
    })
}

fn is_env_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some('A'..='Z'))
        && c.all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

fn is_product_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some('a'..='z'))
        && c.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Kind;
    const OK: &str = include_str!("../tests/fixtures/secrets.toml");
    #[test]
    fn loads_fleet_profile_and_builds_fly_names() {
        let f = parse(OK).unwrap();
        assert_eq!(
            f.fly_name("prod", "allumata", "OPENAI_API_KEY"),
            "FLEET__ALLUMATA__OPENAI_API_KEY"
        );
        assert_eq!(
            f.products["allumata"].keys["SIGNUP_POLICY"].kind,
            Kind::Config
        );
        assert!(f.products["allumata"].keys["INTEGRATION_ENC_KEY"].immutable);
    }
    #[test]
    fn rejects_key_for_undefined_environment() {
        let bad = OK.replace(r#"environments = ["prod"]"#, r#"environments = ["qa"]"#);
        assert!(matches!(parse(&bad), Err(Error::Config(m)) if m.contains("qa")));
    }
    #[test]
    fn rejects_template_without_placeholders() {
        let bad = OK.replace("FLEET__{PRODUCT}__{KEY}", "FLEET_STATIC");
        assert!(matches!(parse(&bad), Err(Error::Config(_))));
    }
    #[test]
    fn rejects_non_env_name_keys() {
        let bad = OK.replace(
            "[products.allumata.keys.OPENAI_API_KEY]",
            "[products.allumata.keys.openai-key]",
        );
        assert!(matches!(parse(&bad), Err(Error::Config(_))));
    }

    fn config_err(text: &str) -> String {
        match parse(text) {
            Err(Error::Config(m)) => m,
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn parses_full_model() {
        let f = parse(OK).unwrap();
        let prod = &f.environments["prod"];
        assert_eq!(prod.vault_id, "vprd");
        assert_eq!(prod.item_id, "iprd");
        assert_eq!(prod.fly_app, "mcproductlabs-portfolio-production");
        assert_eq!(prod.modes["allumata"]["payments"], "off");
        assert_eq!(
            f.environments["staging"].modes["allumata"]["payments"],
            "test"
        );
        let keys = &f.products["allumata"].keys;
        assert_eq!(keys.len(), 4);
        let openai = &keys["OPENAI_API_KEY"];
        assert_eq!(openai.kind, Kind::Secret);
        assert_eq!(openai.environments, vec!["prod"]);
        assert_eq!(openai.rules.prefix.as_deref(), Some("sk-"));
        assert_eq!(openai.rules.not_prefix.as_deref(), Some("sk-or-"));
        assert!(!openai.immutable);
        assert_eq!(openai.guidance, "OpenAI platform / API keys");
        assert_eq!(keys["INTEGRATION_ENC_KEY"].rules.base64_bytes, Some(32));
        let pbm = keys["STRIPE_SECRET_KEY"]
            .rules
            .prefix_by_mode
            .as_ref()
            .unwrap();
        assert_eq!(pbm.mode, "payments");
        assert_eq!(pbm.values["test"], "sk_test_");
        assert_eq!(pbm.values["live"], "sk_live_");
        assert_eq!(pbm.skip, vec!["off", "external"]);
        assert_eq!(
            keys["SIGNUP_POLICY"].rules.r#enum,
            Some(vec!["open".to_string(), "invite_only".to_string()])
        );
    }

    #[test]
    fn rejects_non_fleet_profile() {
        let m = config_err(&OK.replace(r#"kind = "fleet""#, r#"kind = "simple""#));
        assert!(m.contains("profile.kind"), "{m}");
    }

    #[test]
    fn rejects_unknown_fields_and_rules() {
        config_err(&OK.replace("immutable = true", "immutible = true"));
        config_err(&OK.replace("base64_bytes = 32", "base64_len = 32"));
        config_err(&OK.replace("vault_id = \"vprd\"", "vault_id = \"vprd\"\nvault = \"x\""));
    }

    #[test]
    fn rejects_unknown_kind() {
        config_err(&OK.replace(r#"kind = "config""#, r#"kind = "text""#));
    }

    #[test]
    fn rejects_bad_product_name() {
        let m = config_err(&OK.replace("products.allumata.", "products.Allumata."));
        assert!(m.contains("Allumata"), "{m}");
    }

    #[test]
    fn rejects_missing_or_empty_fly_config() {
        let m = config_err(&OK.replace(r#"item_id = "iprd""#, r#"item_id = """#));
        assert!(m.contains("prod") && m.contains("item_id"), "{m}");
        config_err(&OK.replace("fly.app = \"mcproductlabs-portfolio-production\"\n", ""));
    }

    #[test]
    fn rejects_template_missing_one_placeholder() {
        config_err(&OK.replace("FLEET__{PRODUCT}__{KEY}", "FLEET__{KEY}"));
        config_err(&OK.replace("FLEET__{PRODUCT}__{KEY}", "FLEET__{PRODUCT}"));
    }

    #[test]
    fn rejects_regex_that_does_not_compile_naming_key() {
        let m = config_err(&OK.replace(
            r#"rules = { base64_bytes = 32 }"#,
            r#"rules = { regex = "([a-z" }"#,
        ));
        assert!(m.contains("allumata/INTEGRATION_ENC_KEY"), "{m}");
    }

    #[test]
    fn load_reads_file_and_reports_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("secrets.toml");
        std::fs::write(&p, OK).unwrap();
        assert!(load(&p).is_ok());
        let missing = dir.path().join("nope.toml");
        assert!(matches!(load(&missing), Err(Error::Config(m)) if m.contains("nope.toml")));
    }

    #[test]
    fn name_validators() {
        assert!(is_env_name("A") && is_env_name("OPENAI_API_KEY") && is_env_name("K2"));
        assert!(
            !is_env_name("") && !is_env_name("_A") && !is_env_name("1A") && !is_env_name("A-B")
        );
        assert!(!is_env_name("Abc"));
        assert!(is_product_name("allumata") && is_product_name("my-app_2"));
        assert!(!is_product_name("") && !is_product_name("-a") && !is_product_name("App"));
    }
}
