//! `explain <product>/<key> [--env <env>]` use case (FR-22); `explain <KEY>` under the
//! simple profile (FR-20).
//!
//! Reads only the configuration: no 1Password or target call, so it takes no runner at all
//! and cannot emit a value or a value fragment (SR-1, §5). It is not a `secret get`.
//!
//! For the environment named by `--env` (or the only one declared, when `--env` is
//! omitted) it prints the `op://` reference, the field kind, the target's names, the declared
//! rules, `immutable` and `guidance`, plus the `op item get <item_id> --vault <vault_id>`
//! command a person can run to inspect the field in their own terminal. That command never
//! contains `--reveal`.
//!
//! An undeclared product, key or environment is `Error::Config` (exit 2).

use std::io::Write;

use super::{kind_label, write_err};
use crate::adapters::registry;
use crate::domain::model::{KeySpec, Kind, OneOrMany, Rules, SIMPLE_PRODUCT, key_label};
use crate::domain::{Fleet, rules};
use crate::error::Error;

/// The key `explain` was asked about, resolved against the configuration.
///
/// The fleet profile takes `<product>/<key>`; the simple profile (FR-20) takes the bare
/// `<KEY>` and resolves it to its implicit product in [`resolve`]. Everything after
/// resolution is shared.
struct Target<'a> {
    product: &'a str,
    key: &'a str,
    spec: &'a KeySpec,
}

pub fn run(
    fleet: &Fleet,
    target: &str,
    env: Option<&str>,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let t = resolve(fleet, target)?;
    let env_name = environment(fleet, &t, env)?;
    explain_in(fleet, &t, env_name, out)
}

/// Resolve the target to a declared key: `<product>/<key>` under the fleet profile, `<KEY>`
/// under the simple profile. The other profile's form is a configuration error.
fn resolve<'a>(fleet: &'a Fleet, target: &str) -> Result<Target<'a>, Error> {
    if fleet.is_simple() {
        if target.contains('/') {
            return Err(Error::Config(format!(
                "explain expects <KEY> under the simple profile, got {target:?}"
            )));
        }
        let keys = fleet.products.get(SIMPLE_PRODUCT).map(|p| &p.keys);
        let Some((key, spec)) = keys.and_then(|k| k.get_key_value(target)) else {
            return Err(Error::Config(format!("undeclared key {target:?}")));
        };
        return Ok(Target {
            product: SIMPLE_PRODUCT,
            key,
            spec,
        });
    }
    let Some((product, key)) = target.split_once('/') else {
        return Err(Error::Config(format!(
            "explain expects <product>/<key>, got {target:?}"
        )));
    };
    let Some((product, p)) = fleet.products.get_key_value(product) else {
        let known: Vec<&str> = fleet.products.keys().map(String::as_str).collect();
        return Err(Error::Config(format!(
            "undeclared product {product:?} (declared: {})",
            known.join(", ")
        )));
    };
    let Some((key, spec)) = p.keys.get_key_value(key) else {
        return Err(Error::Config(format!(
            "undeclared key {key:?} in product {product}"
        )));
    };
    Ok(Target { product, key, spec })
}

/// The environment to explain: `--env` when given (it must be defined and the key declared
/// for it), otherwise the only environment the configuration declares.
fn environment<'a>(
    fleet: &'a Fleet,
    t: &Target<'_>,
    env: Option<&'a str>,
) -> Result<&'a str, Error> {
    let name = match env {
        Some(e) => {
            fleet.environment(e)?;
            e
        }
        None => {
            let mut names = fleet.environments.keys();
            match (names.next(), names.next()) {
                (Some(only), None) => only.as_str(),
                _ => {
                    let known: Vec<&str> = fleet.environments.keys().map(String::as_str).collect();
                    return Err(Error::Config(format!(
                        "several environments are declared ({}): pass --env <environment>",
                        known.join(", ")
                    )));
                }
            }
        }
    };
    if !t.spec.environments.iter().any(|e| e == name) {
        return Err(Error::Config(format!(
            "{} is not declared for environment {name:?} (declared for: {})",
            key_label(t.product, t.key),
            t.spec.environments.join(", ")
        )));
    }
    Ok(name)
}

fn explain_in(
    fleet: &Fleet,
    t: &Target<'_>,
    env_name: &str,
    out: &mut dyn Write,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    let (product, key, spec) = (t.product, t.key, t.spec);
    let field = match spec.kind {
        Kind::Secret => "concealed field",
        Kind::Config => "text field",
    };
    // Without a target, the lines name the default provider (FR-37).
    let label_of = env
        .target()
        .map_or(registry::DEFAULT.label(), |t| t.provider().label());
    let name_label = format!("{} name", label_of.to_lowercase());
    let target_lines: Vec<(String, String)> = match (spec.kind, env.target()) {
        (Kind::Config, _) => vec![(name_label, format!("- (config: not a {label_of} secret)"))],
        (Kind::Secret, Some(t)) => t
            .explain(product, key)
            .into_iter()
            .map(|(l, v)| (l.to_string(), v))
            .collect(),
        (Kind::Secret, None) => vec![(
            name_label,
            format!(
                "- (environment has no {} section)",
                registry::DEFAULT.section()
            ),
        )],
    };
    let rules = describe_rules(&spec.rules);
    let guidance = if spec.guidance.is_empty() {
        "-"
    } else {
        spec.guidance.as_str()
    };
    // Simple-profile fields are unsectioned: `op://<vault>/<item>/<KEY>`.
    let label = key_label(product, key);
    let mut lines = vec![
        format!("{label} in {env_name}"),
        format!(
            "  reference:  op://{}/{}/{label}",
            env.vault_id, env.item_id
        ),
        format!("  kind:       {} ({field})", kind_label(spec.kind)),
    ];
    for (l, v) in target_lines {
        lines.push(format!("  {:<11} {v}", format!("{l}:")));
    }
    lines.extend([
        format!(
            "  rules:      {}",
            if rules.is_empty() {
                "-".to_string()
            } else {
                rules.join(", ")
            }
        ),
        format!(
            "  immutable:  {}",
            if spec.immutable { "yes" } else { "no" }
        ),
        format!("  guidance:   {guidance}"),
    ]);
    if !rules::applies(spec, env_name, env, product) {
        lines.push("  note:       not required here (its prefix_by_mode mode is skipped)".into());
    }
    lines.push(format!(
        "  inspect:    {}",
        inspect_command(&env.item_id, &env.vault_id)
    ));
    for l in lines {
        writeln!(out, "{l}").map_err(write_err)?;
    }
    Ok(())
}

/// The `op` command a person can run to look at the item themselves. Never `--reveal`.
fn inspect_command(item_id: &str, vault_id: &str) -> String {
    format!("op item get {item_id} --vault {vault_id}")
}

/// The declared rules as `name = value`, from the configuration only.
fn describe_rules(r: &Rules) -> Vec<String> {
    fn list(v: &OneOrMany) -> String {
        let items: Vec<String> = v.iter().map(|s| format!("{s:?}")).collect();
        match v {
            OneOrMany::One(_) => items.join(", "),
            OneOrMany::Many(_) => format!("[{}]", items.join(", ")),
        }
    }
    // Exhaustive on purpose (no `..`): a new rule field fails to compile here until
    // explain shows it.
    let Rules {
        prefix,
        not_prefix,
        ensure_prefix,
        pattern,
        regex,
        r#enum,
        base64_bytes,
        hex_bytes,
        email_list,
        https_url,
        prefix_by_mode,
        refuse_in,
        transform,
    } = r;
    let mut out = Vec::new();
    if let Some(p) = prefix {
        out.push(format!("prefix = {p:?}"));
    }
    if let Some(p) = not_prefix {
        out.push(format!("not_prefix = {}", list(p)));
    }
    if let Some(p) = prefix_by_mode {
        let values: Vec<String> = p
            .values
            .iter()
            .map(|(m, v)| format!("{m} = {}", list(v)))
            .collect();
        let mut s = format!(
            "prefix_by_mode = {{ mode = {:?}, values = {{ {} }}",
            p.mode,
            values.join(", ")
        );
        if !p.skip.is_empty() {
            s.push_str(&format!(", skip = {:?}", p.skip));
        }
        s.push_str(" }");
        out.push(s);
    }
    if let Some(p) = ensure_prefix {
        out.push(format!("ensure_prefix = {p:?}"));
    }
    if let Some(p) = pattern {
        out.push(format!("pattern = {p:?}"));
    }
    if let Some(p) = regex {
        out.push(format!("regex = {p:?}"));
    }
    if let Some(v) = r#enum {
        out.push(format!("enum = {v:?}"));
    }
    if let Some(n) = *base64_bytes {
        out.push(format!("base64_bytes = {n}"));
    }
    if let Some(n) = *hex_bytes {
        out.push(format!("hex_bytes = {n}"));
    }
    if *email_list {
        out.push("email_list = true".into());
    }
    if *https_url {
        out.push("https_url = true".into());
    }
    if !refuse_in.is_empty() {
        out.push(format!("refuse_in = {:?}", refuse_in));
    }
    if let Some(t) = transform {
        out.push(format!("transform = {t:?}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testutil::*;

    fn explain(fleet: &Fleet, target: &str, env: Option<&str>) -> Result<String, Error> {
        let mut out = Vec::new();
        run(fleet, target, env, &mut out).map(|()| text_of(&out))
    }

    fn openai_prod() -> String {
        explain(&fleet(), "allumata/OPENAI_API_KEY", Some("prod")).unwrap()
    }

    fn single_env() -> Fleet {
        crate::config::parse(
            "[profile]\nkind = \"fleet\"\n\
             [environments.prod]\nvault_id = \"vprd\"\nitem_id = \"iprd\"\n\
             fly.app = \"a\"\nfly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"\n\
             [products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n",
        )
        .unwrap()
    }

    #[test]
    fn prints_the_op_reference() {
        assert!(
            openai_prod().contains("reference:  op://vprd/iprd/allumata/OPENAI_API_KEY"),
            "{}",
            openai_prod()
        );
    }

    #[test]
    fn prints_the_field_kind() {
        assert!(openai_prod().contains("kind:       secret (concealed field)"));
    }

    /// FR-37: a provider's own explain lines stay readable when a label is wider than the
    /// column.
    #[test]
    fn prints_the_key_vault_name_of_an_azure_target() {
        let fleet = crate::config::parse(
            "[profile]\nkind = \"fleet\"\n\
             [environments.prod]\nvault_id = \"vprd\"\nitem_id = \"iprd\"\n\
             [environments.prod.azure]\nkey_vault = \"kv\"\nresource_group = \"rg\"\n\
             container_app = \"ca\"\nidentity = \"system\"\n\
             env_name = \"FLEET__{PRODUCT}__{KEY}\"\n\
             [products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n",
        )
        .unwrap();
        let out = explain(&fleet, "api/TOKEN", Some("prod")).unwrap();
        assert!(
            out.contains("  key vault name: FLEET--API--TOKEN\n"),
            "{out}"
        );
    }

    #[test]
    fn prints_the_fly_name() {
        assert!(openai_prod().contains("fly name:   FLEET__ALLUMATA__OPENAI_API_KEY"));
    }

    #[test]
    fn prints_the_declared_rules() {
        assert!(
            openai_prod().contains(r#"rules:      prefix = "sk-", not_prefix = "sk-or-""#),
            "{}",
            openai_prod()
        );
    }

    fn rules_line(extra: &str) -> String {
        let f = fleet_with(&format!(
            "[products.extra.keys.K]\nkind = \"secret\"\nenvironments = [\"prod\"]\nrules = {{ {extra} }}\n"
        ));
        let out = explain(&f, "extra/K", Some("prod")).unwrap();
        out.lines()
            .find_map(|l| l.strip_prefix("  rules:      "))
            .unwrap()
            .to_string()
    }

    #[test]
    fn prints_ensure_prefix_and_pattern() {
        assert_eq!(
            rules_line(r#"ensure_prefix = "sk-", pattern = "[a-z]+""#),
            r#"ensure_prefix = "sk-", pattern = "[a-z]+""#
        );
    }

    #[test]
    fn prints_prefix_by_mode() {
        assert_eq!(
            rules_line(
                r#"prefix_by_mode = { mode = "payments", values = { live = ["sk_live_", "rk_live_"], test = "sk_test_" }, skip = ["off"] }"#
            ),
            r#"prefix_by_mode = { mode = "payments", values = { live = ["sk_live_", "rk_live_"], test = "sk_test_" }, skip = ["off"] }"#
        );
    }

    #[test]
    fn prints_transform() {
        assert_eq!(
            rules_line(r#"transform = "pem_private_key""#),
            r#"transform = "pem_private_key""#
        );
    }

    #[test]
    fn prints_value_shape_rules() {
        assert_eq!(
            rules_line(r#"base64_bytes = 32, email_list = true, https_url = true, enum = ["a"]"#),
            r#"enum = ["a"], base64_bytes = 32, email_list = true, https_url = true"#
        );
    }

    #[test]
    fn prints_no_rules_as_dash() {
        let f =
            fleet_with("[products.extra.keys.K]\nkind = \"secret\"\nenvironments = [\"prod\"]\n");
        let out = explain(&f, "extra/K", Some("prod")).unwrap();
        assert!(out.contains("\n  rules:      -\n"), "{out}");
    }

    #[test]
    fn prints_immutable() {
        let out = explain(&fleet(), "allumata/INTEGRATION_ENC_KEY", Some("prod")).unwrap();
        assert!(out.contains("immutable:  yes"), "{out}");
    }

    #[test]
    fn prints_guidance() {
        assert!(openai_prod().contains("guidance:   OpenAI platform / API keys"));
    }

    #[test]
    fn prints_op_item_get_with_item_and_vault_ids() {
        assert!(openai_prod().contains("inspect:    op item get iprd --vault vprd"));
    }

    #[test]
    fn op_command_never_contains_reveal() {
        for (target, env) in [
            ("allumata/OPENAI_API_KEY", "prod"),
            ("allumata/SIGNUP_POLICY", "staging"),
            ("allumata/STRIPE_SECRET_KEY", "prod"),
        ] {
            let out = explain(&fleet(), target, Some(env)).unwrap();
            assert!(!out.contains("--reveal"), "{out}");
        }
    }

    #[test]
    fn config_key_has_no_fly_name() {
        let out = explain(&fleet(), "allumata/SIGNUP_POLICY", Some("prod")).unwrap();
        assert!(
            out.contains("fly name:   - (config: not a Fly secret)"),
            "{out}"
        );
    }

    #[test]
    fn mode_skipped_key_is_noted() {
        let out = explain(&fleet(), "allumata/STRIPE_SECRET_KEY", Some("prod")).unwrap();
        assert!(out.contains("note:       not required here"), "{out}");
    }

    #[test]
    fn env_may_be_omitted_with_one_environment() {
        let out = explain(&single_env(), "api/TOKEN", None).unwrap();
        assert!(out.starts_with("api/TOKEN in prod\n"), "{out}");
    }

    #[test]
    fn env_is_required_with_several_environments() {
        let e = explain(&fleet(), "allumata/OPENAI_API_KEY", None).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        assert_eq!(e.exit_code(), 2);
    }

    #[test]
    fn undeclared_product_is_config_error() {
        let e = explain(&fleet(), "nope/OPENAI_API_KEY", Some("prod")).unwrap_err();
        assert!(
            matches!(e, Error::Config(ref m) if m.contains("nope")),
            "{e}"
        );
    }

    #[test]
    fn undeclared_key_is_config_error() {
        let e = explain(&fleet(), "allumata/NOPE", Some("prod")).unwrap_err();
        assert!(
            matches!(e, Error::Config(ref m) if m.contains("NOPE")),
            "{e}"
        );
    }

    #[test]
    fn undefined_environment_is_config_error() {
        let e = explain(&fleet(), "allumata/OPENAI_API_KEY", Some("qa")).unwrap_err();
        assert!(matches!(e, Error::Config(ref m) if m.contains("qa")), "{e}");
    }

    #[test]
    fn environment_the_key_is_not_declared_for_is_config_error() {
        let e = explain(&fleet(), "allumata/OPENAI_API_KEY", Some("staging")).unwrap_err();
        assert!(
            matches!(e, Error::Config(ref m) if m.contains("staging")),
            "{e}"
        );
    }

    fn simple() -> Fleet {
        crate::config::load("tests/fixtures/simple.toml").unwrap()
    }

    #[test]
    fn simple_form_prints_the_key_alone() {
        let out = explain(&simple(), "DATABASE_URL", Some("prod")).unwrap();
        assert!(out.starts_with("DATABASE_URL in prod\n"), "{out}");
    }

    #[test]
    fn simple_form_reference_is_an_unsectioned_field() {
        let out = explain(&simple(), "DATABASE_URL", Some("prod")).unwrap();
        assert!(
            out.contains("reference:  op://vprd/iprd/DATABASE_URL\n"),
            "{out}"
        );
    }

    #[test]
    fn simple_form_fly_name_is_the_key() {
        let out = explain(&simple(), "DATABASE_URL", Some("prod")).unwrap();
        assert!(out.contains("fly name:   DATABASE_URL\n"), "{out}");
    }

    #[test]
    fn simple_form_prints_op_item_get_without_reveal() {
        let out = explain(&simple(), "JWT_KEY", Some("staging")).unwrap();
        assert!(
            out.contains("inspect:    op item get istg --vault vstg") && !out.contains("--reveal"),
            "{out}"
        );
    }

    /// The hidden implicit product never shows: no empty `//` section and no leading `/`.
    #[test]
    fn simple_form_never_shows_the_hidden_product() {
        let out = explain(&simple(), "JWT_KEY", Some("staging")).unwrap();
        assert!(!out.contains("istg//") && !out.starts_with('/'), "{out}");
    }

    #[test]
    fn simple_undeclared_key_is_config_error() {
        let e = explain(&simple(), "NOPE", Some("prod")).unwrap_err();
        assert!(
            matches!(e, Error::Config(ref m) if m.contains("NOPE")),
            "{e}"
        );
    }

    #[test]
    fn product_form_under_simple_is_config_error() {
        let e = explain(&simple(), "api/DATABASE_URL", Some("prod")).unwrap_err();
        assert!(
            matches!(e, Error::Config(ref m) if m.contains("<KEY>")),
            "{e}"
        );
    }

    #[test]
    fn simple_key_not_declared_for_env_names_the_key_alone() {
        let e = explain(&simple(), "STAGING_DEBUG_TOKEN", Some("prod")).unwrap_err();
        assert!(
            matches!(e, Error::Config(ref m) if m.starts_with("STAGING_DEBUG_TOKEN is not declared")),
            "{e}"
        );
    }

    #[test]
    fn target_without_slash_is_config_error() {
        let e = explain(&fleet(), "OPENAI_API_KEY", Some("prod")).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
    }
}
