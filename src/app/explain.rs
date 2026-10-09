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

use super::{kind_label, suggest, write_err};
use crate::domain::model::{KeySpec, Kind, OneOrMany, Rules, SIMPLE_PRODUCT, key_label};
use crate::domain::{Fleet, rules};
use crate::error::{Code, Error};

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
    run_as(fleet, target, env, out, false)
}

/// [`run`], printing one JSON document instead of lines when `json` (A5): `{environment,
/// product, key, reference, kind, field, target: [{label, value}], rules, immutable,
/// guidance, required_here, inspect}`. Configuration only, never a value.
pub fn run_as(
    fleet: &Fleet,
    target: &str,
    env: Option<&str>,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    let t = resolve(fleet, target)?;
    let env_name = environment(fleet, &t, env)?;
    explain_in(fleet, &t, env_name, out, json)
}

/// The declared key and environment `opv open` names (H1), resolved exactly as `explain`
/// resolves them: `(product, key, environment)`. Configuration only.
pub(crate) fn locate<'a>(
    fleet: &'a Fleet,
    target: &str,
    env: Option<&'a str>,
) -> Result<(String, String, &'a str), Error> {
    let t = resolve(fleet, target)?;
    let env_name = environment(fleet, &t, env)?;
    Ok((t.product.to_string(), t.key.to_string(), env_name))
}

/// Resolve the target to a declared key: `<product>/<key>` under the fleet profile, `<KEY>`
/// under the simple profile (FR-20). P8: a bare `<KEY>` under the fleet profile resolves to
/// the one product that declares it, or lists every product that does; a `<product>/<KEY>`
/// under the simple profile names the bare key; an unknown name suggests close declared
/// names. Configuration only: names, never values.
fn resolve<'a>(fleet: &'a Fleet, target: &str) -> Result<Target<'a>, Error> {
    if fleet.is_simple() {
        let keys = fleet.products.get(SIMPLE_PRODUCT).map(|p| &p.keys);
        let names = || keys.into_iter().flat_map(|k| k.keys().map(String::as_str));
        if let Some((_, key)) = target.split_once('/') {
            let close: Vec<&str> = if keys.is_some_and(|k| k.contains_key(key)) {
                vec![key]
            } else {
                suggest::close(key, names())
            };
            return Err(did_you_mean(
                format!("explain expects <KEY> under the simple profile, got {target:?}"),
                &close,
            ));
        }
        let Some((key, spec)) = keys.and_then(|k| k.get_key_value(target)) else {
            return Err(did_you_mean(
                format!("undeclared key {target:?}"),
                &suggest::close(target, names()),
            ));
        };
        return Ok(Target {
            product: SIMPLE_PRODUCT,
            key,
            spec,
        });
    }
    let Some((product, key)) = target.split_once('/') else {
        return resolve_bare(fleet, target);
    };
    let Some((product, p)) = fleet.products.get_key_value(product) else {
        let known: Vec<&str> = fleet.products.keys().map(String::as_str).collect();
        let close: Vec<String> = suggest::close(product, known.iter().copied())
            .into_iter()
            .map(|c| key_label(c, key))
            .collect();
        return Err(did_you_mean(
            format!(
                "undeclared product {product:?} (declared: {})",
                known.join(", ")
            ),
            &close.iter().map(String::as_str).collect::<Vec<_>>(),
        ));
    };
    let Some((key, spec)) = p.keys.get_key_value(key) else {
        let elsewhere: Vec<String> = fleet
            .products
            .iter()
            .filter(|(_, other)| other.keys.contains_key(key))
            .map(|(name, _)| key_label(name, key))
            .collect();
        let text = format!("undeclared key {key:?} in product {product}");
        if !elsewhere.is_empty() {
            let e = Error::Config(format!("{text}; declared as {}", elsewhere.join(", ")).into());
            return Err(match elsewhere.as_slice() {
                [one] => e.with_next(format!("opv explain {one}")),
                _ => e,
            });
        }
        let close: Vec<String> = suggest::close(key, p.keys.keys().map(String::as_str))
            .into_iter()
            .map(|c| key_label(product, c))
            .collect();
        return Err(did_you_mean(
            text,
            &close.iter().map(String::as_str).collect::<Vec<_>>(),
        ));
    };
    Ok(Target { product, key, spec })
}

/// A bare `<KEY>` under the fleet profile: the one product that declares it, or an error
/// listing every candidate (ambiguous) or the closest declared keys (unknown).
fn resolve_bare<'a>(fleet: &'a Fleet, key: &str) -> Result<Target<'a>, Error> {
    let found: Vec<(&'a str, &'a str, &'a KeySpec)> = fleet
        .products
        .iter()
        .filter_map(|(name, p)| {
            p.keys
                .get_key_value(key)
                .map(|(k, spec)| (name.as_str(), k.as_str(), spec))
        })
        .collect();
    match found.as_slice() {
        [(product, key, spec)] => Ok(Target { product, key, spec }),
        [] => {
            let all: Vec<String> = fleet
                .products
                .iter()
                .flat_map(|(name, p)| p.keys.keys().map(move |k| key_label(name, k)))
                .collect();
            let bare: Vec<&str> = all
                .iter()
                .map(|l| l.split_once('/').map_or(l.as_str(), |(_, k)| k))
                .collect();
            let close: Vec<&str> = suggest::close(key, bare.iter().copied());
            let labels: Vec<&str> = all
                .iter()
                .zip(&bare)
                .filter(|(_, b)| close.contains(b))
                .map(|(l, _)| l.as_str())
                .collect();
            Err(did_you_mean(
                format!("undeclared key {key:?} (explain takes <product>/<KEY>)"),
                &labels,
            ))
        }
        many => Err(Error::Config(
            format!(
                "ambiguous key {key:?}: declared as {}; pass one of them",
                many.iter()
                    .map(|(p, k, _)| key_label(p, k))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .into(),
        )),
    }
}

/// A configuration error for a name `explain` does not know, with the close declared
/// names (P8). One candidate becomes the single `Next:` step (NR-19); several are listed
/// in the text and the category's default step stays.
fn did_you_mean(text: String, close: &[&str]) -> Error {
    match close {
        [] => Error::Config(text.into()),
        [one] => Error::Config(format!("{text}; did you mean {one}?").into())
            .with_next(format!("opv explain {one}")),
        many => Error::Config(format!("{text}; did you mean {}?", many.join(" or ")).into()),
    }
    .with_code(Code::UndeclaredKey)
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
                    return Err(Error::Config(
                        format!(
                            "several environments are declared ({}): pass --env <environment>",
                            known.join(", ")
                        )
                        .into(),
                    )
                    .with_code(Code::Usage));
                }
            }
        }
    };
    if !t.spec.environments.iter().any(|e| e == name) {
        return Err(Error::Config(
            format!(
                "{} is not declared for environment {name:?} (declared for: {})",
                key_label(t.product, t.key),
                t.spec.environments.join(", ")
            )
            .into(),
        )
        .with_code(Code::UndeclaredKey));
    }
    Ok(name)
}

fn explain_in(
    fleet: &Fleet,
    t: &Target<'_>,
    env_name: &str,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    let (product, key, spec) = (t.product, t.key, t.spec);
    let field = match spec.kind {
        Kind::Secret => "concealed field",
        Kind::Config => "text field",
    };
    let config_lines = env.target().and_then(|t| t.explain_config(product, key));
    let target_lines: Vec<(String, String)> = match (spec.kind, env.target()) {
        // A run-only environment names no provider (P4).
        (_, None) => vec![("target".into(), "none (run-only)".into())],
        (Kind::Config, Some(_)) if config_lines.is_some() => config_lines
            .into_iter()
            .flatten()
            .map(|(l, v)| (l.to_string(), v))
            .collect(),
        (Kind::Config, Some(t)) => {
            let label = t.provider().label();
            vec![(
                format!("{} name", label.to_lowercase()),
                format!("- (config: not a {label} secret)"),
            )]
        }
        (Kind::Secret, Some(t)) => t
            .explain(product, key)
            .into_iter()
            .map(|(l, v)| (l.to_string(), v))
            .collect(),
    };
    let rules = describe_rules(&spec.rules);
    let guidance = if spec.guidance.is_empty() {
        "-"
    } else {
        spec.guidance.as_str()
    };
    // Simple-profile fields are unsectioned: `op://<vault>/<item>/<KEY>`.
    let label = key_label(product, key);
    let required_here = rules::applies(spec, env_name, env, product);
    if json {
        let doc = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env_name,
            "product": super::json_product(product),
            "key": key,
            "reference": format!("op://{}/{}/{label}", env.vault_id, env.item_id),
            "kind": kind_label(spec.kind),
            "field": field,
            "target": target_lines
                .iter()
                .map(|(l, v)| serde_json::json!({"label": l, "value": v}))
                .collect::<Vec<_>>(),
            "rules": rules,
            "immutable": spec.immutable,
            "guidance": (!spec.guidance.is_empty()).then_some(spec.guidance.as_str()),
            "required_here": required_here,
            "inspect": inspect_command(&env.item_id, &env.vault_id),
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    let mut rows: Vec<(String, String)> = vec![
        (
            "reference".into(),
            format!("op://{}/{}/{label}", env.vault_id, env.item_id),
        ),
        (
            "kind".into(),
            format!("{} ({field})", kind_label(spec.kind)),
        ),
    ];
    rows.extend(target_lines);
    rows.extend([
        (
            "rules".into(),
            if rules.is_empty() {
                "-".to_string()
            } else {
                rules.join(", ")
            },
        ),
        (
            "immutable".into(),
            if spec.immutable { "yes" } else { "no" }.into(),
        ),
        ("guidance".into(), guidance.to_string()),
    ]);
    if !required_here {
        rows.push((
            "note".into(),
            "not required here (its prefix_by_mode mode is skipped)".into(),
        ));
    }
    rows.push((
        "inspect".into(),
        inspect_command(&env.item_id, &env.vault_id),
    ));
    // H1: the command that opens the item in 1Password, where the value is typed.
    rows.push(("open".into(), format!("opv open {label} --env {env_name}")));
    // One value column, however long a provider's label is (P4).
    let width = rows
        .iter()
        .map(|(l, _)| l.len() + 1)
        .max()
        .unwrap_or(0)
        .max(11);
    let mut lines = vec![format!("{label} in {env_name}")];
    lines.extend(
        rows.iter()
            .map(|(l, v)| format!("  {:<width$} {v}", format!("{l}:"))),
    );
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
             [environments.prod.azure]\nsubscription = \"00000000-0000-0000-0000-000000000000\"\n\
             key_vault = \"kv\"\nresource_group = \"rg\"\n\
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

    fn azure_fleet() -> Fleet {
        crate::config::parse(
            "[profile]\nkind = \"fleet\"\n\
             [environments.prod]\nvault_id = \"vprd\"\nitem_id = \"iprd\"\n\
             [environments.prod.azure]\nsubscription = \"00000000-0000-0000-0000-000000000000\"\n\
             key_vault = \"kv\"\nresource_group = \"rg\"\n\
             container_app = \"ca\"\nidentity = \"system\"\n\
             env_name = \"FLEET__{PRODUCT}__{KEY}\"\n\
             [products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n",
        )
        .unwrap()
    }

    /// P4: every value starts in one column, however wide a provider's label is.
    #[test]
    fn values_share_one_column_beside_a_wide_provider_label() {
        let out = explain(&azure_fleet(), "api/TOKEN", Some("prod")).unwrap();
        assert!(out.contains("\n  reference:      op://"), "{out}");
    }

    /// P4: a run-only environment names no provider.
    #[test]
    fn run_only_environment_says_run_only() {
        let f = fleet_with(
            "[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n\
             [products.allumata.keys.DEV_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
        );
        let out = explain(&f, "allumata/DEV_KEY", Some("dev")).unwrap();
        assert!(out.contains("\n  target:     none (run-only)\n"), "{out}");
    }

    /// FR-37: a config key on a target that routes config shows that target's lines.
    #[test]
    fn prints_the_routing_of_a_config_key_on_an_azure_target() {
        let fleet = crate::config::parse(
            "[profile]\nkind = \"fleet\"\n\
             [environments.prod]\nvault_id = \"vprd\"\nitem_id = \"iprd\"\n\
             [environments.prod.azure]\nsubscription = \"00000000-0000-0000-0000-000000000000\"\n\
             key_vault = \"kv\"\nresource_group = \"rg\"\n\
             container_app = \"ca\"\nidentity = \"system\"\n\
             env_name = \"FLEET__{PRODUCT}__{KEY}\"\n\
             [products.api.keys.LOG_LEVEL]\nkind = \"config\"\nenvironments = [\"prod\"]\n",
        )
        .unwrap();
        let out = explain(&fleet, "api/LOG_LEVEL", Some("prod")).unwrap();
        assert!(out.contains("  routing:    plain env value"), "{out}");
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

    /// P8: a bare key declared by one product resolves to that product.
    #[test]
    fn bare_key_unique_across_products_resolves() {
        let out = explain(&fleet(), "OPENAI_API_KEY", Some("prod")).unwrap();
        assert!(
            out.starts_with("allumata/OPENAI_API_KEY in prod\n"),
            "{out}"
        );
    }

    fn two_products() -> Fleet {
        fleet_with(
            "[products.web.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"prod\"]\n",
        )
    }

    #[test]
    fn bare_key_in_several_products_lists_the_candidates() {
        let e = explain(&two_products(), "OPENAI_API_KEY", Some("prod")).unwrap_err();
        assert!(
            e.to_string()
                .contains("ambiguous key \"OPENAI_API_KEY\": declared as allumata/OPENAI_API_KEY, web/OPENAI_API_KEY"),
            "{e}"
        );
    }

    #[test]
    fn bare_unknown_key_suggests_a_close_declared_key() {
        let e = explain(&fleet(), "OPENAI_API_KY", Some("prod")).unwrap_err();
        assert!(
            e.to_string()
                .contains("did you mean allumata/OPENAI_API_KEY?"),
            "{e}"
        );
    }

    #[test]
    fn misspelt_key_in_a_product_suggests_the_declared_key() {
        let e = explain(&fleet(), "allumata/OPENAI_API_KY", Some("prod")).unwrap_err();
        assert_eq!(
            e.next_step(),
            Some("opv explain allumata/OPENAI_API_KEY"),
            "{e}"
        );
    }

    #[test]
    fn misspelt_product_suggests_the_declared_product() {
        let e = explain(&fleet(), "alumata/OPENAI_API_KEY", Some("prod")).unwrap_err();
        assert_eq!(
            e.next_step(),
            Some("opv explain allumata/OPENAI_API_KEY"),
            "{e}"
        );
    }

    #[test]
    fn simple_product_form_suggests_the_bare_key() {
        let e = explain(&simple(), "api/DATABASE_URL", Some("prod")).unwrap_err();
        assert!(e.to_string().contains("did you mean DATABASE_URL?"), "{e}");
    }

    #[test]
    fn simple_misspelt_key_suggests_the_declared_key() {
        let e = explain(&simple(), "DATABASE_UR", Some("prod")).unwrap_err();
        assert!(e.to_string().contains("did you mean DATABASE_URL?"), "{e}");
    }
}
