//! `explain <product>/<key> [--env <env>]` (key form, FR-22); `explain <KEY>` under the
//! simple profile (FR-20); and `explain --target <name> --env <env>` (target form, FR-56).
//!
//! Reads only the configuration: it never reads a value, so it cannot emit one or a value
//! fragment (SR-1, §5). It is not a `secret get`. The target form and the key form's
//! account names resolve the project (`--project`, else the repository's name) before this
//! module runs; no runner is used here.
//!
//! The key form names, for the environment `--env` selects (or the only one declared):
//! the value's source (its own field, or `from <product>/<KEY>`), the access boundary and
//! its vault and item IDs (FR-57), every target of that environment that delivers the key
//! (FR-48, FR-56) with its name, provider and rendered name, and who can read it: each
//! delivering target's deploy service account and the environment's CI reader (FR-59). A
//! personal key (FR-55) says it lives in each person's own item. It also prints the declared
//! rules, `immutable` and `guidance`, plus the `op item get <item_id> --vault <vault_id>`
//! command a person can run to inspect the field in their own terminal. That command never
//! contains `--reveal`.
//!
//! The target form names the target's provider and locator, its products, its deploy
//! credentials (or `none`), its state vault ID and its deploy service account.
//!
//! An undeclared product, key, target or environment is `Error::Config` (exit 2).

use std::io::Write;

use super::{kind_label, suggest, write_err};
use crate::domain::access_plan::{ci_account, deploy_account};
use crate::domain::model::{KeySpec, Kind, OneOrMany, Rules, key_label};
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

/// What `opv explain` was asked about (FR-56): a declared key, or a declared target.
pub enum Asked<'a> {
    /// `[PRODUCT/]KEY`: the key form.
    Key(&'a str),
    /// `--target NAME`: the target form.
    Target(&'a str),
}

/// Both forms, for `opv explain` itself (FR-56, FR-59): `project` names the service
/// accounts and was resolved by the caller (`--project`, else the repository's name).
/// Configuration only, never a value.
pub fn run_request(
    fleet: &Fleet,
    asked: &Asked<'_>,
    env: Option<&str>,
    project: &str,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    match asked {
        Asked::Key(key) => {
            let t = resolve(fleet, key).map_err(|e| runnable_next(fleet, env, e))?;
            let env_name = environment(fleet, &t, env)?;
            explain_in(fleet, &t, env_name, project, out, json)
        }
        Asked::Target(name) => {
            let env_name = target_environment(fleet, name, env)?;
            explain_target_in(fleet, name, env_name, project, out, json)
        }
    }
}

/// The declared key and environment `opv open` names (H1), resolved exactly as `explain`
/// resolves them: `(product, key, environment)`. Configuration only.
pub(crate) fn locate<'a>(
    fleet: &'a Fleet,
    target: &str,
    env: Option<&'a str>,
) -> Result<(String, String, &'a str), Error> {
    // The same resolution as `explain`; a suggestion names `opv open` instead (M6).
    let as_open = |e: Error| match e.next_step().and_then(|n| n.strip_prefix("opv explain ")) {
        Some(rest) => {
            let next = format!("opv open {rest}");
            e.with_next(next)
        }
        None => e,
    };
    let t = resolve(fleet, target).map_err(|e| as_open(runnable_next(fleet, env, e)))?;
    let env_name = environment(fleet, &t, env).map_err(as_open)?;
    Ok((t.product.to_string(), t.key.to_string(), env_name))
}

/// Resolve the target to a declared key: `<product>/<key>`. P8: a bare `<KEY>` resolves to
/// the one product that declares it, or lists every product that does; an unknown name
/// suggests close declared names. Configuration only: names, never values.
fn resolve<'a>(fleet: &'a Fleet, target: &str) -> Result<Target<'a>, Error> {
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
        many => {
            let (p, k, _) = many[0];
            Err(Error::Config(
                format!(
                    "ambiguous key {key:?}: declared as {}; pass one of them",
                    many.iter()
                        .map(|(p, k, _)| key_label(p, k))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
                .into(),
            )
            .with_next(format!("opv explain {}", key_label(p, k))))
        }
    }
}

/// A configuration error for a name `explain` does not know, with the close declared
/// names (P8). The closest candidate becomes the `Next:` step (NR-19, H10); with none,
/// [`runnable_next`] names a command that lists the declared keys.
fn did_you_mean(text: String, close: &[&str]) -> Error {
    match close {
        [] => Error::Config(text.into()),
        [one] => Error::Config(format!("{text}; did you mean {one}?").into())
            .with_next(format!("opv explain {one}")),
        many => Error::Config(format!("{text}; did you mean {}?", many.join(" or ")).into())
            .with_next(format!("opv explain {}", many[0])),
    }
    .with_code(Code::UndeclaredKey)
}

/// `e` with a `Next:` step that runs as-is (H10): an `opv explain <label>` step gains the
/// `--env` it needs when several environments are declared, and an error with no step gets
/// the read-only command that lists the declared keys.
fn runnable_next(fleet: &Fleet, env: Option<&str>, e: Error) -> Error {
    let Some(label) = e
        .next_step()
        .and_then(|n| n.strip_prefix("opv explain "))
        .map(str::to_string)
    else {
        let list = super::list_keys_command(fleet);
        return e.or_next(|| list);
    };
    if label.contains(' ') {
        return e;
    }
    let cmd = explain_command(fleet, &label, env);
    e.with_next(cmd)
}

/// `opv explain <label>`, with `--env`: the one given, else none when only one environment
/// is declared, else the first environment the key is declared for.
fn explain_command(fleet: &Fleet, label: &str, env: Option<&str>) -> String {
    if let Some(e) = env.filter(|e| fleet.environments.contains_key(*e)) {
        return format!("opv explain {label} --env {e}");
    }
    if fleet.environments.len() <= 1 {
        return format!("opv explain {label}");
    }
    let declared = label
        .split_once('/')
        .and_then(|(product, key)| fleet.products.get(product)?.keys.get(key))
        .and_then(|spec| spec.environments.first());
    match declared.or_else(|| fleet.environments.keys().next()) {
        Some(e) => format!("opv explain {label} --env {e}"),
        None => format!("opv explain {label}"),
    }
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
            // The key is declared for one environment only: that one, no question.
            let sole: Option<&'a str> = match t.spec.environments.as_slice() {
                [one] => fleet
                    .environments
                    .get_key_value(one)
                    .map(|(k, _)| k.as_str()),
                _ => None,
            };
            match (names.next(), names.next()) {
                (Some(only), None) => only.as_str(),
                _ if sole.is_some() => sole.unwrap_or_default(),
                _ => {
                    let known: Vec<&str> = fleet.environments.keys().map(String::as_str).collect();
                    let label = key_label(t.product, t.key);
                    return Err(Error::Config(
                        format!(
                            "several environments are declared ({}): pass --env <environment>",
                            known.join(", ")
                        )
                        .into(),
                    )
                    .with_code(Code::Usage)
                    .with_next(explain_command(fleet, &label, None)));
                }
            }
        }
    };
    if !t.spec.environments.iter().any(|e| e == name) {
        let label = key_label(t.product, t.key);
        let mut err = Error::Config(
            format!(
                "{label} is not declared for environment {name:?} (declared for: {})",
                t.spec.environments.join(", ")
            )
            .into(),
        )
        .with_code(Code::UndeclaredKey);
        if let Some(first) = t.spec.environments.first() {
            err = err.with_next(format!("opv explain {label} --env {first}"));
        }
        return Err(err);
    }
    Ok(name)
}

fn explain_in(
    fleet: &Fleet,
    t: &Target<'_>,
    env_name: &str,
    project: &str,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    let (product, key, spec) = (t.product, t.key, t.spec);
    let field = match spec.kind {
        Kind::Secret => "concealed field",
        Kind::Config => "text field",
    };
    let label = key_label(product, key);
    let rules = describe_rules(&spec.rules);
    let required_here = rules::applies(spec, env_name, env, product);
    // A shared key (FR-45) has no field: its value lives in its source's field.
    let source = spec
        .source()
        .map(|(p, k)| (p, k, &fleet.products[p].keys[k]));
    let field_label = source.map_or_else(|| label.clone(), |(p, k, _)| key_label(p, k));
    let source_field = match source {
        Some(_) => format!("from {field_label}"),
        None => "own field".to_string(),
    };
    let shared_by: Vec<String> = fleet
        .shared_by(env_name, product, key)
        .iter()
        .map(|(p, k)| key_label(p, k))
        .collect();
    // The boundary item holding the field (FR-57): the source's, for a shared key. Personal
    // keys (FR-55) live in each person's own item, never in a boundary.
    let boundary_name = fleet.boundary_of(source.map_or(product, |(p, _, _)| p));
    let item = if spec.personal {
        None
    } else {
        Some(fleet.boundary(env_name, source.map_or(product, |(p, _, _)| p))?)
    };
    // Every target of this environment that delivers the key (FR-48, FR-56), in name order.
    let mut target_rows: Vec<(String, String)> = Vec::new();
    let mut targets: Vec<serde_json::Value> = Vec::new();
    let mut deploy_accounts: Vec<String> = Vec::new();
    let mut undelivered: Vec<String> = Vec::new();
    for (name, tc) in &env.targets {
        if !fleet.delivers(env_name, name, product) {
            undelivered.push(no_delivery(
                fleet,
                name,
                tc.config.provider().label(),
                product,
            ));
            continue;
        }
        let rendered = fleet.target_name(env_name, name, product, key);
        let details = provider_lines(tc.config.as_ref(), spec.kind, product, key);
        target_rows.push((
            "target".into(),
            format!("{name} ({}) {rendered}", tc.config.provider().label()),
        ));
        target_rows.extend(details.iter().cloned());
        targets.push(serde_json::json!({
            "name": name,
            "provider": tc.config.provider().section(),
            "rendered_name": rendered,
            "details": details
                .iter()
                .map(|(l, v)| serde_json::json!({"label": l, "value": v}))
                .collect::<Vec<_>>(),
        }));
        deploy_accounts.push(deploy_account(project, env_name, name));
    }
    if env.targets.is_empty() {
        // A run-only environment names no provider (P4).
        target_rows.push(("target".into(), "none (run-only)".into()));
    } else if target_rows.is_empty() {
        target_rows.push((
            "delivered".into(),
            format!("no ({})", undelivered.join("; ")),
        ));
    }
    // FR-59: the CI reader reads every boundary the environment records; a personal key
    // lives outside them.
    let ci = (!spec.personal).then(|| ci_account(project, env_name));
    if json {
        let mut doc = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env_name,
            "product": super::json_product(product),
            "key": key,
            "kind": kind_label(spec.kind),
            "field": field,
            "source": source_field.clone(),
            "personal": spec.personal,
            "boundary": item.map(|b| serde_json::json!({
                "name": boundary_name,
                "vault_id": &b.vault_id,
                "item_id": &b.item_id,
            })),
            "targets": targets,
            "rules": rules,
            "immutable": spec.immutable,
            "guidance": (!spec.guidance.is_empty()).then_some(spec.guidance.as_str()),
            "required_here": required_here,
            "shared_from": source.map(|_| field_label.clone()),
            "shared_by": shared_by,
        });
        if let Some(b) = item {
            doc["reference"] =
                serde_json::json!(format!("op://{}/{}/{field_label}", b.vault_id, b.item_id));
            doc["inspect"] = serde_json::json!(inspect_command(&b.item_id, &b.vault_id));
        }
        if let Some(ci) = &ci {
            doc["readers"] = serde_json::json!({
                "deploy": deploy_accounts.clone(),
                "ci": ci,
            });
        }
        return writeln!(out, "{doc}").map_err(write_err);
    }
    let mut rows: Vec<(String, String)> = Vec::new();
    if let Some(b) = item {
        rows.push((
            "reference".into(),
            format!("op://{}/{}/{field_label}", b.vault_id, b.item_id),
        ));
    }
    rows.push((
        "kind".into(),
        format!("{} ({field})", kind_label(spec.kind)),
    ));
    rows.push(("source".into(), source_field));
    if let Some(b) = item {
        rows.push((
            "boundary".into(),
            format!("{boundary_name} (vault {}, item {})", b.vault_id, b.item_id),
        ));
        // FR-45: the source's own rules, for a key that has no field of its own.
        if let Some((_, _, src)) = source {
            let src_rules = describe_rules(&src.rules);
            if !src_rules.is_empty() {
                rows.push(("source rules".into(), src_rules.join(", ")));
            }
        }
    }
    if spec.personal {
        rows.push(("personal".into(), "each person's own item".into()));
    }
    rows.extend(target_rows);
    if let Some(ci) = &ci {
        rows.push(("readers".into(), readers_line(&deploy_accounts, ci)));
    }
    if !shared_by.is_empty() {
        rows.push(("shared by".into(), shared_by.join(", ")));
    }
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
            match (spec.immutable, source) {
                (true, Some(_)) => format!("yes (follows {field_label})"),
                (false, Some(_)) => format!("no (follows {field_label})"),
                (true, None) => "yes".into(),
                (false, None) => "no".into(),
            },
        ),
        (
            "guidance".into(),
            if spec.guidance.is_empty() {
                "-".to_string()
            } else {
                spec.guidance.clone()
            },
        ),
    ]);
    if !required_here {
        rows.push((
            "note".into(),
            "not required here (its prefix_by_mode mode is skipped)".into(),
        ));
    }
    if let Some(b) = item {
        rows.push(("inspect".into(), inspect_command(&b.item_id, &b.vault_id)));
    }
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

/// The environment of target `name` (FR-56): `--env` when given, otherwise the only
/// environment that declares a target with that name.
fn target_environment<'a>(
    fleet: &'a Fleet,
    name: &str,
    env: Option<&'a str>,
) -> Result<&'a str, Error> {
    if let Some(e) = env {
        let environment = fleet.environment(e)?;
        if !environment.targets.contains_key(name) {
            return Err(no_such_target(e, name, environment.targets.keys()));
        }
        return Ok(e);
    }
    let found: Vec<&str> = fleet
        .environments
        .iter()
        .filter(|(_, e)| e.targets.contains_key(name))
        .map(|(n, _)| n.as_str())
        .collect();
    match found.as_slice() {
        [only] => Ok(only),
        [] => Err(Error::Config(
            format!("no target {name:?} is declared in any environment").into(),
        )
        .with_code(Code::Usage)
        .with_next("opv target list")),
        many => Err(Error::Config(
            format!(
                "target {name:?} is declared in several environments ({}): pass --env \
                 <environment>",
                many.join(", ")
            )
            .into(),
        )
        .with_code(Code::Usage)
        .with_next(format!("opv explain --target {name} --env {}", many[0]))),
    }
}

/// The refusal for a target an environment does not declare, naming the ones it does.
fn no_such_target<'a>(
    env_name: &str,
    name: &str,
    known: impl Iterator<Item = &'a String>,
) -> Error {
    let known: Vec<&str> = known.map(String::as_str).collect();
    let text = if known.is_empty() {
        format!("environment {env_name} declares no target; it is run-only")
    } else {
        format!(
            "environment {env_name} declares no target {name:?} (declared: {})",
            known.join(", ")
        )
    };
    Error::Config(text.into())
        .with_code(Code::Usage)
        .with_next(format!("opv target list --env {env_name}"))
}

/// The target form (FR-56): provider, locator, products, deploy credentials, state vault
/// and deploy service account. Configuration only.
fn explain_target_in(
    fleet: &Fleet,
    name: &str,
    env_name: &str,
    project: &str,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    let t = env
        .targets
        .get(name)
        .ok_or_else(|| no_such_target(env_name, name, env.targets.keys()))?;
    let provider = t.config.provider();
    let locator = t.config.target_locator();
    // FR-48: a named list, or every non-source-only product with a key in this environment.
    let products = match &t.products {
        Some(list) => list.join(", "),
        None => format!("every product with keys in {env_name}"),
    };
    let credentials = t.deploy_credentials.as_ref();
    let account = deploy_account(project, env_name, name);
    if json {
        let doc = serde_json::json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env_name,
            "target": name,
            "provider": provider.section(),
            "locator": locator,
            "products": products,
            "deploy_credentials": credentials.map(|c| c.to_string()),
            "state_vault_id": &t.state_vault_id,
            "deploy_account": account,
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    let rows: Vec<(&str, String)> = vec![
        ("provider", provider.label().to_string()),
        ("locator", locator),
        ("products", products),
        (
            "deploy credentials",
            credentials.map_or_else(|| "none".to_string(), ToString::to_string),
        ),
        ("state vault", t.state_vault_id.clone()),
        ("deploy account", account),
    ];
    let width = rows
        .iter()
        .map(|(l, _)| l.len() + 1)
        .max()
        .unwrap_or(0)
        .max(11);
    writeln!(out, "target {name} in {env_name}").map_err(write_err)?;
    for (l, v) in rows {
        writeln!(out, "  {:<width$} {v}", format!("{l}:")).map_err(write_err)?;
    }
    Ok(())
}

/// A target's `explain` lines for a secret (the provider's own), or for a config key: its
/// config routing when it has one, else the `- (config: not a <provider> secret)` line.
fn provider_lines(
    config: &dyn crate::provider::TargetConfig,
    kind: Kind,
    product: &str,
    key: &str,
) -> Vec<(String, String)> {
    match kind {
        Kind::Secret => config
            .explain(product, key)
            .into_iter()
            .map(|(l, v)| (l.to_string(), v))
            .collect(),
        Kind::Config => match config.explain_config(product, key) {
            Some(lines) => lines.into_iter().map(|(l, v)| (l.to_string(), v)).collect(),
            None => {
                let provider = config.provider().label();
                vec![(
                    format!("{} name", provider.to_lowercase()),
                    format!("- (config: not a {provider} secret)"),
                )]
            }
        },
    }
}

/// Why a target does not deliver `product` (FR-47, FR-48): a source-only product is never
/// written anywhere, and a products list may leave the product out.
fn no_delivery(fleet: &Fleet, name: &str, provider: &str, product: &str) -> String {
    if fleet.products.get(product).is_some_and(|p| p.source_only) {
        format!("{name} ({provider}) source-only product, delivered through its sharers")
    } else {
        format!("{name} ({provider}): its products list leaves {product} out")
    }
}

/// The readers of a key (FR-59), one line: each delivering target's deploy service account
/// and the environment's CI reader.
fn readers_line(deploy: &[String], ci: &str) -> String {
    let mut parts: Vec<String> = deploy.iter().map(|a| format!("deploy {a}")).collect();
    parts.push(format!("ci {ci}"));
    parts.join(", ")
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
        crate::app::testutil::explain(fleet, target, env, &mut out, false).map(|()| text_of(&out))
    }

    fn openai_prod() -> String {
        explain(&fleet(), "allumata/OPENAI_API_KEY", Some("prod")).unwrap()
    }

    /// The fixture plus `extra`, recording a boundary for every product `extra`
    /// introduces under the fixture's shared vault and item.
    fn fleet_with(extra: &str) -> Fleet {
        let base = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
        let doc: toml::Table = toml::from_str(&format!("{base}\n{extra}")).unwrap();
        let ids = |env: &str| match env {
            "prod" => ("vprd", "iprd"),
            _ => ("vstg", "istg"),
        };
        let envs = doc["environments"].as_table().unwrap();
        let mut out = format!("{base}\n{extra}");
        let mut seen = std::collections::BTreeSet::new();
        for (product, p) in doc["products"].as_table().unwrap() {
            let Some(keys) = p.get("keys").and_then(|v| v.as_table()) else {
                continue;
            };
            for spec in keys.values() {
                let Some(list) = spec.get("environments").and_then(|v| v.as_array()) else {
                    continue;
                };
                for env in list.iter().filter_map(|v| v.as_str()) {
                    let already = envs
                        .get(env)
                        .and_then(|e| e.get("boundaries"))
                        .and_then(|b| b.as_table())
                        .is_some_and(|b| b.contains_key(product));
                    if already || !seen.insert((product.clone(), env.to_string())) {
                        continue;
                    }
                    let (vault_id, item_id) = ids(env);
                    let header = format!("[environments.{env}]\n");
                    out = out.replacen(
                        &header,
                        &format!(
                            "{header}boundaries.{product} = {{ vault_id = \"{vault_id}\", \
                             item_id = \"{item_id}\" }}\n"
                        ),
                        1,
                    );
                }
            }
        }
        crate::config::parse(&out).unwrap()
    }

    fn single_env() -> Fleet {
        crate::config::parse(
            "[environments.prod]\nboundaries.api = { vault_id = \"vprd\", item_id = \"iprd\" }\n\
             [environments.prod.targets.app]\nstate_vault_id = \"sprod\"\n\
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
            "[environments.prod]\nboundaries.api = { vault_id = \"vprd\", item_id = \"iprd\" }\n\
             [environments.prod.targets.app]\nstate_vault_id = \"sprod\"\n\
             [environments.prod.targets.app.azure]\nsubscription = \"00000000-0000-0000-0000-000000000000\"\n\
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
            "[environments.prod]\nboundaries.api = { vault_id = \"vprd\", item_id = \"iprd\" }\n\
             [environments.prod.targets.app]\nstate_vault_id = \"sprod\"\n\
             [environments.prod.targets.app.azure]\nsubscription = \"00000000-0000-0000-0000-000000000000\"\n\
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
            "[environments.dev]\n\
             [products.allumata.keys.DEV_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
        );
        let out = explain(&f, "allumata/DEV_KEY", Some("dev")).unwrap();
        assert!(out.contains("\n  target:     none (run-only)\n"), "{out}");
    }

    /// FR-37: a config key on a target that routes config shows that target's lines.
    #[test]
    fn prints_the_routing_of_a_config_key_on_an_azure_target() {
        let fleet = crate::config::parse(
            "[environments.prod]\nboundaries.api = { vault_id = \"vprd\", item_id = \"iprd\" }\n\
             [environments.prod.targets.app]\nstate_vault_id = \"sprod\"\n\
             [environments.prod.targets.app.azure]\nsubscription = \"00000000-0000-0000-0000-000000000000\"\n\
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
    fn prints_the_target_name() {
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
    fn prints_ensure_prefix_and_regex() {
        assert_eq!(
            rules_line(r#"ensure_prefix = "sk-", regex = "sk-[a-z]+""#),
            r#"ensure_prefix = "sk-", regex = "sk-[a-z]+""#
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
    fn config_key_has_no_target_name() {
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
    fn env_is_required_for_a_key_declared_in_several_environments() {
        let e = explain(&fleet(), "allumata/INTEGRATION_ENC_KEY", None).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        assert_eq!(e.exit_code(), 2);
    }

    /// OPENAI_API_KEY is declared for prod only: no question to ask.
    #[test]
    fn env_may_be_omitted_for_a_key_declared_in_one_environment() {
        let out = explain(&fleet(), "allumata/OPENAI_API_KEY", None).unwrap();
        assert!(
            out.starts_with("allumata/OPENAI_API_KEY in prod\n"),
            "{out}"
        );
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
            Some("opv explain allumata/OPENAI_API_KEY --env prod"),
            "{e}"
        );
    }

    #[test]
    fn misspelt_product_suggests_the_declared_product() {
        let e = explain(&fleet(), "alumata/OPENAI_API_KEY", Some("prod")).unwrap_err();
        assert_eq!(
            e.next_step(),
            Some("opv explain allumata/OPENAI_API_KEY --env prod"),
            "{e}"
        );
    }
}

#[cfg(test)]
#[path = "explain_tests.rs"]
mod explain_tests;
