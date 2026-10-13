//! The readiness and handoff receipt (FR-51, `docs/design/accounts-and-readiness.md` §4).
//!
//! Pure: the caller gathers the configuration source, the FR-49 account report and one
//! `Result<Vec<Row>, Error>` per environment, and [`receipt`] joins them into one
//! deterministic document. No `op` call, no target call, no filesystem, no tidy. Names,
//! IDs and codes only (SR-1): never a value.
//!
//! [`render_text`] prints the same receipt for a person: a counts line, a
//! product × environment grid and the findings with one runnable prerequisite each.

use std::io::Write;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::app::account::Report;
use crate::domain::{KeyState, Row, TargetState, key_label};
use crate::error::Error;

/// One environment's contribution to the receipt: its name, its target's provider label
/// (`Some("Fly")`, or `None` for a run-only environment) and its rows, or the error that
/// stopped reading it. The caller has already read them; nothing here calls `op`.
pub struct EnvInput {
    pub name: String,
    pub target: Option<String>,
    pub rows: Result<Vec<Row>, Error>,
    /// Display name (FR-55); `None`: the key.
    pub title: Option<String>,
    /// Who the environment is for (FR-55): when set, an environment this person cannot open
    /// is reported as not theirs, non-blocking.
    pub audience: Option<String>,
}

/// Everything [`receipt`] needs, already gathered by the caller.
pub struct Inputs<'a> {
    /// Where the configuration came from, for wording only (FR-44).
    pub config_source: Option<String>,
    /// The FR-49 account report (`opv account list`), for the selected account and its
    /// findings.
    pub account: &'a Report,
    /// One entry per environment, in the order the receipt shows them.
    pub envs: Vec<EnvInput>,
    /// True under the simple profile (FR-20): product names are omitted from scope and
    /// labels.
    pub simple: bool,
    /// The personal keys (FR-55), as (product, key): their findings say "your".
    pub personal: std::collections::BTreeSet<(String, String)>,
}

/// `config` of the receipt: where the configuration was read from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigRef {
    pub source: Option<String>,
}

/// `account` of the receipt: the selected account (FR-49), or `null` when none is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountRef {
    pub account_id: String,
    pub by: String,
}

/// One environment × product cell of the matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatrixEntry {
    pub environment: String,
    /// The environment's display name (FR-55).
    pub title: String,
    pub product: String,
    /// The environment's target provider label; `null` for a run-only environment.
    pub target: Option<String>,
    pub keys: usize,
    pub saved: usize,
    pub findings: usize,
    /// False when every row of the product is `TargetState::NotDelivered`; true for a
    /// run-only environment.
    pub delivered: bool,
}

/// What a finding is about: any of the account, environment, product or key, each omitted
/// when absent (FR-51).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Scope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// One thing a person or agent must act on, with one runnable prerequisite and one verify
/// command (FR-51).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub code: String,
    pub scope: Scope,
    pub blocking: bool,
    pub actor: String,
    pub effect: String,
    pub prerequisite: String,
    pub verify: String,
}

/// The first step: the actor and the command of the first blocking finding, else of the
/// first finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Next {
    pub actor: String,
    pub command: String,
}

/// The FR-51 document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Receipt {
    pub receipt_id: String,
    pub opv_version: String,
    pub config: ConfigRef,
    pub account: Option<AccountRef>,
    pub matrix: Vec<MatrixEntry>,
    pub findings: Vec<Finding>,
    pub next: Option<Next>,
    /// The environments in input order, with their display names, for [`render_text`]'s
    /// columns; never serialized.
    #[serde(skip)]
    environments: Vec<(String, String)>,
}

/// Build the readiness receipt (FR-51). Deterministic: equal inputs give an equal
/// `receipt_id`, which binds the receipt to `(config.source, account, matrix, findings)`
/// and holds no value.
pub fn receipt(inputs: &Inputs<'_>, opv_version: &str) -> Receipt {
    let config = ConfigRef {
        source: inputs.config_source.clone(),
    };
    let account = inputs.account.selected.as_ref().map(|s| AccountRef {
        account_id: s.account_id.clone(),
        by: s.by.clone(),
    });
    let matrix = build_matrix(inputs);
    let findings = build_findings(inputs);
    let next = findings
        .iter()
        .find(|f| f.blocking)
        .or_else(|| findings.first())
        .map(|f| Next {
            actor: f.actor.clone(),
            command: f.prerequisite.clone(),
        });
    let receipt_id = receipt_id(&config, &account, &matrix, &findings);
    let environments = inputs
        .envs
        .iter()
        .map(|e| {
            (
                e.name.clone(),
                e.title.clone().unwrap_or_else(|| e.name.clone()),
            )
        })
        .collect();
    Receipt {
        receipt_id,
        opv_version: opv_version.to_string(),
        config,
        account,
        matrix,
        findings,
        next,
        environments,
    }
}

/// The four inputs `receipt_id` binds (FR-51): the configuration source, the selected
/// account, the matrix and the findings. Names and IDs only.
#[derive(Serialize)]
struct IdInput<'a> {
    source: &'a Option<String>,
    account: &'a Option<AccountRef>,
    matrix: &'a [MatrixEntry],
    findings: &'a [Finding],
}

/// `rcpt-` plus the first 12 hex characters of SHA-256 over the serialized inputs.
fn receipt_id(
    config: &ConfigRef,
    account: &Option<AccountRef>,
    matrix: &[MatrixEntry],
    findings: &[Finding],
) -> String {
    let input = IdInput {
        source: &config.source,
        account,
        matrix,
        findings,
    };
    let bytes = serde_json::to_vec(&input).expect("the receipt id input serializes");
    let hex = format!("{:x}", Sha256::digest(&bytes));
    format!("rcpt-{}", &hex[..12])
}

/// The matrix: one entry per environment × product present in that environment's rows,
/// grouped by product in row order of first appearance. An environment whose rows are
/// `Err` contributes nothing.
fn build_matrix(inputs: &Inputs<'_>) -> Vec<MatrixEntry> {
    let mut out = Vec::new();
    for env in &inputs.envs {
        let Ok(rows) = &env.rows else { continue };
        let mut products: Vec<&str> = Vec::new();
        for r in rows {
            if !products.contains(&r.product.as_str()) {
                products.push(&r.product);
            }
        }
        for product in products {
            let group: Vec<&Row> = rows.iter().filter(|r| r.product == product).collect();
            let saved = group.iter().filter(|r| r.state == KeyState::Ready).count();
            let findings = group.iter().filter(|r| is_finding_state(&r.state)).count();
            let delivered = env.target.is_none()
                || !group.iter().all(|r| r.target == TargetState::NotDelivered);
            out.push(MatrixEntry {
                environment: env.name.clone(),
                title: env.title.clone().unwrap_or_else(|| env.name.clone()),
                product: product.to_string(),
                target: env.target.clone(),
                keys: group.len(),
                saved,
                findings,
                delivered,
            });
        }
    }
    out
}

/// The row states counted as findings in the matrix (FR-51): a key blocked by its source
/// is counted once, on its own row.
fn is_finding_state(state: &KeyState) -> bool {
    matches!(
        state,
        KeyState::Missing
            | KeyState::WrongKind
            | KeyState::RuleFailed(..)
            | KeyState::SourceBlocked
    )
}

/// The findings, in order (FR-51): every account finding, then each environment's error,
/// then each row's own finding. A `SourceBlocked` row produces none (its source's does).
fn build_findings(inputs: &Inputs<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    let selected = inputs
        .account
        .selected
        .as_ref()
        .map(|s| s.account_id.clone());
    for f in &inputs.account.findings {
        let effect = match f.code.as_str() {
            "selected_signed_out" | "selected_account_absent" | "no_accounts" => "signs_in",
            _ => "none",
        };
        out.push(Finding {
            code: f.code.clone(),
            scope: Scope {
                account: selected.clone(),
                ..Scope::default()
            },
            blocking: f.code != "discovery_unavailable",
            actor: "owner".into(),
            effect: effect.into(),
            prerequisite: f.next.clone().unwrap_or_else(|| "opv account list".into()),
            verify: "opv account list --json".into(),
        });
    }
    for env in &inputs.envs {
        let Err(e) = &env.rows else { continue };
        let code = e.code();
        // FR-55: an environment meant for others (its audience) that this person cannot
        // open is not a problem to fix.
        let no_access = matches!(code.as_str(), "vault_no_access" | "item_not_found");
        if let (Some(audience), true) = (&env.audience, no_access) {
            out.push(Finding {
                code: "not_for_you".into(),
                scope: Scope {
                    environment: Some(env.name.clone()),
                    ..Scope::default()
                },
                blocking: false,
                actor: "owner".into(),
                effect: "none".into(),
                prerequisite: format!(
                    "ask the 1Password owner for access to {} if you need it (audience: {audience})",
                    env.name
                ),
                verify: "opv ready --json".into(),
            });
            continue;
        }
        let effect = match code.as_str() {
            "op_not_signed_in"
            | "auth_required"
            | "account_not_registered"
            | "selected_signed_out" => "signs_in",
            _ => "none",
        };
        out.push(Finding {
            code: code.as_str().into(),
            scope: Scope {
                environment: Some(env.name.clone()),
                ..Scope::default()
            },
            blocking: true,
            actor: if code.human_required() {
                "owner"
            } else {
                "agent"
            }
            .into(),
            effect: effect.into(),
            prerequisite: e
                .next_step()
                .map(str::to_string)
                .unwrap_or_else(|| format!("opv status {}", env.name)),
            verify: "opv ready --json".into(),
        });
    }
    for env in &inputs.envs {
        let Ok(rows) = &env.rows else { continue };
        for r in rows {
            let code = match &r.state {
                KeyState::Missing
                    if inputs
                        .personal
                        .contains(&(r.product.clone(), r.key.clone())) =>
                {
                    "personal_key_missing"
                }
                KeyState::RuleFailed("nonempty", _)
                    if inputs
                        .personal
                        .contains(&(r.product.clone(), r.key.clone())) =>
                {
                    "personal_key_empty"
                }
                KeyState::Missing => "key_missing",
                // A field that exists but holds nothing: the owner fills it (#77).
                KeyState::RuleFailed("nonempty", _) => "key_empty",
                KeyState::RuleFailed(..) => "key_failed_rule",
                KeyState::WrongKind => "key_wrong_kind",
                _ => continue,
            };
            let label = if inputs.simple {
                r.key.clone()
            } else {
                key_label(&r.product, &r.key)
            };
            let (product, verify) = if inputs.simple {
                (None, format!("opv status {}", env.name))
            } else {
                (
                    Some(r.product.clone()),
                    format!("opv status {} --product {}", env.name, r.product),
                )
            };
            out.push(Finding {
                code: code.into(),
                scope: Scope {
                    environment: Some(env.name.clone()),
                    product,
                    key: Some(r.key.clone()),
                    account: None,
                },
                blocking: true,
                actor: "owner".into(),
                effect: "writes_1password".into(),
                prerequisite: format!("opv open {label} --env {}", env.name),
                verify,
            });
        }
    }
    out
}

/// Render `r` for a person: the counts line, the product × environment grid, the findings
/// with one line each, and `Next` when set. Names and IDs only, never a value.
pub fn render_text(r: &Receipt, out: &mut dyn Write) -> Result<(), Error> {
    let blocking = r.findings.iter().filter(|f| f.blocking).count();
    writeln!(
        out,
        "ready: {blocking} blocking · {} findings · receipt {}",
        r.findings.len(),
        r.receipt_id
    )
    .map_err(super::write_err)?;

    let envs = &r.environments;
    let mut header: Vec<String> = Vec::with_capacity(envs.len() + 1);
    header.push("PRODUCT".into());
    header.extend(envs.iter().map(|(_, title)| title.clone()));
    let mut body: Vec<Vec<String>> = Vec::new();
    for product in product_order(&r.matrix) {
        let mut cells = Vec::with_capacity(envs.len() + 1);
        cells.push(product.clone());
        for (environment, _) in envs {
            let entry = r
                .matrix
                .iter()
                .find(|m| m.environment == *environment && m.product == product);
            cells.push(match entry {
                None => "-".into(),
                Some(m) if !m.delivered => "n/a".into(),
                Some(m) => {
                    let mut cell = format!("{}/{}", m.saved, m.keys);
                    if m.findings > 0 {
                        cell.push_str(&format!(
                            " · {}",
                            super::plural(m.findings, "finding", "findings")
                        ));
                    }
                    cell
                }
            });
        }
        body.push(cells);
    }
    write_grid(out, &header, &body)?;

    if r.findings.is_empty() {
        writeln!(
            out,
            "Nothing needs attention: every declared key is saved and every environment was read."
        )
        .map_err(super::write_err)?;
    } else {
        writeln!(out, "Needs attention:").map_err(super::write_err)?;
    }
    for f in &r.findings {
        writeln!(
            out,
            "  [{}] {} {} → {}",
            f.actor,
            f.code,
            scope_text(&f.scope),
            f.prerequisite
        )
        .map_err(super::write_err)?;
    }
    if let Some(n) = &r.next {
        writeln!(out, "Next ({}): {}", n.actor, n.command).map_err(super::write_err)?;
    }
    Ok(())
}

/// The products of the matrix in order of first appearance.
fn product_order(matrix: &[MatrixEntry]) -> Vec<String> {
    let mut products = Vec::new();
    for m in matrix {
        if !products.contains(&m.product) {
            products.push(m.product.clone());
        }
    }
    products
}

/// A finding's scope as `env product/KEY` (`KEY` when the product is omitted), with the
/// account appended when present.
fn scope_text(scope: &Scope) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(e) = &scope.environment {
        parts.push(e.clone());
    }
    match (&scope.product, &scope.key) {
        (Some(p), Some(k)) => parts.push(format!("{p}/{k}")),
        (Some(p), None) => parts.push(p.clone()),
        (None, Some(k)) => parts.push(k.clone()),
        (None, None) => {}
    }
    if let Some(a) = &scope.account {
        parts.push(a.clone());
    }
    parts.join(" ")
}

/// Print `header` and `body` as an aligned grid, columns two spaces apart and no trailing
/// spaces.
fn write_grid(out: &mut dyn Write, header: &[String], body: &[Vec<String>]) -> Result<(), Error> {
    let columns = header.len();
    let mut widths = vec![0usize; columns];
    for row in std::iter::once(header).chain(body.iter().map(Vec::as_slice)) {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: &[String]| {
        let mut s = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i > 0 {
                s.push_str("  ");
            }
            s.push_str(cell);
            if i + 1 < columns {
                for _ in 0..widths[i].saturating_sub(cell.chars().count()) {
                    s.push(' ');
                }
            }
        }
        s.trim_end().to_string()
    };
    writeln!(out, "{}", line(header)).map_err(super::write_err)?;
    for row in body {
        writeln!(out, "{}", line(row)).map_err(super::write_err)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "ready_tests.rs"]
mod tests;

/// `opv ready [<env>] [--json] [--save <file>]` (FR-51): read-only. The account report
/// (FR-49), then each environment (or `only` that one) read as `status` reads it, joined into
/// the receipt. Findings never fail the command: the receipt reports them, and `next` is the
/// first step to take.
pub fn run(
    fleet: &crate::domain::Fleet,
    config_source: Option<&str>,
    only: Option<&str>,
    r: &dyn crate::runner::CommandRunner,
    json: bool,
    save: Option<&std::path::Path>,
    out: &mut dyn Write,
) -> Result<(), Error> {
    if let Some(e) = only {
        fleet.environment(e)?;
    }
    let account = super::account::gather(r, None);
    // FR-55: the environments' own order, then their keys; never a fixed list.
    let mut ordered: Vec<(&String, &crate::domain::Environment)> = fleet
        .environments
        .iter()
        .filter(|(name, _)| only.is_none_or(|o| o == name.as_str()))
        .collect();
    ordered.sort_by_key(|(name, env)| (env.order.unwrap_or(i64::MAX), (*name).clone()));
    let envs = ordered
        .into_iter()
        .map(|(name, env)| {
            let target = env.target();
            EnvInput {
                name: name.clone(),
                target: target.map(|t| t.provider().label().to_string()),
                rows: super::status::env_rows(fleet, name, target, r),
                title: env.title.clone(),
                audience: env.audience.clone(),
            }
        })
        .collect();
    let personal = fleet
        .products
        .iter()
        .flat_map(|(p, prod)| {
            prod.keys
                .iter()
                .filter(|(_, spec)| spec.personal)
                .map(move |(k, _)| (p.clone(), k.clone()))
        })
        .collect();
    let doc = receipt(
        &Inputs {
            config_source: config_source.map(str::to_string),
            account: &account,
            envs,
            simple: fleet.is_simple(),
            personal,
        },
        env!("CARGO_PKG_VERSION"),
    );
    let mut v = serde_json::to_value(&doc)
        .map_err(|_| Error::Config("cannot serialize the readiness receipt".into()))?;
    v["schema_version"] = serde_json::json!(crate::json::SCHEMA_VERSION);
    if let Some(path) = save {
        let text = serde_json::to_string_pretty(&v)
            .map_err(|_| Error::Config("cannot serialize the readiness receipt".into()))?;
        super::init::write_atomic(path, &format!("{text}\n"), true)?;
    }
    if json {
        return writeln!(out, "{v}").map_err(super::write_err);
    }
    render_text(&doc, out)?;
    if let Some(path) = save {
        writeln!(out, "saved: {}", path.display()).map_err(super::write_err)?;
    }
    Ok(())
}
