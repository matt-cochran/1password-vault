//! The readiness and handoff receipt (FR-51, `docs/design/accounts-and-readiness.md` §4).
//!
//! Pure: the caller gathers the configuration source, the FR-49 account report and one
//! `Result<Vec<Row>, Error>` per environment, and [`receipt`] joins them into one
//! deterministic document. No `op` call, no target call, no filesystem, no tidy. Names,
//! IDs and codes only (SR-1): never a value.
//!
//! [`render_text`] prints the same receipt for a person: a counts line, a
//! product × environment grid and the findings with one runnable prerequisite each.

use std::collections::BTreeMap;
use std::io::Write;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::app::account::Report;
use crate::app::rule_source::{RuleStatus, rule_source};
use crate::domain::plan::RuleGate;
use crate::domain::{KeyState, Row, TargetState, key_label};
use crate::error::Error;

/// One named target of an environment, as `ready` reads it (FR-56): its identity and the
/// outcome of the probes that decide `ready` or `grants_missing`. The caller has already
/// read the rows and (one vault visibility check per needed vault) the state vault;
/// nothing here calls `op`.
pub struct TargetInput {
    pub name: String,
    /// The provider's label (`Fly`, `GitHub`, ...).
    pub provider: String,
    /// The target instance (an app, repositories, a vault and app, a cluster location);
    /// names only (SR-1).
    pub locator: String,
    /// `None`: every vault and item this target needs could be opened (`ready`).
    /// `Some(reason)`: `grants_missing`, naming what could not be opened.
    pub grants_missing: Option<String>,
    /// The target's rows when it could be read; `Err` when its deploy credentials item or a
    /// boundary it reads could not be opened.
    pub rows: Result<Vec<Row>, Error>,
}

/// One environment's contribution to the receipt: its name, its targets (FR-56; empty for
/// a run-only environment) and, for a run-only environment, its rows, or the error that
/// stopped reading it. The caller has already read them; nothing here calls `op`.
pub struct EnvInput {
    pub name: String,
    /// The environment's targets (FR-56); `None` for a run-only environment. A deployed
    /// environment's rows live on each [`TargetInput`].
    pub target: Option<Vec<TargetInput>>,
    /// A run-only environment's rows, or the error that stopped reading it. Unused when
    /// `target` is `Some`.
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
    /// The personal keys (FR-55), as (product, key): their findings say "your".
    pub personal: std::collections::BTreeSet<(String, String)>,
    /// Settings health (#92), computed by the caller from the values it read: non-blocking
    /// findings after the readiness ones.
    pub health: Vec<crate::domain::health::HealthFinding>,
}

/// `config` of the receipt: where the configuration was read from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigRef {
    pub source: Option<String>,
}

/// `account` of the receipt: the selected account (FR-49), or `null` when none is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRef {
    pub account_id: String,
    pub by: String,
}

/// One environment × product cell of the matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixEntry {
    pub environment: String,
    /// The environment's display name (FR-55).
    pub title: String,
    pub product: String,
    /// The environment's target provider label; `null` for a run-only environment.
    pub target: Option<String>,
    /// The target's name (FR-56); `null` for a run-only environment.
    pub target_name: Option<String>,
    pub keys: usize,
    pub saved: usize,
    pub findings: usize,
    /// False when every row of the product is `TargetState::NotDelivered`; true for a
    /// run-only environment.
    pub delivered: bool,
}

/// What a finding is about: any of the account, environment, target, product or key, each
/// omitted when absent (FR-51).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// The target's name (FR-56), when the finding is about one target of an environment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// One target of an environment as the receipt lists it (FR-56): its identity and whether
/// it is `ready` or `grants_missing`, with the reason when it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetReport {
    pub environment: String,
    pub name: String,
    pub provider: String,
    pub locator: String,
    /// `ready` or `grants_missing`.
    pub state: String,
    /// Why the target is `grants_missing`; omitted when it is `ready`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Always `not_verified` (#134): `ready` sees that the state vault can be opened, which
    /// does not show that this identity can write delivery evidence there. Only a sync that
    /// records evidence proves it (`opv delivery verify`); a read-only CI reader never can.
    pub evidence_write: &'static str,
}

/// One thing a person or agent must act on, with one runnable prerequisite and one verify
/// command (FR-51).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub code: String,
    pub scope: Scope,
    pub blocking: bool,
    pub actor: String,
    pub effect: String,
    pub prerequisite: String,
    pub verify: String,
    /// One sentence for a person, when the code alone does not say it (settings health,
    /// #92). Names only, never a value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The error's own Do, for a finding made from an error (JSON `do`, text `Do:`): what a
    /// person does first, never dropped (07.07).
    #[serde(rename = "do", skip_serializing_if = "Option::is_none")]
    pub act: Option<String>,
}

/// The first step: the actor and the command of the first blocking finding, else of the
/// first finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Next {
    pub actor: String,
    pub command: String,
}

/// The FR-51 document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Receipt {
    pub receipt_id: String,
    pub opv_version: String,
    pub config: ConfigRef,
    pub account: Option<AccountRef>,
    pub matrix: Vec<MatrixEntry>,
    /// Every target of every environment, in environment then name order (FR-56).
    pub targets: Vec<TargetReport>,
    pub findings: Vec<Finding>,
    pub next: Option<Next>,
    /// RFC 3339 UTC the receipt was generated (design row `receipts`). The `--save` receipt
    /// always carries it; omitted when a caller built the receipt without a clock. A time,
    /// never a value (SR-1).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub generated_at: String,
    /// Item id → the `op item list` `version` this receipt saw (C2, as `changed` reads it).
    /// An integer, never a value or a digest of one (SR-1); omitted when none were read.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub item_versions: BTreeMap<String, u64>,
    /// The git commit (`git rev-parse HEAD`) this receipt was generated at; `None` outside a
    /// repository. Hex only, never a value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// The environments in input order, with their display names, for [`render_text`]'s
    /// columns; never serialized.
    #[serde(skip)]
    environments: Vec<(String, String)>,
}

/// Build the readiness receipt (FR-51). Deterministic: equal inputs give an equal
/// `receipt_id`, which binds the receipt to `(config.source, account, matrix, findings)`
/// and holds no value.
pub fn receipt(inputs: &Inputs<'_>, opv_version: &str) -> Receipt {
    receipt_with(inputs, opv_version, "", BTreeMap::new(), None)
}

/// [`receipt`] with the clock, item versions and git revision the `--save` receipt records
/// (design row `receipts`). `generated_at` is RFC 3339 UTC, `item_versions` is item id →
/// the `op item list` version, and `revision` is `git rev-parse HEAD` (`None` outside a
/// repository). All three are times, integers and hex only: never a value (SR-1).
fn receipt_with(
    inputs: &Inputs<'_>,
    opv_version: &str,
    generated_at: &str,
    item_versions: BTreeMap<String, u64>,
    revision: Option<String>,
) -> Receipt {
    let config = ConfigRef {
        source: inputs.config_source.clone(),
    };
    let account = inputs.account.selected.as_ref().map(|s| AccountRef {
        account_id: s.account_id.clone(),
        by: s.by.clone(),
    });
    let matrix = build_matrix(inputs);
    let targets = build_targets(inputs);
    let findings = build_findings(inputs, crate::host::Host::detect().agent_mode().is_some());
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
        targets,
        findings,
        next,
        generated_at: generated_at.to_string(),
        item_versions,
        revision,
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
    let hex = hex::encode(Sha256::digest(&bytes));
    format!("rcpt-{}", &hex[..12])
}

/// The targets the receipt lists (FR-56): one per environment and name, in environment
/// order, with the state the caller's probes found.
fn build_targets(inputs: &Inputs<'_>) -> Vec<TargetReport> {
    let mut out = Vec::new();
    for env in &inputs.envs {
        let Some(targets) = &env.target else { continue };
        for t in targets {
            let reason = target_missing(t);
            out.push(TargetReport {
                environment: env.name.clone(),
                name: t.name.clone(),
                provider: t.provider.clone(),
                locator: t.locator.clone(),
                state: match &reason {
                    None => "ready".into(),
                    Some(_) => "grants_missing".into(),
                },
                reason,
                evidence_write: "not_verified",
            });
        }
    }
    out
}

/// The matrix: one entry per environment × target × product present in that target's rows,
/// grouped by product in row order of first appearance; a run-only environment contributes
/// one entry per product from its own rows. An environment or target whose rows are `Err`
/// contributes nothing.
fn build_matrix(inputs: &Inputs<'_>) -> Vec<MatrixEntry> {
    let mut out = Vec::new();
    for env in &inputs.envs {
        if let Some(targets) = &env.target {
            // One group per target; each target's rows stand on their own (FR-56).
            for t in targets {
                let Ok(rows) = &t.rows else { continue };
                out.extend(matrix_for(
                    env,
                    Some(t.name.as_str()),
                    Some(t.provider.as_str()),
                    rows,
                ));
            }
            continue;
        }
        let Ok(rows) = &env.rows else { continue };
        out.extend(matrix_for(env, None, None, rows));
    }
    out
}

/// The matrix entries of one environment (or one target of it) from its rows.
fn matrix_for(
    env: &EnvInput,
    target_name: Option<&str>,
    provider: Option<&str>,
    rows: &[Row],
) -> Vec<MatrixEntry> {
    let mut products: Vec<&str> = Vec::new();
    for r in rows {
        if !products.contains(&r.product.as_str()) {
            products.push(&r.product);
        }
    }
    products
        .into_iter()
        .map(|product| {
            let group: Vec<&Row> = rows.iter().filter(|r| r.product == product).collect();
            let saved = group.iter().filter(|r| r.state == KeyState::Ready).count();
            let findings = group.iter().filter(|r| is_finding_state(&r.state)).count();
            let delivered =
                provider.is_none() || !group.iter().all(|r| r.target == TargetState::NotDelivered);
            MatrixEntry {
                environment: env.name.clone(),
                title: env.title.clone().unwrap_or_else(|| env.name.clone()),
                product: product.to_string(),
                target: provider.map(str::to_string),
                target_name: target_name.map(str::to_string),
                keys: group.len(),
                saved,
                findings,
                delivered,
            }
        })
        .collect()
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
            | KeyState::RulesPendingReview
    )
}

/// Hold back every uncommitted rule for an assistant (H1, design row `rule-gate`): the
/// rows keep their values to themselves and show [`KeyState::RulesPendingReview`] instead
/// of a rule result. A person at a TTY and CI never reach here.
fn gate_rows(envs: &mut [EnvInput], gate: &RuleGate<'_>) {
    for env in envs {
        if let Some(targets) = &mut env.target {
            for t in targets {
                if let Ok(rows) = &mut t.rows {
                    crate::domain::plan::apply_rule_gate(rows, gate);
                }
            }
        }
        if let Ok(rows) = &mut env.rows {
            crate::domain::plan::apply_rule_gate(rows, gate);
        }
    }
}

/// Why a target is `grants_missing`: the explicit reason the caller found, else the error
/// that stopped reading its rows (a deploy credentials item, a boundary, a sign-in).
fn target_missing(t: &TargetInput) -> Option<String> {
    t.grants_missing
        .clone()
        .or_else(|| t.rows.as_ref().err().map(|e| e.to_string()))
}

/// The FR-56 `grants_missing` finding for one target: what an owner must grant, and the
/// command that names it (`opv access <env> --target <name>`). No value appears.
fn grants_missing(env: &str, target: &str, reason: &str) -> Finding {
    Finding {
        code: "grants_missing".into(),
        scope: Scope {
            environment: Some(env.to_string()),
            target: Some(target.to_string()),
            ..Scope::default()
        },
        blocking: true,
        actor: "owner".into(),
        effect: "none".into(),
        prerequisite: format!("opv access {env} --target {target}"),
        verify: format!("opv access {env} --target {target} --json"),
        message: Some(reason.to_string()),
        act: None,
    }
}

/// True for the codes that mean a vault or item could not be opened: a grant to give.
fn is_no_access(e: &Error) -> bool {
    matches!(e.code_str(), "vault_no_access" | "item_not_found")
}

/// Whether the cause's own Next is `opv ready` (typed: its re-run under `ready`, or a built
/// `ready` command), which is the finding's verify rather than a step toward it.
fn next_is_ready(e: &Error) -> bool {
    use crate::cause::Next;
    let Some((cause, _)) = e.cause() else {
        return false;
    };
    let inv = crate::error::invocation();
    match cause.step(&inv).1 {
        Next::Rerun => inv.command == ["ready"],
        Next::Run(c) | Next::Check(c) => c.command == ["ready"],
        _ => false,
    }
}

/// What `opv ready` re-runs to verify a finding.
const VERIFY: &str = "opv ready --json";

/// The finding for an error that stopped reading an environment (or one target of it): the
/// error's own code, actor, effect, Do and next step (#157), all from its cause (design
/// §6.1: no step override). The prerequisite is the cause's Next; a cause whose Next is no
/// command, or is `ready` itself again, has its Do as the prerequisite, so an owner's step
/// is never dropped (07.07).
fn error_finding(env: &str, target: Option<&str>, e: &Error) -> Finding {
    let code = e.code_str();
    let effect = match code {
        "op_not_signed_in" | "auth_required" | "account_not_registered" | "selected_signed_out" => {
            "signs_in"
        }
        _ => "none",
    };
    let (act, next) = super::own_step(e);
    // The cause's own Next, unless it is `ready` itself (this finding's verify): then its
    // Do is what to do first.
    let next = next.filter(|_| !next_is_ready(e));
    let prerequisite = next.clone().or_else(|| act.clone()).unwrap_or_default();
    Finding {
        code: code.into(),
        scope: Scope {
            environment: Some(env.to_string()),
            target: target.map(str::to_string),
            ..Scope::default()
        },
        blocking: true,
        actor: if e.human_required() { "owner" } else { "agent" }.into(),
        effect: effect.into(),
        // The Do is shown on its own line only when it is not the prerequisite already.
        act: act.filter(|a| *a != prerequisite),
        prerequisite,
        verify: VERIFY.into(),
        message: None,
    }
}

/// Each row's own finding (FR-51), scoped to its environment and, for a deployed
/// environment, the target that delivered it.
fn row_findings(
    out: &mut Vec<Finding>,
    inputs: &Inputs<'_>,
    env: &EnvInput,
    target: Option<&str>,
    rows: &[Row],
) {
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
            KeyState::RulesPendingReview => "rules_pending_review",
            _ => continue,
        };
        let label = key_label(&r.product, &r.key);
        let verify = match target {
            Some(t) => format!(
                "opv status {} --target {t} --product {}",
                env.name, r.product
            ),
            None => format!("opv status {} --product {}", env.name, r.product),
        };
        let product = Some(r.product.clone());
        out.push(Finding {
            code: code.into(),
            scope: Scope {
                environment: Some(env.name.clone()),
                target: target.map(str::to_string),
                product,
                key: Some(r.key.clone()),
                account: None,
            },
            blocking: true,
            actor: "owner".into(),
            effect: "writes_1password".into(),
            prerequisite: format!("opv open {label} --env {}", env.name),
            verify,
            message: None,
            act: None,
        });
    }
}

/// The findings, in order (FR-51): every account finding, then each environment's error,
/// then each row's own finding. A `SourceBlocked` row produces none (its source's does).
/// `agent` is true on assistant surfaces (MCP or a marker): cross-tier health warnings are
/// hidden there, while a person at a terminal and CI still see them.
fn build_findings(inputs: &Inputs<'_>, agent: bool) -> Vec<Finding> {
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
            // Advisory (#142): opv names accounts by ID and ignores other accounts'
            // session variables when it signs in, so these never block readiness.
            blocking: !matches!(
                f.code.as_str(),
                "discovery_unavailable"
                    | "shared_sign_in_address"
                    | "session_for_other_account"
                    | "stale_session_variable"
            ),
            actor: "owner".into(),
            effect: effect.into(),
            prerequisite: f.next.clone().unwrap_or_else(|| "opv account list".into()),
            verify: "opv account list --json".into(),
            message: None,
            act: None,
        });
    }
    for env in &inputs.envs {
        if let Some(targets) = &env.target {
            for t in targets {
                let Some(reason) = target_missing(t) else {
                    continue;
                };
                // FR-55: an environment meant for others (its audience) and an access
                // error is not a problem to fix.
                let no_access = t.rows.as_ref().err().is_some_and(is_no_access);
                if let (Some(audience), true) = (&env.audience, no_access) {
                    out.push(Finding {
                        code: "not_for_you".into(),
                        scope: Scope {
                            environment: Some(env.name.clone()),
                            target: Some(t.name.clone()),
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
                        message: None,
                        act: None,
                    });
                    continue;
                }
                // #157: only a vault or item that cannot be opened is a grant to give; any
                // other cause (signed out, a missing CLI, a timeout, the provider's own
                // preflight) is reported as itself, with its own step.
                match &t.rows {
                    Err(e) if t.grants_missing.is_none() && !no_access => {
                        out.push(error_finding(&env.name, Some(&t.name), e));
                    }
                    _ => out.push(grants_missing(&env.name, &t.name, &reason)),
                }
            }
            continue;
        }
        let Err(e) = &env.rows else { continue };
        // FR-55: an environment meant for others (its audience) that this person cannot
        // open is not a problem to fix.
        let no_access = is_no_access(e);
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
                message: None,
                act: None,
            });
            continue;
        }
        out.push(error_finding(&env.name, None, e));
    }
    for env in &inputs.envs {
        if let Some(targets) = &env.target {
            for t in targets {
                if t.grants_missing.is_some() {
                    continue;
                }
                let Ok(rows) = &t.rows else { continue };
                row_findings(&mut out, inputs, env, Some(&t.name), rows);
            }
            continue;
        }
        let Ok(rows) = &env.rows else { continue };
        row_findings(&mut out, inputs, env, None, rows);
    }
    // Settings health (#92): likely-wrong values, never blocking. The scope is the first
    // environment named (in configured order), where `opv open` takes the person to fix it.
    // Cross-tier warnings (the same value across environments, or under two keys) are for a
    // person at a terminal and CI; they are hidden from assistant surfaces (agent mode).
    // Health stays advisory everywhere: a health finding is never blocking.
    for h in &inputs.health {
        if agent && crate::domain::health::is_cross_tier(h.code) {
            continue;
        }
        let Some(env) = h.environments.first() else {
            continue;
        };
        let (product, label) = (Some(h.product.clone()), key_label(&h.product, &h.key));
        let finding = Finding {
            code: h.code.into(),
            scope: Scope {
                environment: Some(env.clone()),
                target: None,
                product,
                key: Some(h.key.clone()),
                account: None,
            },
            // Advisory (#92): a person judges a likely-wrong value; readiness never fails
            // on one, so `opv ready`'s exit code never changes.
            blocking: false,
            actor: "owner".into(),
            effect: "writes_1password".into(),
            prerequisite: format!("opv open {label} --env {env}"),
            verify: "opv ready --json".into(),
            message: Some(h.message.clone()),
            act: None,
        };
        debug_assert!(!finding.blocking, "a health finding never blocks");
        out.push(finding);
    }
    out
}

/// Render `r` for a person: the counts line, the product × environment grid, the findings
/// with one line each, and `Next` when set. Names and IDs only, never a value.
pub fn render_text(r: &Receipt, out: &mut dyn Write) -> Result<(), Error> {
    let blocking = r.findings.iter().filter(|f| f.blocking).count();
    writeln!(
        out,
        "ready: {blocking} blocking · {} · receipt {}",
        super::plural(r.findings.len(), "finding", "findings"),
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

    if !r.targets.is_empty() {
        writeln!(out, "Targets:").map_err(super::write_err)?;
        for t in &r.targets {
            match &t.reason {
                None => writeln!(
                    out,
                    "  {} {} {} · {} ready",
                    t.environment, t.name, t.provider, t.locator
                ),
                Some(reason) => writeln!(
                    out,
                    "  {} {} {} · {} grants_missing: {reason}",
                    t.environment, t.name, t.provider, t.locator
                ),
            }
            .map_err(super::write_err)?;
        }
    }

    if r.findings.is_empty() {
        // Claim only what was read: one environment, or every one (07.30, X26).
        let claim = match envs.as_slice() {
            [(name, _)] => format!("every declared key in {name} is saved and {name} was read"),
            _ => "every declared key is saved and every environment was read".to_string(),
        };
        writeln!(out, "Nothing needs attention: {claim}.").map_err(super::write_err)?;
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
        if let Some(m) = &f.message {
            writeln!(out, "      {m}").map_err(super::write_err)?;
        }
        if let Some(a) = &f.act {
            writeln!(out, "      Do: {a}").map_err(super::write_err)?;
        }
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
    if let Some(t) = &scope.target {
        parts.push(t.clone());
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

/// One `op vault user list` for `vault_id` (FR-56): `None` when this person can see the
/// vault, else the `grants_missing` reason naming it. The vault ID is never a value.
///
/// Listing a vault's users needs managing it (#157): a person who can read the vault but not
/// manage it gets no list, so one `op vault get` (exit status only; its output names the
/// vault and is dropped unread, SR-1) decides; only when that fails too is a grant missing.
fn state_vault_grants(r: &dyn crate::runner::CommandRunner, vault_id: &str) -> Option<String> {
    match crate::adapters::onepassword_init::vault_users(r, vault_id, &crate::host::Host::detect) {
        Ok(Some(_)) => None,
        Ok(None) => {
            let _ = crate::runner::take_failure_excerpt();
            let opened = r
                .probe(
                    &crate::runner::Call::new(
                        "op",
                        &["vault", "get", vault_id, "--format", "json"],
                    ),
                    crate::runner::PROBE_TIMEOUT,
                )
                .map(|o| o.status == 0);
            match opened {
                // A probe that could not run cannot tell: nothing is claimed missing.
                Ok(true) | Err(_) => None,
                Ok(false) => {
                    // Its stderr must not attach to what is reported (NR-31).
                    let _ = crate::runner::take_failure_excerpt();
                    Some(format!("state vault {vault_id} cannot be opened"))
                }
            }
        }
        Err(e) => Some(format!("state vault {vault_id}: {e}")),
    }
}

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
    run_at(
        fleet,
        config_source,
        only,
        r,
        json,
        save,
        &crate::domain::provenance::utc_now(),
        out,
    )
}

/// [`run`] with the clock the `--save` receipt records, injected so a test is deterministic
/// (design row `receipts`).
#[allow(clippy::too_many_arguments)]
pub fn run_at(
    fleet: &crate::domain::Fleet,
    config_source: Option<&str>,
    only: Option<&str>,
    r: &dyn crate::runner::CommandRunner,
    json: bool,
    save: Option<&std::path::Path>,
    generated_at: &str,
    out: &mut dyn Write,
) -> Result<(), Error> {
    if let Some(e) = only {
        super::environment(fleet, e)?;
    }
    // #157: nobody signed in is one finding of its own, never every target's missing grant.
    // L9: an account op does not know is not a failure here: the account report below names
    // it (`selected_account_absent`) with its step, `opv login --add`.
    match crate::adapters::onepassword::require_session(r, &crate::host::Host::detect, "opv ready")
    {
        Err(e) if e.code_str() == "account_not_registered" => {}
        other => other?,
    }
    let account = super::account::gather(r, None);
    // FR-55: the environments' own order, then their keys; never a fixed list.
    let mut ordered: Vec<(&String, &crate::domain::Environment)> = fleet
        .environments
        .iter()
        .filter(|(name, _)| only.is_none_or(|o| o == name.as_str()))
        .collect();
    ordered.sort_by_key(|(name, env)| (env.order.unwrap_or(i64::MAX), (*name).clone()));
    // Each environment's fields, copied during its one read, for the health checks (#92).
    let mut kept: Vec<(String, bool, Vec<crate::domain::plan::ItemField>)> = Vec::new();
    let mut envs: Vec<EnvInput> = Vec::new();
    for (name, env) in ordered {
        if env.targets.is_empty() {
            // A run-only environment: one read, and its rows stand on their own (FR-56).
            let mut fields = Vec::new();
            let rows = super::status::env_rows_keeping(
                fleet,
                name,
                None,
                r,
                Some(&mut fields),
                super::tidy::Mode::Inspect,
            );
            if rows.is_ok() {
                kept.push((name.clone(), false, fields));
            }
            envs.push(EnvInput {
                name: name.clone(),
                target: None,
                rows,
                title: env.title.clone(),
                audience: env.audience.clone(),
            });
            continue;
        }
        // Every named target is read and reported (FR-56): one probe of its deploy
        // credentials, the boundaries it reads and its provider's preflight.
        let mut fields = Vec::new();
        let mut reading = true;
        let mut targets: Vec<TargetInput> = Vec::new();
        // One visibility check per state vault the targets need (FR-56), not per target.
        let mut vault_checks: std::collections::HashMap<String, Option<String>> =
            std::collections::HashMap::new();
        // The state vault is checked with the environment's own account (FR-40), as
        // `status` reads its rows.
        let env_runner = super::signin::open(fleet, name, r, super::signin::Reach::Store)?;
        for (tname, t) in &env.targets {
            let keep = if reading { Some(&mut fields) } else { None };
            let rows = super::status::env_rows_keeping(
                fleet,
                name,
                Some((tname.as_str(), t.config.as_ref())),
                r,
                keep,
                super::tidy::Mode::Inspect,
            );
            let readable = rows.is_ok();
            if readable {
                reading = false;
            }
            let grants_missing = if readable {
                vault_checks
                    .entry(t.state_vault_id.clone())
                    .or_insert_with(|| state_vault_grants(&env_runner, &t.state_vault_id))
                    .clone()
            } else {
                None
            };
            targets.push(TargetInput {
                name: tname.clone(),
                provider: t.config.provider().label().to_string(),
                locator: t.config.target_locator(),
                grants_missing,
                rows,
            });
        }
        if !reading {
            kept.push((name.clone(), true, std::mem::take(&mut fields)));
        }
        envs.push(EnvInput {
            name: name.clone(),
            target: Some(targets),
            rows: Ok(Vec::new()),
            title: env.title.clone(),
            audience: env.audience.clone(),
        });
    }
    // H1 (design row `rule-gate`): a rule is evaluated for an assistant only once it is
    // committed on the repository's default branch. An agent's rows show
    // `rules_pending_review` instead of a pass or a fail; a person at a TTY and CI are
    // untouched. The gate reads rules, never a value.
    if crate::host::Host::detect().agent_mode.is_some() {
        let repo = crate::config_store::git_toplevel(r);
        let root = repo.as_deref().unwrap_or(std::path::Path::new("."));
        match rule_source(r, root, fleet) {
            Ok(source) => {
                let gate = RuleGate {
                    agent: true,
                    pending: &|p, k| source.status(fleet, p, k) == RuleStatus::PendingReview,
                };
                gate_rows(&mut envs, &gate);
            }
            // Without a readable committed contract no rule is committed: hold them all.
            Err(_) => {
                let gate = RuleGate {
                    agent: true,
                    pending: &|_, _| true,
                };
                gate_rows(&mut envs, &gate);
            }
        }
    }
    let values: Vec<crate::domain::health::EnvValues<'_>> = kept
        .iter()
        .map(
            |(name, deployed, fields)| crate::domain::health::EnvValues {
                name,
                title: fleet
                    .environments
                    .get(name)
                    .and_then(|e| e.title.as_deref()),
                deployed: *deployed,
                fields,
                tier: fleet.environments[name].tier,
            },
        )
        .collect();
    let health = crate::domain::health::check(fleet, &values);
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
    // The saved receipt records what this run saw: the item versions of each boundary
    // (`op item list`, as `changed` reads them) and the git revision. Read only when a
    // receipt is saved; the plain report needs neither.
    let (item_versions, revision) = if save.is_some() {
        (read_item_versions(fleet, only, r)?, git_revision(r))
    } else {
        (BTreeMap::new(), None)
    };
    let doc = receipt_with(
        &Inputs {
            config_source: config_source.map(str::to_string),
            account: &account,
            envs,
            personal,
            health,
        },
        env!("CARGO_PKG_VERSION"),
        if save.is_some() { generated_at } else { "" },
        item_versions,
        revision,
    );
    // The receipt is plain data: failing to serialize it is opv's own bug.
    let bug = |_| {
        Error::from(crate::cause::Cause::Bug {
            site: "ready receipt serialization",
        })
    };
    let mut v = serde_json::to_value(&doc).map_err(bug)?;
    v["schema_version"] = serde_json::json!(crate::json::SCHEMA_VERSION);
    if let Some(path) = save {
        let text = serde_json::to_string_pretty(&v).map_err(bug)?;
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

/// The git commit of the repository, `git rev-parse HEAD` through the runner; `None`
/// outside a repository (design row `receipts`). Hex only, never a value.
fn git_revision(r: &dyn crate::runner::CommandRunner) -> Option<String> {
    match r.probe(
        &crate::runner::Call::new("git", &["rev-parse", "HEAD"]),
        crate::runner::PROBE_TIMEOUT,
    ) {
        Ok(o) if o.status == 0 => {
            let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
            (!text.is_empty()).then_some(text)
        }
        _ => {
            // Not a repository, no git, or no commit yet: its stderr explains nothing later.
            let _ = crate::runner::take_failure_excerpt();
            None
        }
    }
}

/// One row of `op item list --vault <vault> --format json` (as `changed` reads them).
#[derive(serde::Deserialize)]
struct ListRow {
    id: String,
    #[serde(default)]
    version: u64,
}

/// Item id → the `op item list` `version` of each boundary item in scope (design row
/// `receipts`, the versions `changed` reads). One listing per vault, as `changed` does.
fn read_item_versions(
    fleet: &crate::domain::Fleet,
    only: Option<&str>,
    r: &dyn crate::runner::CommandRunner,
) -> Result<BTreeMap<String, u64>, Error> {
    let mut versions = BTreeMap::new();
    for (name, env) in &fleet.environments {
        if only.is_some_and(|o| o != name.as_str()) {
            continue;
        }
        for b in env.boundaries.values() {
            let args = [
                "item",
                "list",
                "--vault",
                b.vault_id.as_str(),
                "--format",
                "json",
            ];
            let out = crate::adapters::onepassword::read_op(r, &args, &crate::host::Host::detect)?;
            if out.status != 0 || out.stdout.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            if let Ok(rows) = serde_json::from_slice::<Vec<ListRow>>(&out.stdout) {
                for row in rows {
                    versions.insert(row.id, row.version);
                }
            }
        }
    }
    Ok(versions)
}
