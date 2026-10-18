//! The view model of `opv ui` (#82): one snapshot built only from opv's own JSON documents
//! (`config export --json`, `ready --json`, `status`/`inventory --json`), so the TUI keeps no
//! state of its own and shows exactly what the CLI would. Names, states, rules and config
//! values only: a secret's value is never in any of these documents. The documents are read
//! as types ([`super::docs`]); a command that failed is a [`Problem`] with its error's steps,
//! never an empty document (07.02).

use std::collections::BTreeMap;

pub use super::docs::Source;
use super::docs::{Failure, InventoryDoc, ReadyDoc, RowsDoc, fetch, fetch_config};
use crate::domain::Fleet;

/// One target of an environment (FR-56): its name and its provider's label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetView {
    pub name: String,
    /// `Fly`, `GitHub`, ...
    pub provider: String,
}

/// One environment, from the configuration and the receipt (FR-55). Never hard-coded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvView {
    pub key: String,
    pub title: String,
    /// The environment's targets (FR-56), in name order; empty: run-only (local).
    pub targets: Vec<TargetView>,
    pub audience: Option<String>,
    pub guarded: bool,
}

impl EnvView {
    /// True when opv delivers this environment to at least one target.
    pub fn deployed(&self) -> bool {
        !self.targets.is_empty()
    }

    /// Where it delivers, in a few words: `local`, the one target's provider, or
    /// `<n> targets`.
    pub fn place(&self) -> String {
        match self.targets.as_slice() {
            [] => "local".into(),
            [one] => one.provider.clone(),
            many => format!("{} targets", many.len()),
        }
    }
}

/// One declared key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyView {
    pub name: String,
    pub kind: String,
    pub personal: bool,
    pub immutable: bool,
    pub from: Option<String>,
    pub guidance: String,
    pub environments: Vec<String>,
}

/// One product and its keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductView {
    pub name: String,
    pub source_only: bool,
    pub keys: Vec<KeyView>,
}

/// One key in one environment: its state words as `status` prints them (a run-only
/// environment's, from `inventory`'s value state).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cell {
    /// `saved`, `missing`, `failing_rule`, `wrong_kind`, `skipped`, `source_blocked`; from
    /// the inventory also `empty`, `placeholder` and `unreadable`.
    pub state: String,
    /// `present`, `absent`, `would_change`, `not_delivered`, or none (config, run-only).
    pub target: Option<String>,
    pub rule: Option<String>,
}

/// One finding of the receipt (FR-51).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub code: String,
    pub environment: Option<String>,
    pub product: Option<String>,
    pub key: Option<String>,
    pub blocking: bool,
    pub actor: String,
    pub effect: String,
    pub prerequisite: String,
    /// The finding's sentence (settings health, #92); names only.
    pub message: Option<String>,
}

/// One environment × product summary of the receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub keys: usize,
    pub saved: usize,
    pub findings: usize,
    pub delivered: bool,
}

/// A document that could not be read: which command, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// What was being read, as `readiness (opv ready)` or `opv status prod`.
    pub what: String,
    pub failure: Failure,
}

impl Problem {
    /// `could not read <what>: <message>`, then the error's own steps.
    pub fn lines(&self) -> Vec<String> {
        let mut lines = self.failure.lines().into_iter();
        let first = lines.next().unwrap_or_default();
        std::iter::once(format!("could not read {}: {first}", self.what))
            .chain(lines.map(|l| format!("  {l}")))
            .collect()
    }
}

/// Everything the screens show.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub config_source: Option<String>,
    pub account: Option<String>,
    pub receipt_id: Option<String>,
    pub envs: Vec<EnvView>,
    pub products: Vec<ProductView>,
    /// (environment, product) → summary.
    pub summary: BTreeMap<(String, String), Summary>,
    /// (environment, product, key) → cell.
    pub cells: BTreeMap<(String, String, String), Cell>,
    pub findings: Vec<Finding>,
    /// (actor, command) of the first step.
    pub next: Option<(String, String)>,
    /// Documents that could not be read, with the command's error and its steps.
    pub problems: Vec<Problem>,
}

/// How notable a row's target state is when an environment has several targets: its cell
/// shows the most notable one.
fn notable(target_state: Option<&str>) -> u8 {
    match target_state {
        Some("absent") => 3,
        Some("would_change") => 2,
        Some("present") | None => 1,
        Some(_) => 0,
    }
}

impl Snapshot {
    /// Read the configuration, the receipt, then each environment's rows.
    pub fn gather(source: &dyn Source) -> Snapshot {
        let mut snap = Snapshot::default();
        match fetch_config(source) {
            Ok(fleet) => snap.read_config(&fleet),
            Err(failure) => snap.problem("the configuration", failure),
        }
        match fetch::<ReadyDoc>(source, &["ready", "--json"]) {
            Ok(ready) => snap.read_ready(ready),
            Err(failure) => snap.problem("readiness (opv ready)", failure),
        }
        // A deployed environment's rows come from `opv status`; a run-only one has no
        // target to read, so its cells come from `opv inventory`'s value states.
        let envs = snap.envs.clone();
        for env in &envs {
            if env.deployed() {
                match fetch::<RowsDoc>(source, &["status", &env.key, "--json"]) {
                    Ok(doc) => snap.read_rows(&env.key, doc),
                    Err(failure) => snap.problem(&format!("opv status {}", env.key), failure),
                }
            } else {
                match fetch::<InventoryDoc>(source, &["inventory", "--env", &env.key, "--json"]) {
                    Ok(doc) => snap.read_inventory(doc),
                    Err(failure) => {
                        snap.problem(&format!("opv inventory --env {}", env.key), failure)
                    }
                }
            }
        }
        snap
    }

    fn problem(&mut self, what: &str, failure: Failure) {
        self.problems.push(Problem {
            what: what.to_string(),
            failure,
        });
    }

    /// The environments, in their order, and the products, from the configuration as opv
    /// parses it: targets are read where 0.7+ keeps them (07.01).
    fn read_config(&mut self, fleet: &Fleet) {
        let mut envs: Vec<(i64, EnvView)> = fleet
            .environments
            .iter()
            .map(|(key, e)| {
                let targets = e
                    .targets
                    .iter()
                    .map(|(name, t)| TargetView {
                        name: name.clone(),
                        provider: t.config.provider().label().to_string(),
                    })
                    .collect();
                (
                    e.order.unwrap_or(i64::MAX),
                    EnvView {
                        key: key.clone(),
                        title: e.title.clone().unwrap_or_else(|| key.clone()),
                        targets,
                        audience: e.audience.clone(),
                        guarded: e.confirm_env,
                    },
                )
            })
            .collect();
        envs.sort_by(|a, b| (a.0, &a.1.key).cmp(&(b.0, &b.1.key)));
        self.envs = envs.into_iter().map(|(_, e)| e).collect();
        self.products = fleet
            .products
            .iter()
            .map(|(name, p)| ProductView {
                name: name.clone(),
                source_only: p.source_only,
                keys: p
                    .keys
                    .iter()
                    .map(|(key, k)| KeyView {
                        name: key.clone(),
                        kind: crate::app::kind_label(k.kind).to_string(),
                        personal: k.personal,
                        immutable: k.immutable,
                        from: k.from.clone(),
                        guidance: k.guidance.clone(),
                        environments: k.envs_in(fleet),
                    })
                    .collect(),
            })
            .collect();
    }

    fn read_ready(&mut self, ready: ReadyDoc) {
        self.config_source = ready.config.source;
        self.account = ready.account.map(|a| a.account_id);
        self.receipt_id = Some(ready.receipt_id);
        for m in ready.matrix {
            self.summary.insert(
                (m.environment, m.product),
                Summary {
                    keys: m.keys,
                    saved: m.saved,
                    findings: m.findings,
                    delivered: m.delivered,
                },
            );
        }
        self.findings = ready
            .findings
            .into_iter()
            .map(|f| Finding {
                code: f.code,
                environment: f.scope.environment,
                product: f.scope.product,
                key: f.scope.key,
                blocking: f.blocking,
                actor: f.actor,
                effect: f.effect,
                prerequisite: f.prerequisite,
                message: f.message,
            })
            .collect();
        // A personal key's step has no command (FR-55): nothing for `n` to run.
        self.next = ready
            .next
            .and_then(|n| n.command.map(|command| (n.actor, command)));
    }

    /// One environment's rows. With several targets a key has one row per target; its cell
    /// shows the most notable target state.
    fn read_rows(&mut self, env: &str, doc: RowsDoc) {
        for r in doc.rows {
            let Some(product) = r.product else {
                continue;
            };
            let cell = Cell {
                state: r.state,
                target: r.target_state,
                rule: r.rule,
            };
            let at = (env.to_string(), product, r.key);
            let keep = self
                .cells
                .get(&at)
                .is_some_and(|c| notable(c.target.as_deref()) >= notable(cell.target.as_deref()));
            if !keep {
                self.cells.insert(at, cell);
            }
        }
    }

    /// A run-only environment's cells, from the inventory's value states in `status`'s
    /// words where one exists (`set` is `saved`, `absent` is `missing`, `malformed` is
    /// `failing_rule` with its rule, `not_wanted` is `skipped`).
    fn read_inventory(&mut self, doc: InventoryDoc) {
        use crate::domain::value_state::ValueState;
        for c in doc.cells {
            let (state, rule) = match c.state {
                ValueState::Set => ("saved", None),
                ValueState::Absent => ("missing", None),
                ValueState::Empty => ("empty", None),
                ValueState::Placeholder => ("placeholder", None),
                ValueState::Malformed { rule } => ("failing_rule", Some(rule)),
                ValueState::Unreadable { .. } => ("unreadable", None),
                ValueState::NotWanted { .. } => ("skipped", None),
            };
            self.cells.insert(
                (c.env, c.product, c.key),
                Cell {
                    state: state.to_string(),
                    target: None,
                    rule,
                },
            );
        }
    }

    /// The findings about `product`/`key` (readiness and settings health), in receipt order.
    pub fn findings_for(&self, product: &str, key: &str) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| {
                f.key.as_deref() == Some(key) && f.product.as_deref().is_none_or(|p| p == product)
            })
            .collect()
    }

    /// The environment with key `key`.
    pub fn env(&self, key: &str) -> Option<&EnvView> {
        self.envs.iter().find(|e| e.key == key)
    }

    /// The products shown in grids: every declared product (source-only ones last).
    pub fn product_names(&self) -> Vec<&str> {
        let mut v: Vec<&ProductView> = self.products.iter().collect();
        v.sort_by_key(|p| (p.source_only, p.name.clone()));
        v.iter().map(|p| p.name.as_str()).collect()
    }

    /// Every key that reads `product/key` with `from` (shared values, FR-45, FR-47).
    pub fn consumers(&self, product: &str, key: &str) -> Vec<(String, String)> {
        let target = format!("{product}/{key}");
        self.products
            .iter()
            .flat_map(|p| {
                p.keys
                    .iter()
                    .filter(|k| k.from.as_deref() == Some(target.as_str()))
                    .map(move |k| (p.name.clone(), k.name.clone()))
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "model_tests.rs"]
pub(crate) mod tests;
