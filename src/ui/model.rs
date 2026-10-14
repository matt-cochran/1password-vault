//! The view model of `opv ui` (#82): one snapshot built only from opv's own JSON documents
//! (`config export --json`, `ready --json`, `status`/`check --json`), so the TUI keeps no
//! state of its own and shows exactly what the CLI would. Names, states, rules and config
//! values only: a secret's value is never in any of these documents.

use std::collections::BTreeMap;

use serde_json::Value;

/// Where the JSON documents come from: the opv binary itself, or fixtures in tests.
pub trait Source {
    /// The stdout of `opv <args>` (with `--json` in `args`) as JSON, whatever the exit code;
    /// `Err` with a short reason when it did not print a JSON document.
    fn json(&self, args: &[&str]) -> Result<Value, String>;
}

/// One environment, from the configuration and the receipt (FR-55). Never hard-coded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvView {
    pub key: String,
    pub title: String,
    /// The target's provider label (`Fly`, `GitHub`, ...); `None`: run-only (local).
    pub target: Option<String>,
    pub audience: Option<String>,
    pub guarded: bool,
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

/// One key in one environment: its state words as `status`/`check` print them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cell {
    /// `saved`, `missing`, `failing_rule`, `wrong_kind`, `skipped`, `source_blocked`.
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
    pub keys: u64,
    pub saved: u64,
    pub findings: u64,
    pub delivered: bool,
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
    /// Documents that could not be read, by command, for the status line.
    pub problems: Vec<String>,
}

fn s(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

impl Snapshot {
    /// Read the configuration, the receipt, then each environment's rows.
    pub fn gather(source: &dyn Source) -> Snapshot {
        let mut snap = Snapshot::default();
        match source.json(&["config", "export", "--json"]) {
            Ok(config) => snap.read_config(&config),
            Err(why) => snap.problems.push(format!("config export: {why}")),
        }
        match source.json(&["ready", "--json"]) {
            Ok(ready) => snap.read_ready(&ready),
            Err(why) => snap.problems.push(format!("ready: {why}")),
        }
        let envs = snap.envs.clone();
        for env in &envs {
            if env.target.is_some() {
                match source.json(&["status", &env.key, "--json"]) {
                    Ok(doc) => snap.read_rows(&env.key, &doc),
                    Err(why) => snap.problems.push(format!("status {}: {why}", env.key)),
                }
            } else {
                for p in snap.products.clone() {
                    if p.source_only || !p.keys.iter().any(|k| k.environments.contains(&env.key)) {
                        continue;
                    }
                    let args = [
                        "check",
                        env.key.as_str(),
                        "--product",
                        p.name.as_str(),
                        "--json",
                    ];
                    match source.json(&args) {
                        Ok(doc) => snap.read_rows(&env.key, &doc),
                        Err(why) => snap.problems.push(format!("check {}: {why}", env.key)),
                    }
                }
            }
        }
        snap
    }

    fn read_config(&mut self, config: &Value) {
        let mut envs: Vec<(i64, EnvView)> = Vec::new();
        if let Some(map) = config["environments"].as_object() {
            for (key, e) in map {
                let target = crate::adapters::registry::PROVIDERS
                    .iter()
                    .find(|p| e.get(p.section()).is_some())
                    .map(|p| p.label().to_string());
                envs.push((
                    e["order"].as_i64().unwrap_or(i64::MAX),
                    EnvView {
                        key: key.clone(),
                        title: s(&e["title"]).unwrap_or_else(|| key.clone()),
                        target,
                        audience: s(&e["audience"]),
                        guarded: e["confirm_env"].as_bool().unwrap_or(false),
                    },
                ));
            }
        }
        envs.sort_by(|a, b| (a.0, &a.1.key).cmp(&(b.0, &b.1.key)));
        self.envs = envs.into_iter().map(|(_, e)| e).collect();
        // Simple profile: keys at the top level, one implicit product.
        let mut products = Vec::new();
        let keys_of = |keys: &Value| -> Vec<KeyView> {
            keys.as_object()
                .map(|m| {
                    m.iter()
                        .map(|(name, k)| KeyView {
                            name: name.clone(),
                            kind: s(&k["kind"]).unwrap_or_else(|| "secret".into()),
                            personal: k["personal"].as_bool().unwrap_or(false),
                            immutable: k["immutable"].as_bool().unwrap_or(false),
                            from: s(&k["from"]),
                            guidance: s(&k["guidance"]).unwrap_or_default(),
                            environments: k["environments"]
                                .as_array()
                                .map(|a| a.iter().filter_map(s).collect())
                                .unwrap_or_default(),
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        if let Some(map) = config["products"].as_object() {
            for (name, p) in map {
                products.push(ProductView {
                    name: name.clone(),
                    source_only: p["source_only"].as_bool().unwrap_or(false),
                    keys: keys_of(&p["keys"]),
                });
            }
        }
        self.products = products;
    }

    fn read_ready(&mut self, ready: &Value) {
        self.config_source = s(&ready["config"]["source"]);
        self.account = s(&ready["account"]["account_id"]);
        self.receipt_id = s(&ready["receipt_id"]);
        for m in ready["matrix"].as_array().into_iter().flatten() {
            let (Some(env), Some(product)) = (s(&m["environment"]), s(&m["product"])) else {
                continue;
            };
            self.summary.insert(
                (env, product),
                Summary {
                    keys: m["keys"].as_u64().unwrap_or(0),
                    saved: m["saved"].as_u64().unwrap_or(0),
                    findings: m["findings"].as_u64().unwrap_or(0),
                    delivered: m["delivered"].as_bool().unwrap_or(true),
                },
            );
        }
        for f in ready["findings"].as_array().into_iter().flatten() {
            self.findings.push(Finding {
                code: s(&f["code"]).unwrap_or_default(),
                environment: s(&f["scope"]["environment"]),
                product: s(&f["scope"]["product"]),
                key: s(&f["scope"]["key"]),
                blocking: f["blocking"].as_bool().unwrap_or(false),
                actor: s(&f["actor"]).unwrap_or_default(),
                effect: s(&f["effect"]).unwrap_or_default(),
                prerequisite: s(&f["prerequisite"]).unwrap_or_default(),
                message: s(&f["message"]),
            });
        }
        if let (Some(a), Some(c)) = (s(&ready["next"]["actor"]), s(&ready["next"]["command"])) {
            self.next = Some((a, c));
        }
    }

    fn read_rows(&mut self, env: &str, doc: &Value) {
        for r in doc["rows"].as_array().into_iter().flatten() {
            let (Some(product), Some(key)) = (s(&r["product"]), s(&r["key"])) else {
                continue;
            };
            self.cells.insert(
                (env.to_string(), product, key),
                Cell {
                    state: s(&r["state"]).unwrap_or_default(),
                    target: s(&r["target"]),
                    rule: s(&r["rule"]),
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
