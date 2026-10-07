//! Sync planner (FR-5, FR-8, FR-14, FR-16, §10). Pure: no `op`, no `flyctl`, no I/O.
//!
//! `build` joins the declared fleet, the 1Password item fields and the names on Fly into a
//! `SyncPlan`. Rows, extras, prune and held lists hold names only. Values appear only in
//! `stage` (secrets, wrapped in `SecretValue`) and `config` (non-secret config values).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::domain::model::{Fleet, Kind};
use crate::domain::rules;
use crate::domain::secret::SecretValue;

/// One field of the 1Password item, as produced by the source adapter.
/// `Debug` never prints the value.
pub struct ItemField {
    pub section: String,
    pub label: String,
    pub kind: Kind,
    pub value: SecretValue,
}

impl fmt::Debug for ItemField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemField")
            .field("section", &self.section)
            .field("label", &self.label)
            .field("kind", &self.kind)
            .field("value", &"<REDACTED>")
            .finish()
    }
}

/// A secret listed on the Fly app. `digest` is Fly's digest when it reports one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlySecret {
    pub name: String,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Missing,
    WrongKind,
    RuleFailed(&'static str),
    Ready,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    Absent,
    Present,
    WouldChange,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub product: String,
    pub key: String,
    pub kind: Kind,
    pub state: KeyState,
    /// Only meaningful for secrets. Secrets absent from Fly are `Absent`; `Present` and
    /// `WouldChange` need both digests; everything else present on Fly is `Unknown`.
    /// Config keys are always `Unknown` (they are not Fly secrets).
    pub target: TargetState,
    pub guidance: String,
}

pub struct SyncPlan {
    pub rows: Vec<Row>,
    /// (section, label) in the item but not declared for any environment of that product.
    pub extras: Vec<(String, String)>,
    /// (fly name, value), secrets only. The value is the one returned by `rules::check`
    /// (possibly transformed).
    pub stage: Vec<(String, SecretValue)>,
    /// (product, key): immutable, present on Fly, not rotated. Not staged.
    pub held_immutable: Vec<(String, String)>,
    /// Fly names rendered from the template for declared secret keys of this fleet that are
    /// on Fly but not desired in this environment (key not declared for it, or skipped by
    /// mode). Names the template does not produce for a declared key are never pruned.
    pub prune: Vec<String>,
    /// product -> key -> value, config keys only.
    pub config: BTreeMap<String, BTreeMap<String, String>>,
}

impl fmt::Debug for SyncPlan {
    /// Names only: staged values are secret, and config values are omitted for uniformity.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stage: Vec<&str> = self.stage.iter().map(|(n, _)| n.as_str()).collect();
        let config: BTreeMap<&str, Vec<&str>> = self
            .config
            .iter()
            .map(|(p, m)| (p.as_str(), m.keys().map(String::as_str).collect()))
            .collect();
        f.debug_struct("SyncPlan")
            .field("rows", &self.rows)
            .field("extras", &self.extras)
            .field("stage", &stage)
            .field("held_immutable", &self.held_immutable)
            .field("prune", &self.prune)
            .field("config_keys", &config)
            .finish()
    }
}

impl SyncPlan {
    /// Rows that stop a sync: Missing, WrongKind or RuleFailed.
    pub fn blocking(&self) -> usize {
        self.rows
            .iter()
            .filter(|r| {
                matches!(
                    r.state,
                    KeyState::Missing | KeyState::WrongKind | KeyState::RuleFailed(_)
                )
            })
            .count()
    }
}

/// Plan a sync of `item` into the Fly app for `env_name`.
///
/// `digest` computes Fly's digest of a value locally (`None` = not computable).
/// Panics if `env_name` is not a defined environment.
pub fn build(
    fleet: &Fleet,
    env_name: &str,
    item: Vec<ItemField>,
    fly: &[FlySecret],
    rotate: &BTreeSet<(String, String)>,
    digest: &dyn Fn(&SecretValue) -> Option<String>,
) -> SyncPlan {
    let env = fleet
        .environments
        .get(env_name)
        .unwrap_or_else(|| panic!("undefined environment {env_name}"));
    let on_fly: BTreeMap<&str, Option<&str>> = fly
        .iter()
        .map(|s| (s.name.as_str(), s.digest.as_deref()))
        .collect();

    let mut by_name: BTreeMap<(&str, &str), &ItemField> = BTreeMap::new();
    for field in &item {
        by_name
            .entry((field.section.as_str(), field.label.as_str()))
            .or_insert(field);
    }

    let mut plan = SyncPlan {
        rows: Vec::new(),
        extras: Vec::new(),
        stage: Vec::new(),
        held_immutable: Vec::new(),
        prune: Vec::new(),
        config: BTreeMap::new(),
    };

    for (product, p) in &fleet.products {
        for (key, spec) in &p.keys {
            let fly_name = env.fly_name(product, key);
            let fly_entry = on_fly.get(fly_name.as_str()).copied();
            let field = by_name.get(&(product.as_str(), key.as_str()));

            // `Ok(None)` means the key is not desired here. `rules::applies` is evaluated
            // exactly once per key: inside `check`, or directly when there is nothing to check.
            let outcome: Result<Option<SecretValue>, KeyState> = match field {
                Some(f) if f.kind == spec.kind => {
                    rules::check(product, key, spec, env_name, env, &f.value)
                        .map_err(|e| KeyState::RuleFailed(e.rule))
                }
                other => {
                    if rules::applies(spec, env_name, env, product) {
                        Err(if other.is_some() {
                            KeyState::WrongKind
                        } else {
                            KeyState::Missing
                        })
                    } else {
                        Ok(None)
                    }
                }
            };

            let mut row = Row {
                product: product.clone(),
                key: key.clone(),
                kind: spec.kind,
                state: KeyState::Skipped,
                target: match (spec.kind, fly_entry) {
                    (Kind::Secret, None) => TargetState::Absent,
                    _ => TargetState::Unknown,
                },
                guidance: spec.guidance.clone(),
            };

            match outcome {
                Ok(None) => {
                    // Not desired in this environment: prune if it is a managed Fly name.
                    if spec.kind == Kind::Secret && fly_entry.is_some() {
                        plan.prune.push(fly_name);
                    }
                    if spec.environments.iter().any(|e| e == env_name) {
                        plan.rows.push(row); // mode-skipped
                    }
                    continue;
                }
                Err(state) => row.state = state,
                Ok(Some(value)) => {
                    row.state = KeyState::Ready;
                    match spec.kind {
                        Kind::Config => {
                            plan.config
                                .entry(product.clone())
                                .or_default()
                                .insert(key.clone(), value.expose().to_string());
                        }
                        Kind::Secret => {
                            if let Some(fly_digest) = fly_entry {
                                row.target = match (digest(&value), fly_digest) {
                                    (Some(local), Some(remote)) if local == remote => {
                                        TargetState::Present
                                    }
                                    (Some(_), Some(_)) => TargetState::WouldChange,
                                    _ => TargetState::Unknown,
                                };
                            }
                            let rotated = rotate.contains(&(product.clone(), key.clone()));
                            if spec.immutable && fly_entry.is_some() && !rotated {
                                plan.held_immutable.push((product.clone(), key.clone()));
                            } else if row.target != TargetState::Present || rotated {
                                plan.stage.push((fly_name, value));
                            }
                        }
                    }
                }
            }
            plan.rows.push(row);
        }
    }

    for field in &item {
        let declared = fleet
            .products
            .get(&field.section)
            .is_some_and(|p| p.keys.contains_key(&field.label));
        let pair = (field.section.clone(), field.label.clone());
        if !declared && !plan.extras.contains(&pair) {
            plan.extras.push(pair);
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use base64::Engine as _;

    fn f() -> Fleet {
        config::load("tests/fixtures/secrets.toml").unwrap()
    }
    fn secret(section: &str, label: &str, v: &str) -> ItemField {
        ItemField {
            section: section.into(),
            label: label.into(),
            kind: Kind::Secret,
            value: SecretValue::new(v.into()),
        }
    }
    fn config_field(section: &str, label: &str, v: &str) -> ItemField {
        ItemField {
            kind: Kind::Config,
            ..secret(section, label, v)
        }
    }
    fn b64_32() -> String {
        base64::engine::general_purpose::STANDARD.encode([7u8; 32])
    }
    fn none(_: &SecretValue) -> Option<String> {
        None
    }
    fn fly_secret(name: &str, digest: Option<&str>) -> FlySecret {
        FlySecret {
            name: name.into(),
            digest: digest.map(String::from),
        }
    }
    fn no_rotate() -> BTreeSet<(String, String)> {
        BTreeSet::new()
    }
    fn plan(item: Vec<ItemField>, fly: &[FlySecret]) -> SyncPlan {
        build(&f(), "prod", item, fly, &no_rotate(), &none)
    }
    fn row<'a>(p: &'a SyncPlan, key: &str) -> &'a Row {
        p.rows.iter().find(|r| r.key == key).unwrap()
    }
    fn enc_item() -> Vec<ItemField> {
        vec![secret("allumata", "INTEGRATION_ENC_KEY", &b64_32())]
    }
    const ENC: &str = "FLEET__ALLUMATA__INTEGRATION_ENC_KEY";

    #[test]
    fn missing_section_reports_every_key_missing() {
        let p = plan(vec![], &[]);
        assert!(
            p.rows
                .iter()
                .filter(|r| r.product == "allumata")
                .all(|r| matches!(r.state, KeyState::Missing | KeyState::Skipped))
        );
        assert!(p.blocking() > 0);
        assert!(p.stage.is_empty());
        assert_eq!(row(&p, "OPENAI_API_KEY").state, KeyState::Missing);
        assert_eq!(row(&p, "STRIPE_SECRET_KEY").state, KeyState::Skipped);
    }

    #[test]
    fn undeclared_field_is_extra_never_staged() {
        let item = vec![
            secret("allumata", "OPENAI_API_KEYS", "sk-x"),
            secret("allumata", "OPENAI_API_KEY", "sk-proj-1"),
            secret("allumata", "INTEGRATION_ENC_KEY", &b64_32()),
        ];
        let p = plan(item, &[]);
        assert_eq!(
            p.extras,
            vec![("allumata".to_string(), "OPENAI_API_KEYS".to_string())]
        );
        assert_eq!(p.stage.len(), 2, "other keys are Ready and staged");
        assert!(p.stage.iter().all(|(n, _)| !n.ends_with("OPENAI_API_KEYS")));
        assert!(p.prune.is_empty());
    }

    #[test]
    fn field_declared_only_for_other_env_is_not_extra() {
        // fixture: OPENAI_API_KEY is prod only; planning staging must not call it extra
        let item = vec![secret("allumata", "OPENAI_API_KEY", "sk-proj-1")];
        let p = build(&f(), "staging", item, &[], &no_rotate(), &none);
        assert!(p.extras.is_empty());
        assert!(p.stage.is_empty());
        assert!(p.rows.iter().all(|r| r.key != "OPENAI_API_KEY"));
    }

    #[test]
    fn secret_stored_as_text_is_wrong_kind() {
        let p = plan(
            vec![config_field("allumata", "OPENAI_API_KEY", "sk-proj-1")],
            &[],
        );
        assert_eq!(row(&p, "OPENAI_API_KEY").state, KeyState::WrongKind);
        assert!(p.stage.is_empty());
    }

    #[test]
    fn config_stored_as_concealed_is_wrong_kind_and_not_leaked() {
        let p = plan(
            vec![secret("allumata", "SIGNUP_POLICY", "invite_only")],
            &[],
        );
        assert_eq!(row(&p, "SIGNUP_POLICY").state, KeyState::WrongKind);
        assert!(p.config.is_empty());
    }

    #[test]
    fn rule_failure_names_rule_and_blocks() {
        let p = plan(vec![secret("allumata", "OPENAI_API_KEY", "sk-or-abc")], &[]);
        assert_eq!(
            row(&p, "OPENAI_API_KEY").state,
            KeyState::RuleFailed("not_prefix")
        );
        assert!(p.blocking() > 0);
        assert!(p.stage.is_empty());
    }

    #[test]
    fn skipped_key_with_wrong_kind_or_absent_is_not_blocking() {
        let p = plan(
            vec![config_field("allumata", "STRIPE_SECRET_KEY", "x")],
            &[],
        );
        assert_eq!(row(&p, "STRIPE_SECRET_KEY").state, KeyState::Skipped);
        assert!(p.stage.is_empty());
    }

    #[test]
    fn immutable_present_on_fly_is_held_unless_rotated() {
        let fly = [fly_secret(ENC, None)];
        let p = build(&f(), "prod", enc_item(), &fly, &no_rotate(), &none);
        assert!(p.stage.is_empty());
        assert_eq!(
            p.held_immutable,
            vec![("allumata".to_string(), "INTEGRATION_ENC_KEY".to_string())]
        );
        let rot = BTreeSet::from([("allumata".to_string(), "INTEGRATION_ENC_KEY".to_string())]);
        let r = build(&f(), "prod", enc_item(), &fly, &rot, &none);
        assert_eq!(r.stage.len(), 1);
        assert!(r.held_immutable.is_empty());
    }

    #[test]
    fn immutable_absent_on_fly_is_staged() {
        let p = plan(enc_item(), &[]);
        assert_eq!(p.stage.len(), 1);
        assert_eq!(p.stage[0].0, ENC);
        assert!(p.held_immutable.is_empty());
        assert_eq!(row(&p, "INTEGRATION_ENC_KEY").target, TargetState::Absent);
    }

    #[test]
    fn immutable_held_for_present_wouldchange_and_unknown() {
        let same = |_: &SecretValue| Some("d1".to_string());
        for (fly_digest, d) in [
            (Some("d1"), &same as &dyn Fn(&SecretValue) -> Option<String>),
            (Some("other"), &same),
            (None, &same),
        ] {
            let fly = [fly_secret(ENC, fly_digest)];
            let p = build(&f(), "prod", enc_item(), &fly, &no_rotate(), d);
            assert!(p.stage.is_empty(), "{fly_digest:?}");
            assert_eq!(p.held_immutable.len(), 1, "{fly_digest:?}");
        }
    }

    #[test]
    fn config_goes_to_config_map_not_stage() {
        let p = plan(
            vec![config_field("allumata", "SIGNUP_POLICY", "invite_only")],
            &[],
        );
        assert_eq!(p.config["allumata"]["SIGNUP_POLICY"], "invite_only");
        assert!(p.stage.is_empty());
    }

    #[test]
    fn digest_branches() {
        let item = || vec![secret("allumata", "OPENAI_API_KEY", "sk-proj-1")];
        let name = "FLEET__ALLUMATA__OPENAI_API_KEY";
        let some = |_: &SecretValue| Some("d1".to_string());
        let run = |fly_digest: Option<&str>, d: &dyn Fn(&SecretValue) -> Option<String>| {
            build(
                &f(),
                "prod",
                item(),
                &[fly_secret(name, fly_digest)],
                &no_rotate(),
                d,
            )
        };
        // equal digests: Present, not staged
        let p = run(Some("d1"), &some);
        assert_eq!(row(&p, "OPENAI_API_KEY").target, TargetState::Present);
        assert!(p.stage.is_empty());
        // differing digests: WouldChange, staged
        let p = run(Some("d2"), &some);
        assert_eq!(row(&p, "OPENAI_API_KEY").target, TargetState::WouldChange);
        assert_eq!(p.stage.len(), 1);
        // Fly has no digest: Unknown, staged
        let p = run(None, &some);
        assert_eq!(row(&p, "OPENAI_API_KEY").target, TargetState::Unknown);
        assert_eq!(p.stage.len(), 1);
        // local digest not computable: Unknown, staged
        let p = run(Some("d1"), &none);
        assert_eq!(row(&p, "OPENAI_API_KEY").target, TargetState::Unknown);
        assert_eq!(p.stage.len(), 1);
        // absent on Fly: Absent, staged
        let p = build(&f(), "prod", item(), &[], &no_rotate(), &some);
        assert_eq!(row(&p, "OPENAI_API_KEY").target, TargetState::Absent);
        assert_eq!(p.stage.len(), 1);
    }

    #[test]
    fn rotate_stages_immutable_even_when_present_with_equal_digest() {
        let some = |_: &SecretValue| Some("d1".to_string());
        let fly = [fly_secret(ENC, Some("d1"))];
        let rot = BTreeSet::from([("allumata".to_string(), "INTEGRATION_ENC_KEY".to_string())]);
        let p = build(&f(), "prod", enc_item(), &fly, &rot, &some);
        assert_eq!(p.stage.len(), 1);
    }

    #[test]
    fn prune_only_managed_template_names() {
        let fly = [
            fly_secret("FLEET__ALLUMATA__OLD_KEY", None),
            fly_secret("FLEET__ALLUMATA__DATABASE_URL", None),
            fly_secret("UNRELATED", None),
        ];
        let p = plan(vec![], &fly);
        assert!(p.prune.is_empty());
    }

    const TWO_KEYS: &str = r#"
[profile]
kind = "fleet"
[environments.staging]
vault_id = "v1"
item_id = "i1"
fly.app = "a-stg"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
[environments.prod]
vault_id = "v2"
item_id = "i2"
fly.app = "a-prd"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
[products.p.keys.STAGING_ONLY]
kind = "secret"
environments = ["staging"]
[products.p.keys.BOTH]
kind = "secret"
environments = ["staging", "prod"]
[products.p.keys.TRACE]
kind = "secret"
environments = ["staging", "prod"]
rules = { transform = "signoz_ingestion_header" }
"#;

    #[test]
    fn key_declared_for_other_env_only_is_pruned_when_present() {
        let fleet = config::parse(TWO_KEYS).unwrap();
        let fly = [fly_secret("FLEET__P__STAGING_ONLY", None)];
        let p = build(&fleet, "prod", vec![], &fly, &no_rotate(), &none);
        assert_eq!(p.prune, vec!["FLEET__P__STAGING_ONLY".to_string()]);
        assert!(p.rows.iter().all(|r| r.key != "STAGING_ONLY"));
        // in staging the same name is desired, not pruned
        let p = build(&fleet, "staging", vec![], &fly, &no_rotate(), &none);
        assert!(p.prune.is_empty());
    }

    #[test]
    fn declared_applicable_present_key_is_never_pruned() {
        let fleet = config::parse(TWO_KEYS).unwrap();
        let fly = [fly_secret("FLEET__P__BOTH", None)];
        for item in [vec![], vec![secret("p", "BOTH", "v")]] {
            let p = build(&fleet, "prod", item, &fly, &no_rotate(), &none);
            assert!(p.prune.is_empty());
        }
    }

    #[test]
    fn mode_skipped_key_present_on_fly_is_pruned() {
        let fly = [fly_secret("FLEET__ALLUMATA__STRIPE_SECRET_KEY", None)];
        let p = plan(vec![], &fly);
        assert_eq!(
            p.prune,
            vec!["FLEET__ALLUMATA__STRIPE_SECRET_KEY".to_string()]
        );
        // staging has payments=test: the key applies and is not pruned
        let p = build(&f(), "staging", vec![], &fly, &no_rotate(), &none);
        assert!(p.prune.is_empty());
    }

    #[test]
    fn stages_the_transformed_value() {
        let fleet = config::parse(TWO_KEYS).unwrap();
        let item = vec![secret("p", "TRACE", "abc123")];
        let p = build(&fleet, "prod", item, &[], &no_rotate(), &none);
        assert_eq!(p.stage.len(), 1);
        assert_eq!(p.stage[0].0, "FLEET__P__TRACE");
        assert_eq!(p.stage[0].1.expose(), "signoz-ingestion-key=abc123");
    }

    #[test]
    fn digest_is_computed_on_the_checked_value() {
        let fleet = config::parse(TWO_KEYS).unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        let d = |v: &SecretValue| {
            seen.borrow_mut().push(v.expose().to_string());
            None
        };
        let item = vec![secret("p", "TRACE", "abc123")];
        build(
            &fleet,
            "prod",
            item,
            &[fly_secret("FLEET__P__TRACE", Some("x"))],
            &no_rotate(),
            &d,
        );
        assert_eq!(*seen.borrow(), vec!["signoz-ingestion-key=abc123"]);
    }

    #[test]
    fn debug_never_prints_values() {
        let item = vec![
            secret("allumata", "OPENAI_API_KEY", "sk-LEAKME-1"),
            config_field("allumata", "SIGNUP_POLICY", "invite_only"),
        ];
        let dbg_field = format!("{:?}", item[0]);
        let p = plan(item, &[]);
        for s in [dbg_field, format!("{p:?}"), format!("{p:#?}")] {
            assert!(!s.contains("LEAKME"), "{s}");
            assert!(!s.contains("\"invite_only\""), "{s}");
        }
        assert!(format!("{p:?}").contains("FLEET__ALLUMATA__OPENAI_API_KEY"));
    }
}
