//! Sync planner (FR-5, FR-8, FR-14, FR-16, §10). Pure: no `op`, no `flyctl`, no I/O.
//!
//! `build` joins the declared fleet, the 1Password item fields and the names on Fly into a
//! `SyncPlan`. Rows, extras, prune and held lists hold names only. Values appear only in
//! `stage` (secrets, wrapped in `SecretValue`) and `config` (non-secret config values).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::domain::model::{Fleet, KeySpec, Kind};
use crate::domain::rules::{self, Reason};
use crate::domain::secret::SecretValue;

/// One field of the 1Password item, as produced by the source adapter.
/// `Debug` never prints the value.
pub struct ItemField {
    pub section: String,
    pub label: String,
    pub kind: Kind,
    pub value: SecretValue,
    /// The 1Password field is concealed (M4): a config key read from a concealed field is
    /// delivered, but its value is never printed (`config export`) and `status` warns.
    pub concealed: bool,
}

impl fmt::Debug for ItemField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemField")
            .field("section", &self.section)
            .field("label", &self.label)
            .field("kind", &self.kind)
            .field("concealed", &self.concealed)
            .field("value", &"<REDACTED>")
            .finish()
    }
}

/// A value listed on the target's store (FR-12): its name, the store's version of the
/// value when it reports one (Fly: the digest), and whether a change is written but not yet
/// live (Fly: status `Staged` or `Partial`). The planner ignores `pending`; `fly sync` uses
/// it only as an extra deploy trigger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreEntry {
    pub name: String,
    pub version: Option<String>,
    pub pending: bool,
    /// opv's provenance stamp on the entry (FR-42), when the store records one.
    pub stamp: Option<crate::domain::provenance::Stamp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyState {
    Missing,
    WrongKind,
    /// The failing rule's stable name and why it failed (FR-15, FR-22). Never the value.
    RuleFailed(&'static str, Reason),
    Ready,
    Skipped,
    /// A shared key (FR-45) whose source has a finding: the finding is reported once, on
    /// the source's row, which also blocks the sync. Not counted as a finding of its own.
    SourceBlocked,
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
    /// Only meaningful for secrets. Secrets absent from the store are `Absent`; `Present`
    /// and `WouldChange` need both digests, or the store's current value
    /// ([`PlanOptions::current`]); everything else present is `Unknown`. Config keys are
    /// always `Unknown` (they are not store secrets).
    pub target: TargetState,
    pub guidance: String,
    /// A shared key's source `(product, key)` (FR-45): `shared from <product>/<KEY>`.
    pub source: Option<(String, String)>,
    /// The keys declared here that share this key's value (FR-45), as `(product, key)`.
    pub shared_by: Vec<(String, String)>,
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
    /// mode). Names the template does not produce for a declared key are never pruned, a
    /// name in `stage` is never pruned, and an immutable key is never pruned unless listed
    /// in [`PlanOptions::prune_immutable`] (FR-8, FR-16).
    pub prune: Vec<String>,
    /// (product, key, fly name): immutable keys that would otherwise be pruned. Held.
    pub held_from_prune: Vec<(String, String, String)>,
    /// product -> key -> value, config keys only.
    pub config: BTreeMap<String, BTreeMap<String, String>>,
    /// (product, key): config keys whose 1Password field is concealed (M4, owner ruling).
    /// Accepted and delivered as plain environment values, but their values are never
    /// printed, and `status` warns once per key.
    pub concealed_config: Vec<(String, String)>,
    /// What this run tidied in 1Password (FR-43), names only; set by the application layer.
    pub tidy: Vec<crate::domain::convention::Change>,
    /// The error code of a tidy that did not complete (`tidy_conflict`, ...), set by the
    /// application layer; the read went on as it is (FR-43).
    pub tidy_error: Option<&'static str>,
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
            .field("held_from_prune", &self.held_from_prune)
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
                    KeyState::Missing | KeyState::WrongKind | KeyState::RuleFailed(..)
                )
            })
            .count()
    }
}

/// The target's value check: for (target name, value), the first rule the target would
/// refuse and that rule's fixed reason (FR-22), or `None`.
pub type TargetCheck<'a> = dyn Fn(&str, &SecretValue) -> Option<(&'static str, &'static str)> + 'a;

/// How the store's current value of a name compares with the desired one (FR-31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentState {
    /// Byte-for-byte equal.
    Same,
    Differs,
    /// Not in the store.
    Absent,
}

/// The store's current value check: for (target name, desired value), how the stored value
/// compares, or `None` when the store cannot say.
pub type CurrentCheck<'a> = dyn Fn(&str, &SecretValue) -> Option<CurrentState> + 'a;

/// Target-specific inputs to [`build_with`]. The planner stays target-agnostic (FR-12):
/// the application layer supplies the digest function and the value check.
pub struct PlanOptions<'a> {
    /// Immutable keys to stage even though present on the target (FR-16).
    pub rotate: &'a BTreeSet<(String, String)>,
    /// Immutable keys that may be pruned (otherwise immutable keys are never pruned).
    pub prune_immutable: &'a BTreeSet<(String, String)>,
    /// Computes the target's digest of a value locally (`None` = not computable).
    pub digest: &'a dyn Fn(&SecretValue) -> Option<String>,
    /// The first rule the target would refuse for (target name, value) and its fixed
    /// reason, e.g. a value the Fly import cannot carry. A refusal makes the row
    /// `RuleFailed(rule, reason)`; not staged.
    pub target_check: &'a TargetCheck<'a>,
    /// For a store that can read its values back (pinned flow, FR-31): each ready secret
    /// the store lists is compared exactly. `None` keeps the digest compare alone (Fly).
    pub current: Option<&'a CurrentCheck<'a>>,
}

/// Plan a sync of `item` into the Fly app for `env_name`, with no prune overrides and no
/// target value check. See [`build_with`].
///
/// `digest` computes Fly's digest of a value locally (`None` = not computable).
/// Panics if `env_name` is not a defined environment.
pub fn build(
    fleet: &Fleet,
    env_name: &str,
    item: Vec<ItemField>,
    on_store: &[StoreEntry],
    rotate: &BTreeSet<(String, String)>,
    digest: &dyn Fn(&SecretValue) -> Option<String>,
) -> SyncPlan {
    let none = BTreeSet::new();
    build_with(
        fleet,
        env_name,
        item,
        on_store,
        &PlanOptions {
            rotate,
            prune_immutable: &none,
            digest,
            target_check: &|_, _| None,
            current: None,
        },
    )
}

/// Plan a sync of `item` into the target for `env_name`.
///
/// Without a Fly target in the environment nothing is staged or pruned; rows and config
/// are still produced (for `config export`). Panics if `env_name` is not defined.
pub fn build_with(
    fleet: &Fleet,
    env_name: &str,
    item: Vec<ItemField>,
    on_store: &[StoreEntry],
    opts: &PlanOptions<'_>,
) -> SyncPlan {
    let env = fleet
        .environments
        .get(env_name)
        .unwrap_or_else(|| panic!("undefined environment {env_name}"));
    let on_target: BTreeMap<&str, Option<&str>> = on_store
        .iter()
        .map(|s| (s.name.as_str(), s.version.as_deref()))
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
        held_from_prune: Vec::new(),
        config: BTreeMap::new(),
        concealed_config: Vec::new(),
        tidy: Vec::new(),
        tidy_error: None,
    };

    // `Ok(None)` means the key is not desired here. `refuse_in` is checked first and
    // whatever the field's kind: a non-empty field in a refused environment blocks even
    // though the key is not otherwise desired there (FR-15). `rules::applies` is evaluated
    // exactly once per key otherwise.
    let evaluate = |product: &str,
                    key: &str,
                    spec: &KeySpec,
                    field: Option<(Kind, &SecretValue)>|
     -> Result<Option<SecretValue>, KeyState> {
        let refused =
            rules::refused_in(spec, env_name) && field.is_some_and(|(_, v)| !v.expose().is_empty());
        match field {
            _ if refused => Err(KeyState::RuleFailed(
                "refuse_in",
                Reason::Fixed(rules::REASON_REFUSED),
            )),
            Some((kind, value)) if kind == spec.kind => {
                rules::check(product, key, spec, env_name, env, value)
                    .map_err(|e| KeyState::RuleFailed(e.rule, e.reason))
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
        }
    };

    for (product, p) in &fleet.products {
        for (key, spec) in &p.keys {
            let target_name = env.target_name(product, key);
            let target_entry = target_name
                .as_deref()
                .and_then(|n| on_target.get(n).copied());
            let field = by_name.get(&(product.as_str(), key.as_str()));
            let declared_here = spec.environments.iter().any(|e| e == env_name);

            // A shared key (FR-45) reads its source's field: the source's rules first (its
            // transformed value is the one shared), then the key's own rules on that value.
            // When the source has a finding, the finding is reported once, on the source
            // row; this row only says it waits on it.
            let source = spec.source();
            let concealed = match source {
                None => field.is_some_and(|f| f.concealed),
                Some((sp, sk)) => by_name.get(&(sp, sk)).is_some_and(|f| f.concealed),
            };
            let outcome = match source {
                None => evaluate(product, key, spec, field.map(|f| (f.kind, &f.value))),
                Some((sp, sk)) => {
                    let src_spec = &fleet.products[sp].keys[sk];
                    let src_field = by_name.get(&(sp, sk)).map(|f| (f.kind, &f.value));
                    match evaluate(sp, sk, src_spec, src_field) {
                        Ok(Some(v)) => evaluate(product, key, spec, Some((spec.kind, &v))),
                        Ok(None) => evaluate(product, key, spec, src_field),
                        Err(_) if rules::applies(spec, env_name, env, product) => {
                            Err(KeyState::SourceBlocked)
                        }
                        Err(_) => Ok(None),
                    }
                }
            };
            // A ready secret the target cannot carry is a failing rule, in plan and status
            // exactly as in sync.
            let outcome = match (outcome, spec.kind, target_name.as_deref()) {
                (Ok(Some(v)), Kind::Secret, Some(name)) => match (opts.target_check)(name, &v) {
                    Some((rule, why)) => Err(KeyState::RuleFailed(rule, Reason::Fixed(why))),
                    None => Ok(Some(v)),
                },
                (o, _, _) => o,
            };

            let mut row = Row {
                product: product.clone(),
                key: key.clone(),
                kind: spec.kind,
                state: KeyState::Skipped,
                target: match (spec.kind, target_entry) {
                    (Kind::Secret, None) => TargetState::Absent,
                    _ => TargetState::Unknown,
                },
                guidance: spec.guidance.clone(),
                source: source.map(|(p, k)| (p.to_string(), k.to_string())),
                shared_by: fleet.shared_by(env_name, product, key),
            };

            match outcome {
                Ok(None) => {
                    // Not desired in this environment: prune if it is a managed Fly name,
                    // unless it is immutable and not explicitly released.
                    if let (Kind::Secret, Some(_), Some(name)) =
                        (spec.kind, target_entry, target_name)
                    {
                        let pair = (product.clone(), key.clone());
                        if spec.immutable && !opts.prune_immutable.contains(&pair) {
                            plan.held_from_prune.push((pair.0, pair.1, name));
                        } else {
                            plan.prune.push(name);
                        }
                    }
                    if declared_here {
                        plan.rows.push(row); // mode-skipped
                    }
                    continue;
                }
                Err(state) => row.state = state,
                Ok(Some(value)) => {
                    row.state = KeyState::Ready;
                    match spec.kind {
                        Kind::Config => {
                            if concealed {
                                plan.concealed_config.push((product.clone(), key.clone()));
                            }
                            plan.config
                                .entry(product.clone())
                                .or_default()
                                .insert(key.clone(), value.expose().to_string());
                        }
                        Kind::Secret => {
                            if let Some(target_digest) = target_entry {
                                row.target = match ((opts.digest)(&value), target_digest) {
                                    (Some(local), Some(remote)) if local == remote => {
                                        TargetState::Present
                                    }
                                    (Some(_), Some(_)) => TargetState::WouldChange,
                                    _ => TargetState::Unknown,
                                };
                                if let (Some(current), Some(name)) =
                                    (opts.current, target_name.as_deref())
                                    && let Some(state) = current(name, &value)
                                {
                                    row.target = match state {
                                        CurrentState::Same => TargetState::Present,
                                        CurrentState::Differs => TargetState::WouldChange,
                                        CurrentState::Absent => TargetState::Absent,
                                    };
                                }
                            }
                            // Rotating a source rotates every key sharing it (FR-45).
                            let rotated = opts.rotate.contains(&(product.clone(), key.clone()))
                                || source.is_some_and(|(p, k)| {
                                    opts.rotate.contains(&(p.to_string(), k.to_string()))
                                });
                            let on_target = row.target != TargetState::Absent;
                            if spec.immutable && on_target && !rotated {
                                plan.held_immutable.push((product.clone(), key.clone()));
                            } else if let Some(name) = target_name
                                && (row.target != TargetState::Present || rotated)
                            {
                                plan.stage.push((name, value));
                            }
                        }
                    }
                }
            }
            plan.rows.push(row);
        }
    }

    // Defence in depth (config validation already rejects colliding names): a name staged
    // by this run is never pruned by it.
    let staged: BTreeSet<&str> = plan.stage.iter().map(|(n, _)| n.as_str()).collect();
    plan.prune.retain(|n| !staged.contains(n.as_str()));
    plan.held_from_prune
        .retain(|(_, _, n)| !staged.contains(n.as_str()));

    for field in &item {
        // A shared key (FR-45) has no field of its own: a leftover copy is an extra.
        let declared = fleet
            .products
            .get(&field.section)
            .and_then(|p| p.keys.get(&field.label))
            .is_some_and(|spec| spec.from.is_none());
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
            concealed: true,
        }
    }
    fn config_field(section: &str, label: &str, v: &str) -> ItemField {
        ItemField {
            kind: Kind::Config,
            concealed: false,
            ..secret(section, label, v)
        }
    }
    fn b64_32() -> String {
        base64::engine::general_purpose::STANDARD.encode([7u8; 32])
    }
    fn none(_: &SecretValue) -> Option<String> {
        None
    }
    fn fly_secret(name: &str, version: Option<&str>) -> StoreEntry {
        StoreEntry {
            name: name.into(),
            version: version.map(String::from),
            pending: false,
            stamp: None,
        }
    }
    fn no_rotate() -> BTreeSet<(String, String)> {
        BTreeSet::new()
    }
    fn plan(item: Vec<ItemField>, fly: &[StoreEntry]) -> SyncPlan {
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
            KeyState::RuleFailed("not_prefix", Reason::Fixed(rules::REASON_REFUSED_PREFIX))
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
rules = { ensure_prefix = "signoz-ingestion-key=", pattern = "[A-Za-z0-9._~+/-]+={0,2}" }
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

    fn opts_with<'a>(
        rotate: &'a BTreeSet<(String, String)>,
        prune_immutable: &'a BTreeSet<(String, String)>,
        target_check: &'a TargetCheck<'a>,
    ) -> PlanOptions<'a> {
        PlanOptions {
            rotate,
            prune_immutable,
            digest: &none,
            target_check,
            current: None,
        }
    }

    /// C1 defence in depth: even a fleet that bypassed config validation (two keys
    /// rendering one Fly name, one desired here and one not) never has a name in both
    /// `stage` and `prune`.
    #[test]
    fn a_staged_name_is_never_pruned_even_if_validation_was_bypassed() {
        let mut fleet = config::parse(TWO_KEYS).unwrap();
        // q/BOTH is declared for staging only; p/BOTH is desired in prod.
        let mut q = fleet.products["p"].clone();
        let spec = q.keys.remove("STAGING_ONLY").unwrap();
        q.keys.clear();
        q.keys.insert("BOTH".into(), spec);
        fleet.products.insert("q".into(), q);
        for env in fleet.environments.values_mut() {
            // A template without {PRODUCT}: p/BOTH and q/BOTH both render FLEET__BOTH.
            let app = env
                .target()
                .and_then(|t| t.as_any().downcast_ref::<crate::adapters::fly::FlyTarget>())
                .expect("fixture is Fly")
                .app
                .clone();
            env.target = Some(Box::new(crate::adapters::fly::FlyTarget {
                app,
                secret_name_template: "FLEET__{KEY}".into(),
                profile: crate::domain::Profile::Fleet,
            }));
        }
        let fly = [fly_secret("FLEET__BOTH", None)];
        let item = vec![secret("p", "BOTH", "v1")];
        let p = build(&fleet, "prod", item, &fly, &no_rotate(), &none);
        let staged: Vec<&str> = p.stage.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(staged, vec!["FLEET__BOTH"]);
        assert!(
            p.prune.iter().all(|n| !staged.contains(&n.as_str())),
            "{:?}",
            p.prune
        );
    }

    /// C2: an immutable key not desired here but present on Fly is held, never pruned,
    /// unless listed in `prune_immutable`.
    #[test]
    fn immutable_key_is_held_from_prune_unless_released() {
        let fleet = config::parse(&TWO_KEYS.replace(
            "environments = [\"staging\"]",
            "environments = [\"staging\"]\nimmutable = true",
        ))
        .unwrap();
        assert!(fleet.products["p"].keys["STAGING_ONLY"].immutable);
        let fly = [fly_secret("FLEET__P__STAGING_ONLY", None)];
        let p = build(&fleet, "prod", vec![], &fly, &no_rotate(), &none);
        assert!(p.prune.is_empty(), "{:?}", p.prune);
        assert_eq!(
            p.held_from_prune,
            vec![(
                "p".to_string(),
                "STAGING_ONLY".to_string(),
                "FLEET__P__STAGING_ONLY".to_string()
            )]
        );
        let release = BTreeSet::from([("p".to_string(), "STAGING_ONLY".to_string())]);
        let p = build_with(
            &fleet,
            "prod",
            vec![],
            &fly,
            &opts_with(&no_rotate(), &release, &|_, _| None),
        );
        assert_eq!(p.prune, vec!["FLEET__P__STAGING_ONLY".to_string()]);
        assert!(p.held_from_prune.is_empty());
    }

    /// I1: refuse_in produces a blocking row where the key is otherwise not desired, for
    /// a non-empty field of either kind; an empty field produces nothing.
    #[test]
    fn refuse_in_row_in_refused_env() {
        let fleet = config::parse(&format!(
            "{TWO_KEYS}\n[products.p.keys.SMTP_PASS]\nkind = \"secret\"\n\
             environments = [\"prod\"]\nrules = {{ refuse_in = [\"staging\"] }}\n"
        ))
        .unwrap();
        for f in [
            secret("p", "SMTP_PASS", "x"),
            config_field("p", "SMTP_PASS", "x"),
        ] {
            let p = build(&fleet, "staging", vec![f], &[], &no_rotate(), &none);
            assert_eq!(
                row(&p, "SMTP_PASS").state,
                KeyState::RuleFailed("refuse_in", Reason::Fixed(rules::REASON_REFUSED))
            );
            assert!(p.blocking() > 0);
            assert!(p.stage.iter().all(|(n, _)| n != "FLEET__P__SMTP_PASS"));
        }
        let p = build(
            &fleet,
            "staging",
            vec![secret("p", "SMTP_PASS", "")],
            &[],
            &no_rotate(),
            &none,
        );
        assert!(p.rows.iter().all(|r| r.key != "SMTP_PASS"));
        // In prod the key is simply desired.
        let p = build(
            &fleet,
            "prod",
            vec![secret("p", "SMTP_PASS", "x")],
            &[],
            &no_rotate(),
            &none,
        );
        assert_eq!(row(&p, "SMTP_PASS").state, KeyState::Ready);
    }

    /// I2: the target check turns a ready secret into a failing rule; config keys and
    /// non-ready rows are not checked.
    #[test]
    fn target_check_marks_ready_secret_as_failing_rule() {
        let seen = std::cell::RefCell::new(Vec::new());
        let check = |name: &str, _: &SecretValue| {
            seen.borrow_mut().push(name.to_string());
            (name == "FLEET__ALLUMATA__OPENAI_API_KEY").then_some(("import-something", "why"))
        };
        let item = vec![
            secret("allumata", "OPENAI_API_KEY", "sk-proj-1"),
            secret("allumata", "INTEGRATION_ENC_KEY", &b64_32()),
            config_field("allumata", "SIGNUP_POLICY", "invite_only"),
        ];
        let p = build_with(
            &f(),
            "prod",
            item,
            &[],
            &opts_with(&no_rotate(), &no_rotate(), &check),
        );
        assert_eq!(
            row(&p, "OPENAI_API_KEY").state,
            KeyState::RuleFailed("import-something", Reason::Fixed("why"))
        );
        assert_eq!(row(&p, "INTEGRATION_ENC_KEY").state, KeyState::Ready);
        assert_eq!(p.stage.len(), 1);
        assert_eq!(
            *seen.borrow(),
            vec![
                "FLEET__ALLUMATA__INTEGRATION_ENC_KEY".to_string(),
                "FLEET__ALLUMATA__OPENAI_API_KEY".to_string()
            ]
        );
    }

    /// I5: without a Fly target nothing is staged or pruned; rows and config still are.
    #[test]
    fn env_without_fly_plans_rows_and_config_only() {
        let mut fleet = f();
        fleet.environments.get_mut("prod").unwrap().target = None;
        let item = vec![
            secret("allumata", "OPENAI_API_KEY", "sk-proj-1"),
            config_field("allumata", "SIGNUP_POLICY", "invite_only"),
        ];
        let p = build(&fleet, "prod", item, &[], &no_rotate(), &none);
        assert!(p.stage.is_empty() && p.prune.is_empty());
        assert_eq!(row(&p, "OPENAI_API_KEY").state, KeyState::Ready);
        assert_eq!(p.config["allumata"]["SIGNUP_POLICY"], "invite_only");
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
