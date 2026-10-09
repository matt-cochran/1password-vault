//! Plan ids and provenance stamps (FR-41, FR-42). Pure, stateless and value-free.
//!
//! - [`plan_id`] fingerprints what `plan` reviewed: the environment, the product scope, the
//!   1Password item's `version` integer, every row's names and states, the planned names
//!   (stage, prune, held) and the store listing (names, pending flags and, for a pinned
//!   store, its version ids). It is SHA-256 over those names and integers only: no value,
//!   no value length and no value digest goes in (Fly digests are left out for that reason),
//!   so the id can neither reveal nor confirm a value (SR-1). It is recomputed by `sync
//!   --expect-plan`, never stored (§7, §9).
//! - [`Stamp`] is the run metadata a pinned target records on what opv writes (Key Vault
//!   tags, Kubernetes annotations): opv's version, the UTC time, the environment and the
//!   plan id. Nothing else: no value and no identity (FR-42).

use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::domain::model::Kind;
use crate::domain::plan::{KeyState, StoreEntry, SyncPlan, TargetState};

/// Hex digits of a plan id.
pub const PLAN_ID_LEN: usize = 8;

/// The inputs of a plan id besides the plan itself.
pub struct PlanIdInput<'a> {
    pub env: &'a str,
    /// `--product`, when the plan was scoped to one product.
    pub product: Option<&'a str>,
    /// The 1Password item's `version` integer, when `op` reported one.
    pub item_version: Option<u64>,
    /// The store listing the plan was built against.
    pub listed: &'a [StoreEntry],
    /// True when [`StoreEntry::version`] is a store version id (a pinned store). False when
    /// it is a digest of the value (Fly): then it is left out (SR-1).
    pub version_ids: bool,
}

/// The short plan id (FR-41): [`PLAN_ID_LEN`] hex digits of SHA-256 over names, states,
/// version ids and the item version. Never over a value; see the module docs.
pub fn plan_id(input: &PlanIdInput<'_>, plan: &SyncPlan) -> String {
    let mut h = Sha256::new();
    let mut put = |s: &str| {
        h.update((s.len() as u64).to_be_bytes());
        h.update(s.as_bytes());
    };
    put("opv-plan-v1");
    put(input.env);
    put(input.product.unwrap_or(""));
    put(&input
        .item_version
        .map(|v| v.to_string())
        .unwrap_or_default());
    put("rows");
    for r in &plan.rows {
        put(&r.product);
        put(&r.key);
        put(match r.kind {
            Kind::Secret => "secret",
            Kind::Config => "config",
        });
        put(match &r.state {
            KeyState::Missing => "missing",
            KeyState::WrongKind => "wrong-kind",
            KeyState::RuleFailed(rule, _) => rule,
            KeyState::Ready => "ready",
            KeyState::Skipped => "skipped",
        });
        put(match r.target {
            TargetState::Absent => "absent",
            TargetState::Present => "present",
            TargetState::WouldChange => "would-change",
            TargetState::Unknown => "unknown",
        });
    }
    let mut sorted = |label: &str, names: Vec<String>| {
        let mut names = names;
        names.sort();
        put(label);
        for n in &names {
            put(n);
        }
    };
    sorted("stage", plan.stage.iter().map(|(n, _)| n.clone()).collect());
    sorted("prune", plan.prune.clone());
    sorted(
        "held",
        plan.held_immutable
            .iter()
            .map(|(p, k)| format!("{p}/{k}"))
            .collect(),
    );
    sorted(
        "held-from-prune",
        plan.held_from_prune
            .iter()
            .map(|(_, _, n)| n.clone())
            .collect(),
    );
    sorted(
        "extras",
        plan.extras
            .iter()
            .map(|(p, k)| format!("{p}/{k}"))
            .collect(),
    );
    sorted(
        "listed",
        input
            .listed
            .iter()
            .map(|e| {
                let version = if input.version_ids {
                    e.version.as_deref().unwrap_or("")
                } else {
                    ""
                };
                format!("{}\t{version}\t{}", e.name, e.pending)
            })
            .collect(),
    );
    hex::encode(h.finalize())[..PLAN_ID_LEN].to_string()
}

/// Tag and annotation keys of a [`Stamp`] (FR-42).
pub const STAMP_VERSION: &str = "opv-version";
pub const STAMP_WRITTEN: &str = "opv-written";
pub const STAMP_ENV: &str = "opv-env";
pub const STAMP_PLAN: &str = "opv-plan";

/// opv's run metadata, recorded on what a pinned target writes (FR-42). Names, a version,
/// a time and a plan id only: never a value or an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    pub opv_version: String,
    /// UTC, `YYYY-MM-DDTHH:MM:SSZ`; sorts by time as text.
    pub written: String,
    pub env: String,
    pub plan: String,
}

impl Stamp {
    /// This opv build's stamp for a write now.
    pub fn now(env: &str, plan: &str) -> Self {
        Self {
            opv_version: env!("CARGO_PKG_VERSION").to_string(),
            written: utc_now(),
            env: env.to_string(),
            plan: plan.to_string(),
        }
    }

    /// `(key, value)` pairs, in a fixed order.
    pub fn pairs(&self) -> [(&'static str, &str); 4] {
        [
            (STAMP_VERSION, self.opv_version.as_str()),
            (STAMP_WRITTEN, self.written.as_str()),
            (STAMP_ENV, self.env.as_str()),
            (STAMP_PLAN, self.plan.as_str()),
        ]
    }

    /// The stamp read back from tags or annotations, when all of it is there and each
    /// field has the shape opv writes (anything else is ignored, never printed).
    pub fn parse<'a>(get: impl Fn(&str) -> Option<&'a str>) -> Option<Stamp> {
        let word = |k: &str| {
            get(k).filter(|v| {
                !v.is_empty()
                    && v.len() <= 64
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.:+".contains(&b))
            })
        };
        Some(Stamp {
            opv_version: word(STAMP_VERSION)?.to_string(),
            written: word(STAMP_WRITTEN)?.to_string(),
            env: word(STAMP_ENV)?.to_string(),
            plan: word(STAMP_PLAN)?.to_string(),
        })
    }

    /// `last changed by opv <ver> at <time> (plan <id>)`.
    pub fn line(&self) -> String {
        format!(
            "last changed by opv {} at {} (plan {})",
            self.opv_version, self.written, self.plan
        )
    }
}

/// A fixed stamp for tests.
#[cfg(test)]
pub(crate) fn fixture() -> Stamp {
    Stamp {
        opv_version: "0.5.0".into(),
        written: "2026-10-08T14:02:11Z".into(),
        env: "prod".into(),
        plan: "7f3c9a1e".into(),
    }
}

/// The latest stamp of `entries` (by time).
pub fn latest(entries: &[StoreEntry]) -> Option<&Stamp> {
    entries
        .iter()
        .filter_map(|e| e.stamp.as_ref())
        .max_by(|a, b| a.written.cmp(&b.written))
}

/// The current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    utc(secs)
}

/// `secs` since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ` (proleptic Gregorian, UTC).
pub fn utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Row;
    use crate::domain::SecretValue;
    use std::collections::BTreeMap;

    const MARKER: &str = "opv-plan-id-marker-value-1";

    fn row(key: &str) -> Row {
        Row {
            product: "api".into(),
            key: key.into(),
            kind: Kind::Secret,
            state: KeyState::Ready,
            target: TargetState::Absent,
            guidance: String::new(),
        }
    }

    fn plan_with(stage: &[(&str, &str)]) -> SyncPlan {
        SyncPlan {
            rows: vec![row("DB_URL")],
            extras: vec![],
            stage: stage
                .iter()
                .map(|(n, v)| (n.to_string(), SecretValue::new(v.to_string())))
                .collect(),
            held_immutable: vec![],
            prune: vec![],
            held_from_prune: vec![],
            config: BTreeMap::new(),
        }
    }

    fn entry(name: &str, version: &str) -> StoreEntry {
        StoreEntry {
            name: name.into(),
            version: Some(version.into()),
            pending: false,
            stamp: None,
        }
    }

    fn id(item_version: u64, listed: &[StoreEntry], plan: &SyncPlan) -> String {
        plan_id(
            &PlanIdInput {
                env: "prod",
                product: None,
                item_version: Some(item_version),
                listed,
                version_ids: true,
            },
            plan,
        )
    }

    #[test]
    fn plan_id_is_stable_across_runs() {
        let listed = [entry("DB_URL", "v1")];
        let p = plan_with(&[("DB_URL", MARKER)]);
        assert_eq!(id(41, &listed, &p), id(41, &listed, &p));
    }

    #[test]
    fn plan_id_changes_with_the_item_version() {
        let p = plan_with(&[("DB_URL", MARKER)]);
        assert_ne!(id(41, &[], &p), id(42, &[], &p));
    }

    #[test]
    fn plan_id_changes_with_a_target_version() {
        let p = plan_with(&[("DB_URL", MARKER)]);
        assert_ne!(
            id(41, &[entry("DB_URL", "v1")], &p),
            id(41, &[entry("DB_URL", "v2")], &p)
        );
    }

    #[test]
    fn plan_id_changes_with_a_planned_name() {
        assert_ne!(
            id(41, &[], &plan_with(&[("DB_URL", MARKER)])),
            id(41, &[], &plan_with(&[("API_KEY", MARKER)]))
        );
    }

    /// SR-1: the same names with another value give the same id: no value goes in.
    #[test]
    fn plan_id_ignores_values() {
        assert_eq!(
            id(41, &[], &plan_with(&[("DB_URL", MARKER)])),
            id(41, &[], &plan_with(&[("DB_URL", "another-value")]))
        );
    }

    /// SR-1: a Fly digest is a digest of the value, so it never goes in.
    #[test]
    fn plan_id_ignores_value_digests() {
        let p = plan_with(&[]);
        let fly = |digest: &str| {
            plan_id(
                &PlanIdInput {
                    env: "prod",
                    product: None,
                    item_version: Some(1),
                    listed: &[entry("DB_URL", digest)],
                    version_ids: false,
                },
                &p,
            )
        };
        assert_eq!(fly("d1"), fly("d2"));
    }

    #[test]
    fn plan_id_is_eight_hex_digits() {
        let p = plan_with(&[]);
        assert!(
            id(1, &[], &p).len() == PLAN_ID_LEN
                && id(1, &[], &p).bytes().all(|b| b.is_ascii_hexdigit())
        );
    }

    #[test]
    fn utc_formats_a_known_instant() {
        assert_eq!(utc(1_791_468_131), "2026-10-08T14:02:11Z");
    }

    #[test]
    fn stamp_reads_back_what_it_writes() {
        let s = Stamp::now("prod", "7f3c9a1e");
        let pairs: BTreeMap<&str, &str> = s.pairs().into_iter().collect();
        assert_eq!(Stamp::parse(|k| pairs.get(k).copied()), Some(s));
    }

    #[test]
    fn stamp_with_a_field_opv_never_writes_is_ignored() {
        let s = Stamp::now("prod", "7f3c9a1e");
        let mut pairs: BTreeMap<&str, &str> = s.pairs().into_iter().collect();
        pairs.insert(STAMP_PLAN, "has spaces");
        assert_eq!(Stamp::parse(|k| pairs.get(k).copied()), None);
    }

    #[test]
    fn stamp_line_names_version_time_and_plan() {
        let s = Stamp {
            opv_version: "0.5.0".into(),
            written: "2026-10-08T14:02:11Z".into(),
            env: "prod".into(),
            plan: "7f3c9a1e".into(),
        };
        assert_eq!(
            s.line(),
            "last changed by opv 0.5.0 at 2026-10-08T14:02:11Z (plan 7f3c9a1e)"
        );
    }
}
