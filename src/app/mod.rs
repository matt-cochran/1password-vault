//! Application use cases, one module per command (§6.2).
//!
//! Rules shared by every command:
//! - The environment name is resolved with [`Fleet::environment`] before any subprocess
//!   call, so an unknown name is `Error::Config` and `plan::build` never sees one.
//! - A command that reads 1Password makes exactly one `op item get` (FR-13); a failed `op`
//!   call adds only the free `op whoami` / `op account list` diagnosis (FR-26).
//! - Output names products, keys, kinds, rules and Fly names, never values (SR-1).

#[cfg(test)]
mod characterization_tests;
pub mod config_export;
pub mod doctor;
pub mod explain;
#[cfg(test)]
mod guidance_tests;
pub mod init;
pub mod run;
#[cfg(test)]
mod simple_tests;
pub mod skeleton;
pub mod status;
pub mod sync;

use std::collections::{BTreeSet, HashSet};
use std::io::{self, Write};

use crate::adapters::onepassword;
use crate::domain::plan;
use crate::domain::{
    Fleet, KeyState, Kind, Row, SIMPLE_PRODUCT, SecretValue, StoreEntry, SyncPlan, TargetState,
    key_label,
};
use crate::error::Error;
use crate::ports::SecretStore;
use crate::runner::CommandRunner;

/// Fly digests are not computable locally (D0 Q4, ruling P1): every key present on Fly is
/// `Unknown` to the planner, and change detection is stage-and-compare in `fly sync`.
fn no_digest(_: &SecretValue) -> Option<String> {
    None
}

/// Read the environment's item once (FR-13), list the target's store once when `store` is
/// given, and build the plan. `env_name` must already be resolved, and the target opened,
/// by the caller (so a missing target is `Error::Config` before any call).
///
/// With a store, every ready secret is also checked against the store's own rules
/// ([`SecretStore::refusal`]), so `status` and `plan` show a value `sync` would refuse as a
/// failing rule naming product/KEY.
pub(crate) fn read_and_plan(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    store: Option<&dyn SecretStore>,
    rotate: &BTreeSet<(String, String)>,
    prune_immutable: &BTreeSet<(String, String)>,
) -> Result<(SyncPlan, Vec<StoreEntry>), Error> {
    let env = fleet.environment(env_name)?;
    let item = onepassword::read_item_as(r, env, fleet.profile)?;
    let on_target = match store {
        Some(s) => s.list()?,
        None => Vec::new(),
    };
    let refusal = |n: &str, v: &SecretValue| store.and_then(|s| s.refusal(n, v));
    let p = plan::build_with(
        fleet,
        env_name,
        item.fields,
        &on_target,
        &plan::PlanOptions {
            rotate,
            prune_immutable,
            digest: &no_digest,
            target_check: &refusal,
        },
    );
    Ok((p, on_target))
}

/// A failed write to the output stream. A closed pipe never gets here: `main` swallows
/// `BrokenPipe` so the command still returns its own result (e.g. `status | head`).
pub(crate) fn write_err(e: io::Error) -> Error {
    Error::Dependency(format!("cannot write output ({})", e.kind()))
}

/// The `product` of a JSON row: `None` (JSON `null`) for the simple profile's implicit
/// product, which is never shown (FR-20).
fn json_product(product: &str) -> Option<String> {
    (product != SIMPLE_PRODUCT).then(|| product.to_string())
}

/// FR-21: one names-only JSON document for `status --json` and `fly plan --json`.
///
/// Under the simple profile (FR-20) `product` is `null` in rows, extras and held entries,
/// matching the text table, which has no PRODUCT column there.
///
/// `schema_version` is 1; adding a field keeps the version. Rows carry names, states and
/// counts only (SR-1): no value, value fragment, value length or guidance text. Errors
/// before this point leave stdout empty, so a caller only gets a document on success.
pub(crate) fn write_json(
    out: &mut dyn Write,
    fleet: &Fleet,
    env_name: &str,
    plan: &SyncPlan,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    let staged: HashSet<&str> = plan.stage.iter().map(|(n, _)| n.as_str()).collect();
    let pruned: HashSet<&str> = plan.prune.iter().map(String::as_str).collect();
    let held_keys: HashSet<(&str, &str)> = plan
        .held_immutable
        .iter()
        .map(|(p, k)| (p.as_str(), k.as_str()))
        .collect();
    let held_from_prune: HashSet<&str> = plan
        .held_from_prune
        .iter()
        .map(|(_, _, n)| n.as_str())
        .collect();

    let rows: Vec<JsonRow> = plan
        .rows
        .iter()
        .map(|r| {
            let fly_name = env.target_name(&r.product, &r.key);
            let action = row_action(
                r,
                fly_name.as_deref(),
                &staged,
                &pruned,
                &held_keys,
                &held_from_prune,
            );
            JsonRow {
                product: json_product(&r.product),
                key: r.key.clone(),
                kind: kind_label(r.kind),
                state: json_state(&r.state),
                rule: json_rule(&r.state),
                reason: json_reason(&r.state),
                fly_name,
                target: json_target(r.kind, r.target),
                action,
            }
        })
        .collect();

    let doc = JsonDoc {
        schema_version: 1,
        environment: env_name.to_string(),
        rows,
        extras: plan
            .extras
            .iter()
            .map(|(product, key)| JsonName {
                product: json_product(product),
                key: key.clone(),
            })
            .collect(),
        stage: plan.stage.iter().map(|(n, _)| n.clone()).collect(),
        held: plan
            .held_immutable
            .iter()
            .map(|(product, key)| JsonHeld {
                product: json_product(product),
                key: key.clone(),
                fly_name: env.target_name(product, key),
            })
            .collect(),
        prune: plan.prune.clone(),
        totals: JsonTotals {
            rows: plan.rows.len(),
            findings: plan.blocking(),
            extras: plan.extras.len(),
            to_stage: plan.stage.len(),
            held: plan.held_immutable.len(),
            to_prune: plan.prune.len(),
        },
    };
    let text = serde_json::to_string(&doc)
        .map_err(|e| Error::Dependency(format!("cannot serialize JSON ({e})")))?;
    writeln!(out, "{text}").map_err(write_err)
}

#[derive(serde::Serialize)]
struct JsonDoc {
    schema_version: u32,
    environment: String,
    rows: Vec<JsonRow>,
    extras: Vec<JsonName>,
    stage: Vec<String>,
    held: Vec<JsonHeld>,
    prune: Vec<String>,
    totals: JsonTotals,
}

#[derive(serde::Serialize)]
struct JsonRow {
    product: Option<String>,
    key: String,
    kind: &'static str,
    state: &'static str,
    rule: Option<&'static str>,
    /// Why `rule` failed (FR-22): from the rule's fixed set or the configuration only.
    reason: Option<String>,
    fly_name: Option<String>,
    target: Option<&'static str>,
    action: Option<&'static str>,
}

#[derive(serde::Serialize)]
struct JsonName {
    product: Option<String>,
    key: String,
}

#[derive(serde::Serialize)]
struct JsonHeld {
    product: Option<String>,
    key: String,
    fly_name: Option<String>,
}

#[derive(serde::Serialize)]
struct JsonTotals {
    rows: usize,
    findings: usize,
    extras: usize,
    to_stage: usize,
    held: usize,
    to_prune: usize,
}

/// Machine-readable row state, spelled with underscores (FR-21).
fn json_state(s: &KeyState) -> &'static str {
    match s {
        KeyState::Missing => "missing",
        KeyState::WrongKind => "wrong_kind",
        KeyState::RuleFailed(..) => "failing_rule",
        KeyState::Ready => "saved",
        KeyState::Skipped => "skipped",
    }
}

/// The name of the failing rule, next to the state (FR-22).
fn json_rule(s: &KeyState) -> Option<&'static str> {
    match s {
        KeyState::RuleFailed(rule, _) => Some(rule),
        _ => None,
    }
}

/// Why the rule failed, as a separate field next to `rule` (FR-22). Never the value.
fn json_reason(s: &KeyState) -> Option<String> {
    match s {
        KeyState::RuleFailed(_, reason) => Some(reason.to_string()),
        _ => None,
    }
}

/// Target presence: secrets are present/absent/would-change; config is not a Fly secret.
fn json_target(kind: Kind, target: TargetState) -> Option<&'static str> {
    match (kind, target) {
        (Kind::Config, _) => None,
        (Kind::Secret, TargetState::Absent) => Some("absent"),
        (Kind::Secret, TargetState::WouldChange) => Some("would_change"),
        (Kind::Secret, _) => Some("present"),
    }
}

/// What a `fly plan` would do with this row: stage, prune or hold it.
fn row_action(
    r: &Row,
    fly_name: Option<&str>,
    staged: &HashSet<&str>,
    pruned: &HashSet<&str>,
    held_keys: &HashSet<(&str, &str)>,
    held_from_prune: &HashSet<&str>,
) -> Option<&'static str> {
    if held_keys.contains(&(r.product.as_str(), r.key.as_str())) {
        return Some("held");
    }
    let name = fly_name?;
    if staged.contains(name) {
        Some("would_stage")
    } else if pruned.contains(name) {
        Some("would_prune")
    } else if held_from_prune.contains(name) {
        Some("held")
    } else {
        None
    }
}

pub(crate) fn kind_label(k: Kind) -> &'static str {
    match k {
        Kind::Secret => "secret",
        Kind::Config => "config",
    }
}

/// The STATE cell: a failing rule reads `failed <rule> (<reason>)` (FR-22).
pub(crate) fn state_label(s: &KeyState) -> String {
    match s {
        KeyState::Missing => "missing".into(),
        KeyState::WrongKind => "wrong kind".into(),
        KeyState::RuleFailed(rule, reason) => format!("failed {rule} ({reason})"),
        KeyState::Ready => "saved".into(),
        KeyState::Skipped => "skipped".into(),
    }
}

/// `product/KEY` (`KEY` under the simple profile) of every row in `rows` matching `pred`,
/// for names-only messages.
pub(crate) fn row_names(rows: &[Row], pred: impl Fn(&Row) -> bool) -> Vec<String> {
    rows.iter()
        .filter(|r| pred(r))
        .map(|r| {
            format!(
                "{} ({})",
                key_label(&r.product, &r.key),
                state_label(&r.state)
            )
        })
        .collect()
}

pub(crate) fn is_blocking(r: &Row) -> bool {
    matches!(
        r.state,
        KeyState::Missing | KeyState::WrongKind | KeyState::RuleFailed(..)
    )
}

/// Missing keys, and keys whose value fails a rule (including an empty skeleton field
/// nobody filled in), get their declared guidance printed under the row (FR-17, spec §7.4;
/// FR-26: the reason, in the STATE column, plus the key's guidance).
fn wants_guidance(r: &Row) -> bool {
    matches!(r.state, KeyState::Missing | KeyState::RuleFailed(..)) && !r.guidance.is_empty()
}

/// Print `rows` as a table `PRODUCT KEY KIND STATE TARGET`, with guidance on the line after
/// each missing row. `target` renders the last column. Rows hold names only. Under the
/// simple profile (FR-20) there is no PRODUCT column: the table is `KEY KIND STATE TARGET`.
pub(crate) fn print_rows(
    out: &mut dyn Write,
    fleet: &Fleet,
    rows: &[Row],
    target: impl Fn(&Row) -> String,
) -> Result<(), Error> {
    let skip = usize::from(fleet.is_simple());
    let header: Vec<String> = ["PRODUCT", "KEY", "KIND", "STATE", "TARGET"]
        .iter()
        .skip(skip)
        .map(|s| s.to_string())
        .collect();
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            [
                r.product.clone(),
                r.key.clone(),
                kind_label(r.kind).to_string(),
                state_label(&r.state),
                target(r),
            ]
            .into_iter()
            .skip(skip)
            .collect()
        })
        .collect();
    let last = header.len() - 1;
    let mut w = vec![0usize; last];
    for c in std::iter::once(&header).chain(&cells) {
        for (i, wi) in w.iter_mut().enumerate() {
            *wi = (*wi).max(c[i].len());
        }
    }
    let line = |c: &[String]| {
        let mut s = String::new();
        for (i, wi) in w.iter().enumerate() {
            s.push_str(&format!("{:<wi$}  ", c[i]));
        }
        s.push_str(&c[last]);
        s.trim_end().to_string()
    };
    writeln!(out, "{}", line(&header)).map_err(write_err)?;
    for (r, c) in rows.iter().zip(&cells) {
        writeln!(out, "{}", line(c)).map_err(write_err)?;
        if wants_guidance(r) {
            writeln!(out, "    guidance: {}", r.guidance).map_err(write_err)?;
        }
    }
    Ok(())
}

/// Print each undeclared item field as a warning; extras are never staged or pruned.
pub(crate) fn print_extras(out: &mut dyn Write, plan: &SyncPlan) -> Result<(), Error> {
    for (section, label) in &plan.extras {
        writeln!(
            out,
            "warning: extra field {} is in the 1Password item but not declared",
            key_label(section, label)
        )
        .map_err(write_err)?;
    }
    Ok(())
}

/// Every Fly name the template renders for a declared key: the managed set (FR-8, §10).
pub(crate) fn managed_names(fleet: &Fleet, env_name: &str) -> Result<HashSet<String>, Error> {
    let (_, target) = fleet.target(env_name)?;
    Ok(fleet
        .products
        .iter()
        .flat_map(|(p, prod)| prod.keys.keys().map(move |k| target.target_name(p, k)))
        .collect())
}

/// Fly names on the app that the template does not render for any declared key: other
/// tools' secrets, which opv never touches (FR-5 "unmanaged on Fly", §10.3).
pub(crate) fn unmanaged_on_target<'a>(
    fleet: &Fleet,
    env_name: &str,
    on_fly: &'a [StoreEntry],
) -> Result<Vec<&'a str>, Error> {
    let managed = managed_names(fleet, env_name)?;
    Ok(on_fly
        .iter()
        .map(|s| s.name.as_str())
        .filter(|n| !managed.contains(*n))
        .collect())
}

/// FR-12, §8 item 27: use cases reach a target only through the ports. `init` writes a Fly
/// configuration and `doctor` checks installed vendor CLIs, so both may name an adapter.
#[cfg(test)]
#[test]
fn use_cases_name_no_target_adapter() {
    let mut hits = Vec::new();
    for dir in ["src/app", "src/domain"] {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            let exempt = ["init.rs", "doctor.rs", "characterization_tests.rs"];
            if exempt.iter().any(|x| p.ends_with(x)) {
                continue;
            }
            let s = std::fs::read_to_string(&p).unwrap();
            // Built at runtime so this test does not match itself.
            let needles = [["fly", "::"].concat(), ["adapters::", "fly"].concat()];
            if needles.iter().any(|n| s.contains(n.as_str())) {
                hits.push(p);
            }
        }
    }
    assert!(hits.is_empty(), "a target adapter named in core: {hits:?}");
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Fixtures for command tests: items are built in code with obviously fake, rule-valid
    //! values (ruling P7). Every value contains [`MARKER`] so leaks are easy to assert.

    use base64::Engine as _;
    use serde_json::{Value, json};

    use crate::config;
    use crate::domain::Fleet;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    pub const MARKER: &str = "FIXTUREVALUE";
    pub const OPENAI: &str = "sk-proj-FIXTUREVALUE";
    pub const POLICY: &str = "invite_only";
    pub const OPENAI_FLY: &str = "FLEET__ALLUMATA__OPENAI_API_KEY";
    pub const ENC_FLY: &str = "FLEET__ALLUMATA__INTEGRATION_ENC_KEY";
    pub const STRIPE_FLY: &str = "FLEET__ALLUMATA__STRIPE_SECRET_KEY";

    pub fn fleet() -> Fleet {
        config::load("tests/fixtures/secrets.toml").unwrap()
    }

    /// The fixture fleet plus extra TOML appended (e.g. another key).
    pub fn fleet_with(extra: &str) -> Fleet {
        let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
        config::parse(&format!("{text}\n{extra}")).unwrap()
    }

    /// 32 bytes, base64. The bytes spell the marker, so a decoded leak is detectable too.
    pub fn enc() -> String {
        let mut b = *b"FIXTUREVALUEFIXTUREVALUEFIXTUREV";
        b[31] = b'!';
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    /// One field: (section, label, `CONCEALED`/`STRING`, value; `None` = empty field).
    pub type Field = (String, String, &'static str, Option<String>);

    pub fn secret(section: &str, label: &str, v: &str) -> Field {
        (section.into(), label.into(), "CONCEALED", Some(v.into()))
    }
    pub fn text(section: &str, label: &str, v: &str) -> Field {
        (section.into(), label.into(), "STRING", Some(v.into()))
    }

    /// Every key desired in prod, correctly typed and rule-valid.
    pub fn complete_fields() -> Vec<Field> {
        vec![
            secret("allumata", "OPENAI_API_KEY", OPENAI),
            secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
            text("allumata", "SIGNUP_POLICY", POLICY),
        ]
    }

    /// `op item get --format json` output for `fields`, shaped like the D0 fixture.
    pub fn item_json(fields: &[Field]) -> Vec<u8> {
        let mut sections: Vec<Value> = Vec::new();
        let mut fs: Vec<Value> = vec![json!({
            "id": "notesPlain", "type": "STRING", "purpose": "NOTES", "label": "notesPlain"
        })];
        for (s, l, ty, v) in fields {
            // An empty section is an unsectioned field (simple profile, FR-20).
            let mut f = if s.is_empty() {
                json!({"id": l.to_lowercase(), "type": ty, "label": l})
            } else {
                if !sections.iter().any(|x| x["id"] == s.as_str()) {
                    sections.push(json!({"id": s, "label": s}));
                }
                json!({
                    "id": format!("{s}_{}", l.to_lowercase()),
                    "section": {"id": s, "label": s},
                    "type": ty,
                    "label": l,
                })
            };
            if let Some(v) = v {
                f["value"] = json!(v);
            }
            fs.push(f);
        }
        serde_json::to_vec(&json!({
            "id": "iprd", "title": "fleet", "version": 1,
            "vault": {"id": "vprd", "name": "fleet-prod"},
            "category": "SECURE_NOTE",
            "sections": sections,
            "fields": fs,
        }))
        .unwrap()
    }

    pub fn item(fields: &[Field]) -> Output {
        Output::success(item_json(fields))
    }
    pub fn complete_item() -> Output {
        item(&complete_fields())
    }
    pub fn item_without(section: &str, label: &str) -> Output {
        let fs: Vec<Field> = complete_fields()
            .into_iter()
            .filter(|(s, l, _, _)| !(s == section && l == label))
            .collect();
        item(&fs)
    }
    /// `fields` with the entry for `label` replaced.
    pub fn complete_with(f: Field) -> Output {
        let mut fs: Vec<Field> = complete_fields()
            .into_iter()
            .filter(|(s, l, _, _)| !(*s == f.0 && *l == f.1))
            .collect();
        fs.push(f);
        item(&fs)
    }

    /// `flyctl secrets list --json` output: (name, digest).
    pub fn fly(entries: &[(&str, &str)]) -> Output {
        let v: Vec<Value> = entries
            .iter()
            .map(|(n, d)| json!({"name": n, "digest": d, "status": "Deployed"}))
            .collect();
        Output::success(serde_json::to_vec(&v).unwrap())
    }
    /// `flyctl secrets list --json` output with explicit Fly status: (name, digest, status).
    pub fn fly_st(entries: &[(&str, &str, &str)]) -> Output {
        let v: Vec<Value> = entries
            .iter()
            .map(|(n, d, st)| json!({"name": n, "digest": d, "status": st}))
            .collect();
        Output::success(serde_json::to_vec(&v).unwrap())
    }
    pub fn fly_empty() -> Output {
        Output::success(b"[]".to_vec())
    }
    pub fn ok() -> Output {
        Output::success(Vec::new())
    }

    pub fn op_calls(r: &FakeRunner) -> usize {
        r.calls
            .borrow()
            .iter()
            .filter(|c| c.program == "op")
            .count()
    }

    /// True if some call to `program` has argv starting with `prefix`.
    pub fn called(r: &FakeRunner, program: &str, prefix: &[&str]) -> bool {
        r.calls.borrow().iter().any(|c| {
            c.program == program
                && c.args.len() >= prefix.len()
                && c.args.iter().zip(prefix).all(|(a, p)| a == p)
        })
    }

    /// `program args...` of every call, for exact-sequence assertions.
    pub fn argvs(r: &FakeRunner) -> Vec<String> {
        r.calls
            .borrow()
            .iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect()
    }

    /// Stdin of the staging import, as text (it carries values by design).
    pub fn import_stdin(r: &FakeRunner) -> Option<String> {
        r.calls
            .borrow()
            .iter()
            .find(|c| c.program == "flyctl" && c.args.iter().any(|a| a == "import"))
            .map(|c| String::from_utf8(c.stdin.clone().unwrap_or_default()).unwrap())
    }

    /// No value (marker, or the base64 form) in any argv or env value (SR-3).
    pub fn assert_no_values_in_argv(r: &FakeRunner) {
        assert!(!r.argv_contains(MARKER), "value in argv: {:?}", argvs(r));
        assert!(!r.argv_contains(&enc()), "value in argv: {:?}", argvs(r));
        for c in r.calls.borrow().iter() {
            assert!(c.env.iter().all(|(_, v)| !v.contains(MARKER)));
        }
    }

    /// Output or error text must not contain any fixture value.
    pub fn assert_no_values(s: &str) {
        assert!(!s.contains(MARKER), "value leaked: {s}");
        assert!(!s.contains(&enc()), "value leaked: {s}");
    }

    pub fn text_of(out: &[u8]) -> String {
        String::from_utf8(out.to_vec()).unwrap()
    }
}
