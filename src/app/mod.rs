//! Application use cases, one module per command (§6.2).
//!
//! Rules shared by every command:
//! - The environment name is resolved with [`Fleet::environment`] before any subprocess
//!   call, so an unknown name is `Error::Config` and `plan::build` never sees one.
//! - A command that reads 1Password makes exactly one `op` call (FR-13).
//! - Output names products, keys, kinds, rules and Fly names, never values (SR-1).

pub mod config_export;
pub mod doctor;
pub mod run;
pub mod skeleton;
pub mod status;
pub mod sync;

use std::collections::{BTreeSet, HashSet};
use std::io::{self, Write};

use crate::adapters::{fly, onepassword};
use crate::domain::plan;
use crate::domain::{Fleet, FlySecret, KeyState, Kind, Row, SecretValue, SyncPlan};
use crate::error::Error;
use crate::runner::CommandRunner;

/// Fly digests are not computable locally (D0 Q4, ruling P1): every key present on Fly is
/// `Unknown` to the planner, and change detection is stage-and-compare in `fly sync`.
fn no_digest(_: &SecretValue) -> Option<String> {
    None
}

/// Read the environment's item once (FR-13), list the Fly app once when `with_fly`, and
/// build the plan. `env_name` must already be resolved (callers do it first).
pub(crate) fn read_and_plan(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    with_fly: bool,
    rotate: &BTreeSet<(String, String)>,
) -> Result<(SyncPlan, Vec<FlySecret>), Error> {
    let env = fleet.environment(env_name)?;
    let item = onepassword::read_item(r, env)?;
    let on_fly = if with_fly {
        fly::list(r, &env.fly_app)?
    } else {
        Vec::new()
    };
    let p = plan::build(fleet, env_name, item.fields, &on_fly, rotate, &no_digest);
    Ok((p, on_fly))
}

/// A failed write to the output stream (closed pipe and the like).
pub(crate) fn write_err(e: io::Error) -> Error {
    Error::Dependency(format!("cannot write output ({})", e.kind()))
}

pub(crate) fn kind_label(k: Kind) -> &'static str {
    match k {
        Kind::Secret => "secret",
        Kind::Config => "config",
    }
}

pub(crate) fn state_label(s: KeyState) -> String {
    match s {
        KeyState::Missing => "missing".into(),
        KeyState::WrongKind => "wrong kind".into(),
        KeyState::RuleFailed(rule) => format!("fails rule {rule}"),
        KeyState::Ready => "saved".into(),
        KeyState::Skipped => "skipped".into(),
    }
}

/// `product/KEY` of every row in `rows` matching `pred`, for names-only messages.
pub(crate) fn row_names(rows: &[Row], pred: impl Fn(&Row) -> bool) -> Vec<String> {
    rows.iter()
        .filter(|r| pred(r))
        .map(|r| format!("{}/{} ({})", r.product, r.key, state_label(r.state)))
        .collect()
}

pub(crate) fn is_blocking(r: &Row) -> bool {
    matches!(
        r.state,
        KeyState::Missing | KeyState::WrongKind | KeyState::RuleFailed(_)
    )
}

/// Missing keys, and keys that exist but are empty (a skeleton field nobody filled in),
/// get their declared guidance printed under the row (FR-17, spec §7.4).
fn wants_guidance(r: &Row) -> bool {
    matches!(
        r.state,
        KeyState::Missing | KeyState::RuleFailed("nonempty")
    ) && !r.guidance.is_empty()
}

/// Print `rows` as a table `PRODUCT KEY KIND STATE TARGET`, with guidance on the line after
/// each missing row. `target` renders the last column. Rows hold names only.
pub(crate) fn print_rows(
    out: &mut dyn Write,
    rows: &[Row],
    target: impl Fn(&Row) -> String,
) -> Result<(), Error> {
    let header = ["PRODUCT", "KEY", "KIND", "STATE", "TARGET"].map(String::from);
    let cells: Vec<[String; 5]> = rows
        .iter()
        .map(|r| {
            [
                r.product.clone(),
                r.key.clone(),
                kind_label(r.kind).to_string(),
                state_label(r.state),
                target(r),
            ]
        })
        .collect();
    let mut w = [0usize; 4];
    for c in std::iter::once(&header).chain(&cells) {
        for (i, wi) in w.iter_mut().enumerate() {
            *wi = (*wi).max(c[i].len());
        }
    }
    let line = |c: &[String; 5]| {
        let mut s = String::new();
        for (i, wi) in w.iter().enumerate() {
            s.push_str(&format!("{:<wi$}  ", c[i]));
        }
        s.push_str(&c[4]);
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
            "warning: extra field {section}/{label} is in the 1Password item but not declared"
        )
        .map_err(write_err)?;
    }
    Ok(())
}

/// Every Fly name the template renders for a declared key: the managed set (FR-8, §10).
pub(crate) fn managed_names(fleet: &Fleet, env_name: &str) -> Result<HashSet<String>, Error> {
    let env = fleet.environment(env_name)?;
    Ok(fleet
        .products
        .iter()
        .flat_map(|(p, prod)| prod.keys.keys().map(move |k| env.fly_name(p, k)))
        .collect())
}

/// Fly names on the app that the template does not render for any declared key: other
/// tools' secrets, which secretctl never touches (FR-5 "unmanaged on Fly", §10.3).
pub(crate) fn unmanaged_on_fly<'a>(
    fleet: &Fleet,
    env_name: &str,
    on_fly: &'a [FlySecret],
) -> Result<Vec<&'a str>, Error> {
    let managed = managed_names(fleet, env_name)?;
    Ok(on_fly
        .iter()
        .map(|s| s.name.as_str())
        .filter(|n| !managed.contains(*n))
        .collect())
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
            if !sections.iter().any(|x| x["id"] == s.as_str()) {
                sections.push(json!({"id": s, "label": s}));
            }
            let mut f = json!({
                "id": format!("{s}_{}", l.to_lowercase()),
                "section": {"id": s, "label": s},
                "type": ty,
                "label": l,
            });
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
