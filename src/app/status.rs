//! `status <env>` use case (FR-17, spec §7.3, ruling P17).
//!
//! A one-line count summary first (NR-16), then one row per product × key with its
//! 1Password state and target state, guidance under each missing row, extras as warnings.
//! Names only. Exits `Findings(n)` for the n rows that are missing, of the wrong kind or
//! failing a rule; extras alone exit 0. `--product` limits all of it to one product (P12);
//! without an environment, one count line per environment (P22). Read-only: one `op item get` and one store list
//! (plus the free `op whoami` diagnosis when the read fails). A pinned target is also read
//! value by value (FR-31) and its bindings once, for the pending-deploy, drift and
//! env-routed lines (FR-29).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use super::sync::{drift_line, pinned_diff, pinned_want};
use super::{
    KeyNames, PinnedRow, check_product, ci_summary, count_line, is_blocking, item_url, open_next,
    open_target, plan_item, plural, preflight, print_extras, print_legend, print_rows,
    product_names, read_and_plan, read_fields, scope_plan, target_word, write_err, write_json,
};
use crate::domain::{Binding, Fleet, KeyState, Row, StoreEntry, SyncPlan};
use crate::error::Error;
use crate::ports::{PinnedRuntime, PinnedStore, Ports};
use crate::provider::TargetConfig;
use crate::runner::CommandRunner;

pub fn run(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    run_with(fleet, env_name, r, out, false)
}

/// `status <env> [--json]` for every product.
pub fn run_with(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    run_scoped(fleet, env_name, None, r, out, json)
}

/// `status <env> [--product p] [--json]`. Text starts with the one-line count summary
/// (NR-16), then the rows. With `json`, stdout carries one FR-21 document and nothing
/// else. `product` limits rows, totals and findings to one product (P12). Exit codes are
/// unchanged (`Findings` for blocking rows).
pub fn run_scoped(
    fleet: &Fleet,
    env_name: &str,
    product: Option<&str>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    check_product(fleet, product)?;
    // Needs a target: `Error::Config` naming the environment otherwise, before any call.
    let (t, ports) = open_target(fleet, env_name, r)?;
    // The target's state, read-only and never waiting (NR-23, NR-25).
    preflight::read(t, r)?;
    let none = BTreeSet::new();
    let (mut plan, listed) = read_and_plan(fleet, env_name, r, Some(&ports), &none, &none)?;
    if let Some(p) = product {
        scope_plan(&mut plan, p, &product_names(fleet, env_name, p)?);
    }
    let pinned = match &ports {
        Ports::Pinned { store, runtime } => Some(pinned_status(
            fleet,
            env_name,
            t,
            &plan,
            &listed,
            store.as_ref(),
            runtime.as_ref(),
        )?),
        Ports::Staged { .. } => None,
    };
    let n = plan.rows.iter().filter(|r| is_blocking(r)).count();
    // The 1Password link for the rows to fix (H1): one free `op whoami`, only when needed.
    let link = if n > 0 {
        Some(item_url(fleet, env_name, r)?)
    } else {
        None
    };
    let findings = || Error::findings(n, open_next(&plan.rows, env_name));
    let env = fleet.environment(env_name)?;
    let held: BTreeSet<(&str, &str)> = plan
        .held_immutable
        .iter()
        .map(|(p, k)| (p.as_str(), k.as_str()))
        .collect();
    let word = |row: &Row| {
        let binding = env
            .target_name(&row.product, &row.key)
            .and_then(|name| pinned.as_ref().and_then(|p| p.rows.get(&name)));
        target_word(
            row,
            held.contains(&(row.product.as_str(), row.key.as_str())),
            binding,
        )
        .to_string()
    };
    let count = count_line(env_name, &plan.rows, t.provider().label());
    r.step_summary(&ci_summary::table(
        &status_command(env_name, product),
        &count,
        None,
        &plan.rows,
        fleet.is_simple(),
        word,
    ));
    if json {
        write_json(
            out,
            fleet,
            env_name,
            &plan,
            pinned.as_ref().map(|p| &p.rows),
            product,
            link.as_deref(),
        )?;
        return if n > 0 { Err(findings()) } else { Ok(()) };
    }
    let names = KeyNames::new(fleet, env_name)?;
    writeln!(out, "{count}").map_err(write_err)?;
    print_rows(out, fleet, &plan.rows, word, link.as_deref())?;
    let words: Vec<String> = plan.rows.iter().map(&word).collect();
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    print_legend(out, &words, t.provider().label())?;
    print_extras(out, &plan)?;
    if let Some(p) = &pinned {
        p.print(out, env_name, &names)?;
    }
    if n > 0 {
        return Err(findings());
    }
    Ok(())
}

/// `opv status <env>[ --product p]`.
fn status_command(env_name: &str, product: Option<&str>) -> String {
    match product {
        Some(p) => format!("opv status {env_name} --product {p}"),
        None => format!("opv status {env_name}"),
    }
}

/// `status` without an environment (P22, H11): one count line per environment, in name
/// order. Every environment is read, a run-only one too (`dev: run-only · 2 keys · 1
/// finding`), so a green overview means every environment is green. One item read per
/// environment (FR-13); a target is also listed as `status <env>` does. `product` limits
/// every line to that product's keys. An environment that cannot be read is one line
/// naming the error, and the rest are still shown; the first such error is the result,
/// else `Findings` when any environment has findings. With `json`, one document
/// `{"schema_version":1,"product":…,"environments":[{"name","target","keys","saved",
/// "skipped","findings","error"}]}` and nothing else on stdout.
pub fn overview(
    fleet: &Fleet,
    product: Option<&str>,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), Error> {
    check_product(fleet, product)?;
    let mut first_err: Option<(String, Error)> = None;
    let mut findings = 0;
    let mut first_finding: Option<&str> = None;
    let mut docs = Vec::new();
    for (name, env) in &fleet.environments {
        let t = env.target();
        let rows = env_rows(fleet, name, t, r).map(|mut rows| {
            if let Some(p) = product {
                rows.retain(|row| row.product == p);
            }
            rows
        });
        let target = t.map(|t| t.provider().section());
        match rows {
            Ok(rows) => {
                let line = match t {
                    Some(t) => count_line(name, &rows, t.provider().label()),
                    None => run_only_line(name, &rows),
                };
                let n = rows.iter().filter(|r| is_blocking(r)).count();
                if n > 0 {
                    findings += n;
                    first_finding.get_or_insert(name);
                }
                docs.push(OverviewEnv {
                    name: name.clone(),
                    target,
                    keys: Some(rows.len()),
                    saved: Some(rows.iter().filter(|r| r.state == KeyState::Ready).count()),
                    skipped: Some(rows.iter().filter(|r| r.state == KeyState::Skipped).count()),
                    findings: Some(n),
                    error: None,
                });
                if !json {
                    writeln!(out, "{line}").map_err(write_err)?;
                }
            }
            Err(e) => {
                let first = e.to_string().lines().next().unwrap_or_default().to_string();
                if !json {
                    writeln!(out, "{name}: not checked ({first})").map_err(write_err)?;
                }
                docs.push(OverviewEnv {
                    name: name.clone(),
                    target,
                    keys: None,
                    saved: None,
                    skipped: None,
                    findings: None,
                    error: Some(first),
                });
                first_err.get_or_insert((name.clone(), e));
            }
        }
    }
    if json {
        let doc = OverviewDoc {
            schema_version: 1,
            product: product.map(str::to_string),
            environments: docs,
        };
        let text = serde_json::to_string(&doc)
            .map_err(|e| Error::Dependency(format!("cannot serialize JSON ({e})").into()))?;
        writeln!(out, "{text}").map_err(write_err)?;
    }
    let scoped = |cmd: String| match product {
        Some(p) => format!("{cmd} --product {p}"),
        None => cmd,
    };
    if let Some((name, e)) = first_err {
        return Err(e.or_next(|| scoped(format!("opv status {name}"))));
    }
    match first_finding {
        Some(name) => {
            let cmd = match fleet.environments.get(name).and_then(|e| e.target()) {
                Some(_) => format!("opv status {name}"),
                None if fleet.is_simple() => format!("opv check {name}"),
                None => match product {
                    Some(_) => format!("opv check {name}"),
                    None => format!("opv check {name} --product {}", first_product(fleet)),
                },
            };
            Err(Error::findings(findings, scoped(cmd)))
        }
        None => Ok(()),
    }
}

/// The first declared product, for a runnable `opv check <env> --product <p>` step.
fn first_product(fleet: &Fleet) -> &str {
    fleet
        .products
        .keys()
        .next()
        .map_or("<name>", String::as_str)
}

/// `dev: run-only · 4 keys · 3 saved · 1 skipped · 1 finding` (H11).
fn run_only_line(env_name: &str, rows: &[Row]) -> String {
    let saved = rows.iter().filter(|r| r.state == KeyState::Ready).count();
    let skipped = rows.iter().filter(|r| r.state == KeyState::Skipped).count();
    let n = rows.iter().filter(|r| is_blocking(r)).count();
    format!(
        "{env_name}: run-only · {} · {saved} saved · {skipped} skipped · {}",
        plural(rows.len(), "key", "keys"),
        plural(n, "finding", "findings"),
    )
}

#[derive(serde::Serialize)]
struct OverviewDoc {
    schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    product: Option<String>,
    environments: Vec<OverviewEnv>,
}

/// One environment of the overview document: counts, or the first line of the error that
/// stopped it (value-free like every error).
#[derive(serde::Serialize)]
struct OverviewEnv {
    name: String,
    /// The target section (`fly`, `azure`, `kubernetes`), or `null` for run-only.
    target: Option<&'static str>,
    keys: Option<usize>,
    saved: Option<usize>,
    skipped: Option<usize>,
    findings: Option<usize>,
    error: Option<String>,
}

/// One environment's rows, for [`overview`]: with a target as `status <env>` reads them
/// (item and store list), without one from the item alone, as `check` does.
fn env_rows(
    fleet: &Fleet,
    env_name: &str,
    t: Option<&dyn TargetConfig>,
    r: &dyn CommandRunner,
) -> Result<Vec<Row>, Error> {
    let none = BTreeSet::new();
    let Some(t) = t else {
        let fields = read_fields(fleet, env_name, r)?;
        return Ok(plan_item(fleet, env_name, fields, None, &none, &none)?
            .0
            .rows);
    };
    let (_, ports) = open_target(fleet, env_name, r)?;
    preflight::read(t, r)?;
    Ok(
        read_and_plan(fleet, env_name, r, Some(&ports), &none, &none)?
            .0
            .rows,
    )
}

/// Bindings of a pinned target (FR-29): per desired name whether its binding is current,
/// whether the next `--deploy` changes it, and drift; plus the env-routed config names.
struct PinnedStatus {
    rows: BTreeMap<String, PinnedRow>,
    pending: Vec<String>,
    drift: Vec<String>,
    env_routed: Vec<String>,
    runtime: String,
}

impl PinnedStatus {
    fn print(&self, out: &mut dyn Write, env_name: &str, names: &KeyNames) -> Result<(), Error> {
        let mut line = |text: String| writeln!(out, "{text}").map_err(write_err);
        if !self.pending.is_empty() {
            line(format!(
                "pending deploy (opv sync {env_name} --deploy): {}",
                names.join(&self.pending)
            ))?;
        }
        if !self.drift.is_empty() {
            line(drift_line(env_name, &names.join(&self.drift)))?;
        }
        for (name, row) in &self.rows {
            if let Some(chain) = &row.chain {
                let rest = chain.strip_prefix(name.as_str()).unwrap_or(chain);
                line(format!("chain: {}{rest}", names.label(name)))?;
            }
        }
        if !self.env_routed.is_empty() {
            line(format!(
                "env-routed (visible to readers of {}): {}",
                self.runtime,
                names.join(&self.env_routed)
            ))?;
        }
        Ok(())
    }
}

/// Reads the runtime's bindings once and compares them with the plan (no write).
fn pinned_status(
    fleet: &Fleet,
    env_name: &str,
    t: &dyn TargetConfig,
    plan: &SyncPlan,
    listed: &[StoreEntry],
    store: &dyn PinnedStore,
    runtime: &dyn PinnedRuntime,
) -> Result<PinnedStatus, Error> {
    let want = pinned_want(
        fleet,
        env_name,
        plan,
        listed,
        store,
        runtime.config_in_store(),
    )?;
    let snap = runtime.bindings()?;
    let d = pinned_diff(t, &want, &BTreeMap::new(), &snap, plan, false);
    let pending = d.pending();
    let rows = want
        .store
        .keys()
        .chain(want.plain.keys())
        .map(|n| {
            let is_pending = pending.contains(n.as_str());
            let binding = match (snap.bindings.contains_key(n), is_pending) {
                (_, false) => "current",
                (true, true) => "stale",
                (false, true) => "unbound",
            };
            let chain = match snap.bindings.get(n) {
                Some(Binding::Pinned { version, .. }) if want.store.contains_key(n) => {
                    runtime.chain(n, version)
                }
                _ => None,
            };
            let row = PinnedRow {
                binding,
                pending_deploy: is_pending,
                drift: d.drift.contains(n),
                chain,
            };
            (n.clone(), row)
        })
        .collect();
    Ok(PinnedStatus {
        rows,
        pending: pending.iter().map(|n| n.to_string()).collect(),
        drift: d.drift.iter().cloned().collect(),
        env_routed: want.plain.keys().cloned().collect(),
        runtime: runtime.describe(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testutil::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    fn status_of(item: Output, fly_list: Output) -> (Result<(), Error>, String, FakeRunner) {
        let r = FakeRunner::new([item, fly_list]);
        let mut out = Vec::new();
        let res = run(&fleet(), "prod", &r, &mut out);
        (res, text_of(&out), r)
    }

    /// Every value-bearing path: saved rows, rule failures, wrong kind, missing (with
    /// guidance), extras, and the returned error. The marker must never appear.
    #[test]
    fn status_prints_names_never_values() {
        let extra = secret("allumata", "OPENAI_API_KEYS", "sk-proj-FIXTUREVALUE-typo");
        let cases: Vec<(Vec<Field>, &str)> = vec![
            (complete_fields(), "saved"),
            (
                vec![
                    secret("allumata", "OPENAI_API_KEY", "sk-or-FIXTUREVALUE"),
                    secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
                    text("allumata", "SIGNUP_POLICY", "FIXTUREVALUE"),
                ],
                "failed ",
            ),
            (
                vec![
                    text("allumata", "OPENAI_API_KEY", OPENAI),
                    secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
                    secret("allumata", "SIGNUP_POLICY", POLICY),
                ],
                "wrong kind",
            ),
            (
                vec![
                    secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
                    text("allumata", "SIGNUP_POLICY", POLICY),
                    extra.clone(),
                ],
                "missing",
            ),
            (
                vec![
                    secret("allumata", "OPENAI_API_KEY", " sk-proj-FIXTUREVALUE\n"),
                    secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
                    text("allumata", "SIGNUP_POLICY", POLICY),
                    extra.clone(),
                ],
                "failed ",
            ),
        ];
        for (fields, expect) in cases {
            let (res, out, _) = status_of(item(&fields), fly(&[(OPENAI_FLY, "d1")]));
            assert!(out.contains("OPENAI_API_KEY"), "{out}");
            assert!(out.contains(expect), "{expect}: {out}");
            assert_no_values(&out);
            if let Err(e) = res {
                assert_no_values(&e.to_string());
                assert_no_values(&format!("{e:?}"));
            }
        }
    }

    #[test]
    fn status_missing_row_prints_guidance_on_next_line() {
        let (res, out, _) = status_of(item_without("allumata", "OPENAI_API_KEY"), fly_empty());
        assert!(matches!(res, Err(Error::Findings(1, _))), "{res:?}");
        let lines: Vec<&str> = out.lines().collect();
        let i = lines
            .iter()
            .position(|l| l.contains("OPENAI_API_KEY") && l.contains("missing"))
            .unwrap();
        assert!(lines[i + 1].contains("OpenAI platform / API keys"), "{out}");
    }

    /// FR-26: a value failing its rule shows the reason and, under it, the key's guidance.
    #[test]
    fn status_rule_failure_prints_guidance_on_next_line() {
        let (res, out, _) = status_of(
            complete_with(secret("allumata", "OPENAI_API_KEY", "sk-or-FIXTUREVALUE")),
            fly_empty(),
        );
        assert!(matches!(res, Err(Error::Findings(1, _))), "{res:?}");
        let lines: Vec<&str> = out.lines().collect();
        let i = lines
            .iter()
            .position(|l| l.contains("OPENAI_API_KEY") && l.contains("failed "))
            .unwrap();
        assert!(lines[i + 1].starts_with("    guidance: "), "{out}");
        assert!(lines[i + 1].contains("OpenAI platform / API keys"), "{out}");
        assert_no_values(&out);
    }

    /// Review Focus 2: a missing product section reports every desired key missing.
    #[test]
    fn status_missing_section_reports_every_key_missing() {
        let (res, out, _) = status_of(item(&[]), fly_empty());
        assert!(matches!(res, Err(Error::Findings(3, _))), "{res:?}");
        for k in ["OPENAI_API_KEY", "INTEGRATION_ENC_KEY", "SIGNUP_POLICY"] {
            assert!(
                out.lines().any(|l| l.contains(k) && l.contains("missing")),
                "{k}: {out}"
            );
        }
        // prod has payments = "off": the Stripe key is skipped, not missing.
        assert!(
            out.lines()
                .any(|l| l.contains("STRIPE_SECRET_KEY") && l.contains("skipped")),
            "{out}"
        );
    }

    /// P17: extras are warnings; they alone exit 0.
    #[test]
    fn status_extras_alone_exit_zero() {
        let mut fs = complete_fields();
        fs.push(secret("allumata", "OPENAI_API_KEYS", OPENAI));
        let (res, out, _) = status_of(item(&fs), fly_empty());
        res.unwrap();
        assert!(
            out.contains("warning: extra field allumata/OPENAI_API_KEYS"),
            "{out}"
        );
        assert_no_values(&out);
    }

    #[test]
    fn status_complete_is_ok_and_shows_target_state() {
        let (res, out, _) = status_of(complete_item(), fly(&[(OPENAI_FLY, "d1")]));
        res.unwrap();
        let row = |k: &str| out.lines().find(|l| l.contains(k)).unwrap().to_string();
        assert!(row("OPENAI_API_KEY").ends_with("unknown"), "{out}");
        assert!(row("INTEGRATION_ENC_KEY").ends_with("new"), "{out}");
        assert!(row("SIGNUP_POLICY").ends_with("n/a"), "{out}");
        assert!(out.contains("PRODUCT") && out.contains("TARGET"), "{out}");
    }

    #[test]
    fn status_reads_item_once_and_lists_once() {
        let (_, _, r) = status_of(complete_item(), fly_empty());
        assert_eq!(op_calls(&r), 1);
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json",
                "flyctl secrets list --app mcproductlabs-portfolio-production --json",
            ]
        );
    }

    /// I1: a prod-only SMTP_PASS present (non-empty) in the staging item is a blocking
    /// `refuse_in` row in staging status, naming product and key.
    #[test]
    fn status_refuse_in_is_blocking_in_refused_env() {
        let fl = fleet_with(
            "[products.allumata.keys.SMTP_PASS]\nkind = \"secret\"\n\
             environments = [\"prod\"]\nrules = { refuse_in = [\"staging\"] }\n",
        );
        let fields = vec![
            secret("allumata", "INTEGRATION_ENC_KEY", &enc()),
            secret("allumata", "STRIPE_SECRET_KEY", "sk_test_FIXTUREVALUE"),
            text("allumata", "SIGNUP_POLICY", POLICY),
            secret("allumata", "SMTP_PASS", "FIXTUREVALUE-smtp"),
        ];
        let r = FakeRunner::new([item(&fields), fly_empty()]);
        let mut out = Vec::new();
        let res = run(&fl, "staging", &r, &mut out);
        let out = text_of(&out);
        assert!(matches!(res, Err(Error::Findings(1, _))), "{res:?}");
        assert!(
            out.lines().any(|l| l.starts_with("allumata")
                && l.contains("SMTP_PASS")
                && l.contains("failed refuse_in (")),
            "{out}"
        );
        assert_no_values(&out);
    }

    /// I2: a value that passes the rules but cannot travel on a Fly import line shows as a
    /// failing rule (exit 8), not green.
    #[test]
    fn status_shows_import_refusal_as_failing_rule() {
        let (res, out, _) = status_of(
            complete_with(secret("allumata", "OPENAI_API_KEY", "sk-a\"#FIXTUREVALUE")),
            fly_empty(),
        );
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Findings(1, _)), "{e}");
        assert_eq!(e.exit_code(), 8);
        assert!(
            out.lines().any(|l| l.contains("OPENAI_API_KEY")
                && l.contains("failed import-hash-after-odd-quotes (")),
            "{out}"
        );
        assert_no_values(&out);
    }

    /// I5: status needs a Fly target; Config naming the environment, before any call.
    #[test]
    fn status_env_without_fly_is_config_error_before_any_call() {
        let fl = fleet_with("[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n");
        let r = FakeRunner::new([]);
        let e = run(&fl, "dev", &r, &mut Vec::new()).unwrap_err();
        assert!(
            matches!(&e, Error::Config(m) if m.contains("\"dev\"") && m.contains("no deployment target")),
            "{e}"
        );
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn status_unknown_env_is_config_error_before_any_call() {
        let r = FakeRunner::new([]);
        let e = run(&fleet(), "qa", &r, &mut Vec::new()).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn status_source_failure_is_typed_and_value_free() {
        let r = FakeRunner::new(std::iter::once(Output::failure(1)).chain([Output::success(
            br#"{"email":"x-FIXTUREVALUE@example.com","user_type":"SERVICE_ACCOUNT"}"#.to_vec(),
        )]));
        r.responses
            .borrow_mut()
            .push_back(Ok(crate::runner::Output::failure(1)));
        let mut out = Vec::new();
        let e = run(&fleet(), "prod", &r, &mut out).unwrap_err();
        assert!(matches!(e, Error::Source(_)), "{e}");
        assert_no_values(&e.to_string());
        // One item read, then the free session and vault checks (NR-26, P16: before any
        // retry; the vault is not readable, so none); no Fly call.
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json",
                "op whoami --format json",
                "op vault get vprd --format json"
            ]
        );
    }

    /// NR-16: the first line is the count summary.
    #[test]
    fn status_starts_with_a_count_summary() {
        let (res, out, _) = status_of(complete_item(), fly(&[(OPENAI_FLY, "d1")]));
        res.unwrap();
        // prod: OPENAI_API_KEY (on Fly), INTEGRATION_ENC_KEY (absent), SIGNUP_POLICY
        // (config); the Stripe key is skipped.
        assert_eq!(
            out.lines().next().unwrap(),
            "prod: 4 keys · 3 saved · 1 skipped · 0 findings · 1 not yet on Fly",
            "{out}"
        );
    }

    /// Findings are counted in the summary line, and exit 8 is unchanged.
    #[test]
    fn status_with_findings_counts_them_first() {
        let (_, out, _) = status_of(item_without("allumata", "OPENAI_API_KEY"), fly_empty());
        assert!(
            out.lines().next().unwrap().contains(" · 1 finding · "),
            "{out}"
        );
    }

    #[test]
    fn status_with_findings_exits_8() {
        let (res, _, _) = status_of(item_without("allumata", "OPENAI_API_KEY"), fly_empty());
        assert_eq!(res.unwrap_err().exit_code(), 8);
    }

    /// NR-19, H1: the next step opens the first key to fix in 1Password.
    #[test]
    fn status_findings_next_step_opens_the_first_key() {
        let (res, _, _) = status_of(item_without("allumata", "OPENAI_API_KEY"), fly_empty());
        assert_eq!(
            res.unwrap_err().next_step(),
            Some("opv open allumata/OPENAI_API_KEY --env prod")
        );
    }
}
