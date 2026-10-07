//! `fly plan` / `fly sync` use cases (FR-5..FR-8, FR-16, §6.4).
//!
//! Fly digests cannot be computed locally (D0 Q4), so `fly sync` is stage-and-compare
//! (ruling P1): read the item once → list A → plan → refuse if anything blocks (nothing
//! staged) → validate the import batch → stage → list B → report each staged key as
//! changed or unchanged by digest → `--prune`: unset the plan's prune list (staged) →
//! `--deploy`: deploy when a staged digest changed, a prune happened, or a managed name is
//! still `Staged`/`Partial` on Fly from an earlier run (FR-7). Without `--deploy`
//! nothing is ever deployed. `fly plan` reads the item once and lists once; it mutates
//! nothing (FR-11).

use std::collections::BTreeSet;
use std::io::Write;

use super::{
    is_blocking, managed_names, print_extras, print_rows, read_and_plan, row_names,
    unmanaged_on_fly, write_err,
};
use crate::adapters::fly;
use crate::domain::rules;
use crate::domain::{Fleet, FlySecret, KeyState, Kind, Row, SecretValue, SyncPlan, TargetState};
use crate::error::Error;
use crate::runner::CommandRunner;

/// Flags of `fly sync`.
#[derive(Debug, Default, Clone)]
pub struct SyncOpts {
    /// Deploy staged changes (FR-7). Never implied.
    pub deploy: bool,
    /// Unset managed names not desired in this environment (FR-8). Never implied.
    pub prune: bool,
    /// `PRODUCT/KEY` entries: immutable keys to stage even though present on Fly (FR-16).
    pub rotate: Vec<String>,
    /// Fail with `Findings` if staging changed any digest (the migration gate, P1).
    pub expect_no_change: bool,
}

pub fn run(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
    opts: &SyncOpts,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    let rotate = parse_rotate(fleet, env_name, &opts.rotate)?;
    let (plan, list_a) = read_and_plan(fleet, env_name, r, true, &rotate)?;

    let blocking = row_names(&plan.rows, is_blocking);
    if !blocking.is_empty() {
        return Err(Error::Policy(format!(
            "fly sync refused, nothing staged: {}",
            blocking.join(", ")
        )));
    }
    let batch: Vec<(String, &SecretValue)> =
        plan.stage.iter().map(|(n, v)| (n.clone(), v)).collect();
    fly::validate_import(&batch)?;
    print_extras(out, &plan)?;
    print_counts(out, &plan)?;

    let mut changed = Vec::new();
    let mut unchanged = Vec::new();
    // Nothing staged by this run: list A is the current state, no second list needed.
    let list_b = if batch.is_empty() {
        list_a.clone()
    } else {
        fly::stage(r, &env.fly_app, &batch)?;
        fly::list(r, &env.fly_app)?
    };
    for (name, _) in &batch {
        let (a, b) = (digest(&list_a, name), digest(&list_b, name));
        // A staged key with no digest after staging is unknown: count it as changed.
        if b.is_none() || a != b {
            changed.push(name.as_str());
        } else {
            unchanged.push(name.as_str());
        }
    }

    let p = |out: &mut dyn Write, s: String| writeln!(out, "{s}").map_err(write_err);
    if opts.expect_no_change && !changed.is_empty() {
        // The gate result wins over output: a failed write must not turn Findings into a
        // dependency error, so these writes are best effort and the result line comes first.
        let _ = p(
            out,
            format!(
                "expected no change, but {} staged key(s) changed: {}",
                changed.len(),
                changed.join(", ")
            ),
        );
        let _ = print_changes(out, &changed, &unchanged);
        return Err(Error::Findings(changed.len()));
    }
    print_changes(out, &changed, &unchanged)?;

    let pruned = if plan.prune.is_empty() {
        false
    } else if opts.prune {
        fly::unset_staged(r, &env.fly_app, &plan.prune)?;
        p(out, format!("pruned (staged): {}", plan.prune.join(", ")))?;
        true
    } else {
        p(
            out,
            format!(
                "not desired here, kept (pass --prune to unset): {}",
                plan.prune.join(", ")
            ),
        )?;
        false
    };

    // Managed names still staged from an earlier run (e.g. a sync without --deploy, or a
    // failed deploy). Status is only an extra deploy trigger, never change detection.
    let managed = managed_names(fleet, env_name)?;
    let pending: Vec<&str> = list_b
        .iter()
        .filter(|s| managed.contains(&s.name))
        .filter(|s| matches!(s.status.as_deref(), Some("Staged" | "Partial")))
        .map(|s| s.name.as_str())
        .collect();
    if !pending.is_empty() {
        p(out, format!("pending on Fly: {}", pending.join(", ")))?;
    }

    let needs_deploy = !changed.is_empty() || pruned || !pending.is_empty();
    match (needs_deploy, opts.deploy) {
        (false, true) => p(out, "nothing pending; not deploying".into()),
        (false, false) => p(out, "nothing pending".into()),
        (true, true) => {
            fly::deploy(r, &env.fly_app)?;
            p(out, "deployed staged secrets".into())
        }
        (true, false) => p(out, "staged changes not deployed (no --deploy)".into()),
    }
}

/// The result line, then the per-key change lists (names only).
fn print_changes(out: &mut dyn Write, changed: &[&str], unchanged: &[&str]) -> Result<(), Error> {
    writeln!(
        out,
        "staged: {} changed, {} unchanged",
        changed.len(),
        unchanged.len()
    )
    .map_err(write_err)?;
    for n in changed {
        writeln!(out, "  changed: {n}").map_err(write_err)?;
    }
    for n in unchanged {
        writeln!(out, "  unchanged: {n}").map_err(write_err)?;
    }
    Ok(())
}

/// `fly plan <env>`: rows, prune list and counts; no mutation. Exits `Findings(n)` when
/// n rows would block a sync.
pub fn plan(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    out: &mut dyn Write,
) -> Result<(), Error> {
    fleet.environment(env_name)?;
    let (plan, on_fly) = read_and_plan(fleet, env_name, r, true, &BTreeSet::new())?;
    let held: BTreeSet<(&str, &str)> = plan
        .held_immutable
        .iter()
        .map(|(p, k)| (p.as_str(), k.as_str()))
        .collect();
    print_rows(out, &plan.rows, |row| {
        plan_target(
            row,
            held.contains(&(row.product.as_str(), row.key.as_str())),
        )
    })?;
    print_extras(out, &plan)?;
    for n in &plan.prune {
        writeln!(out, "to prune (with --prune): {n}").map_err(write_err)?;
    }
    let unmanaged = unmanaged_on_fly(fleet, env_name, &on_fly)?;
    print_counts(out, &plan)?;
    writeln!(out, "{} unmanaged on Fly (never touched)", unmanaged.len()).map_err(write_err)?;
    let n = plan.rows.iter().filter(|r| is_blocking(r)).count();
    if n > 0 {
        writeln!(out, "{n} key(s) block a sync").map_err(write_err)?;
        return Err(Error::Findings(n));
    }
    Ok(())
}

fn print_counts(out: &mut dyn Write, plan: &SyncPlan) -> Result<(), Error> {
    writeln!(
        out,
        "{} to stage, {} held (immutable), {} to prune",
        plan.stage.len(),
        plan.held_immutable.len(),
        plan.prune.len()
    )
    .map_err(write_err)
}

/// Target column of `fly plan`. Keys present on Fly cannot be compared locally, so a
/// desired key there is "potentially changed" (FR-5, P1).
fn plan_target(r: &Row, held: bool) -> String {
    match (r.kind, r.target, r.state) {
        (Kind::Config, _, _) => "-",
        (Kind::Secret, TargetState::Absent, KeyState::Ready) => "absent (new)",
        (Kind::Secret, TargetState::Absent, _) => "absent",
        (Kind::Secret, _, _) if held => "present (immutable, held)",
        (Kind::Secret, _, KeyState::Ready) => "potentially changed",
        (Kind::Secret, _, KeyState::Skipped) => "present (not desired)",
        (Kind::Secret, _, _) => "present",
    }
    .to_string()
}

fn digest<'a>(list: &'a [FlySecret], name: &str) -> Option<&'a str> {
    list.iter()
        .find(|s| s.name == name)
        .and_then(|s| s.digest.as_deref())
}

/// Validate every `--rotate PRODUCT/KEY` before any call (FR-16): it must name a declared,
/// immutable key desired in `env_name`. An unmatched entry is never a silent no-op.
fn parse_rotate(
    fleet: &Fleet,
    env_name: &str,
    entries: &[String],
) -> Result<BTreeSet<(String, String)>, Error> {
    let env = fleet.environment(env_name)?;
    let mut set = BTreeSet::new();
    for e in entries {
        let bad = |why: String| Error::Config(format!("--rotate {e:?}: {why}"));
        let (product, key) = e
            .split_once('/')
            .filter(|(p, k)| !p.is_empty() && !k.is_empty())
            .ok_or_else(|| bad("expected PRODUCT/KEY".into()))?;
        let spec = fleet
            .products
            .get(product)
            .and_then(|p| p.keys.get(key))
            .ok_or_else(|| bad("not a declared key".into()))?;
        if !spec.immutable {
            return Err(bad(
                "key is not immutable (other keys are staged on every sync)".into(),
            ));
        }
        if !rules::applies(spec, env_name, env, product) {
            return Err(bad(format!(
                "key is not desired in environment {env_name:?}"
            )));
        }
        set.insert((product.to_string(), key.to_string()));
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testutil::*;
    use crate::runner::fake::FakeRunner;

    fn f() -> Fleet {
        fleet()
    }
    fn opts() -> SyncOpts {
        SyncOpts::default()
    }
    fn fake_with(item: crate::runner::Output, fly_a: crate::runner::Output) -> FakeRunner {
        FakeRunner::new([item, fly_a])
    }
    /// item, list A, import, list B, then spare responses so an unexpected call (deploy,
    /// unset) is recorded rather than panicking, and the test can assert it never happened.
    fn fake_sync(
        item: crate::runner::Output,
        a: crate::runner::Output,
        b: crate::runner::Output,
    ) -> FakeRunner {
        FakeRunner::new([item, a, ok(), b, ok(), ok(), ok()])
    }
    fn fake_complete() -> FakeRunner {
        fake_sync(
            complete_item(),
            fly_empty(),
            fly(&[(OPENAI_FLY, "d-openai"), (ENC_FLY, "d-enc")]),
        )
    }
    fn sync_out(fleet: &Fleet, r: &FakeRunner, o: &SyncOpts) -> (Result<(), Error>, String) {
        let mut out = Vec::new();
        let res = run(fleet, "prod", r, &mut out, o);
        (res, text_of(&out))
    }

    // ---- fly sync: refusal before staging -------------------------------------------
    //
    // Every refusal test passes --deploy, --prune and a valid --rotate, with a prunable
    // managed name on Fly, and asserts nothing is staged, unset or deployed.

    fn all_flags() -> SyncOpts {
        SyncOpts {
            deploy: true,
            prune: true,
            rotate: vec!["allumata/INTEGRATION_ENC_KEY".into()],
            expect_no_change: false,
        }
    }
    fn assert_nothing_mutated(r: &FakeRunner) {
        for sub in ["import", "unset", "deploy"] {
            assert!(
                !called(r, "flyctl", &["secrets", sub]),
                "{sub}: {:?}",
                argvs(r)
            );
        }
    }

    #[test]
    fn sync_refuses_when_anything_missing_and_stages_nothing() {
        let r = fake_with(
            item_without("allumata", "OPENAI_API_KEY"),
            fly_with_prunable(),
        );
        let e = run(&f(), "prod", &r, &mut Vec::new(), &all_flags()).unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
        assert!(e.to_string().contains("OPENAI_API_KEY"), "{e}");
        assert_no_values(&e.to_string());
        assert!(
            r.calls
                .borrow()
                .iter()
                .all(|c| !(c.program == "flyctl" && c.args.contains(&"import".to_string())))
        );
        assert_nothing_mutated(&r);
    }

    /// Review Focus 2: a product section missing from the item → every key Missing, the
    /// sync refuses, and nothing is staged (the only flyctl call is list A).
    #[test]
    fn sync_refuses_when_product_section_missing() {
        let r = fake_with(item(&[]), fly_with_prunable());
        let (res, out) = sync_out(&f(), &r, &all_flags());
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
        for k in ["OPENAI_API_KEY", "INTEGRATION_ENC_KEY", "SIGNUP_POLICY"] {
            assert!(e.to_string().contains(k), "{e}");
        }
        assert_nothing_mutated(&r);
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json",
                "flyctl secrets list --app mcproductlabs-portfolio-production --json",
            ]
        );
        assert_no_values(&out);
    }

    #[test]
    fn sync_refuses_on_wrong_kind_and_rule_failure() {
        for item in [
            complete_with(text("allumata", "OPENAI_API_KEY", OPENAI)),
            complete_with(secret("allumata", "OPENAI_API_KEY", "sk-or-FIXTUREVALUE")),
            complete_with(secret("allumata", "SIGNUP_POLICY", POLICY)),
        ] {
            let r = fake_with(item, fly_with_prunable());
            let (res, out) = sync_out(&f(), &r, &all_flags());
            let e = res.unwrap_err();
            assert!(matches!(e, Error::Policy(_)), "{e}");
            assert_no_values(&e.to_string());
            assert_no_values(&out);
            assert_nothing_mutated(&r);
        }
    }

    /// A value Fly's import parser would mangle is refused before anything is staged.
    #[test]
    fn sync_validates_import_before_staging() {
        let r = fake_with(
            complete_with(secret("allumata", "OPENAI_API_KEY", "sk-a\"#FIXTUREVALUE")),
            fly_with_prunable(),
        );
        let (res, out) = sync_out(&f(), &r, &all_flags());
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
        assert!(e.to_string().contains(OPENAI_FLY), "{e}");
        assert_no_values(&e.to_string());
        assert_no_values(&out);
        assert_nothing_mutated(&r);
        assert_eq!(r.calls.borrow().len(), 2);
    }

    // ---- fly sync: happy path, deploy, change detection -----------------------------

    #[test]
    fn sync_never_deploys_without_flag() {
        let r = fake_complete();
        let (res, out) = sync_out(&f(), &r, &opts());
        res.unwrap();
        let calls = argvs(&r);
        assert!(
            calls.contains(
                &"flyctl secrets import --app mcproductlabs-portfolio-production --stage"
                    .to_string()
            ),
            "{calls:?}"
        );
        assert!(
            r.calls
                .borrow()
                .iter()
                .all(|c| !c.args.iter().any(|a| a == "deploy")),
            "{calls:?}"
        );
        assert!(!called(&r, "flyctl", &["secrets", "unset"]));
        assert_no_values(&out);
    }

    #[test]
    fn sync_call_sequence_is_read_list_stage_list() {
        let r = fake_complete();
        sync_out(&f(), &r, &opts()).0.unwrap();
        let app = "mcproductlabs-portfolio-production";
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json".to_string(),
                format!("flyctl secrets list --app {app} --json"),
                format!("flyctl secrets import --app {app} --stage"),
                format!("flyctl secrets list --app {app} --json"),
            ]
        );
    }

    #[test]
    fn one_op_request_per_run() {
        let r = fake_complete();
        let _ = run(&f(), "prod", &r, &mut Vec::new(), &opts());
        assert_eq!(
            r.calls
                .borrow()
                .iter()
                .filter(|c| c.program == "op")
                .count(),
            1
        );
    }

    #[test]
    fn sync_values_only_on_stdin() {
        let r = fake_complete();
        let (res, out) = sync_out(&f(), &r, &opts());
        res.unwrap();
        assert_no_values_in_argv(&r);
        assert_no_values(&out);
        let stdin = import_stdin(&r).unwrap();
        assert!(stdin.contains(&format!("{OPENAI_FLY}=\"\"\"{OPENAI}\"\"\"")));
        assert!(stdin.contains(ENC_FLY));
        // Config keys are never Fly secrets.
        assert!(!stdin.contains("SIGNUP_POLICY"));
    }

    #[test]
    fn sync_reports_changed_and_unchanged_by_digest() {
        let r = fake_sync(
            complete_item(),
            fly(&[(OPENAI_FLY, "d1")]),
            fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]),
        );
        let (res, out) = sync_out(&f(), &r, &opts());
        res.unwrap();
        assert!(out.contains("1 changed, 1 unchanged"), "{out}");
        assert!(out.contains(&format!("changed: {ENC_FLY}")), "{out}");
        assert!(out.contains(&format!("unchanged: {OPENAI_FLY}")), "{out}");
        assert_no_values(&out);
    }

    #[test]
    fn sync_deploys_with_flag_when_changed() {
        let r = fake_complete();
        let o = SyncOpts {
            deploy: true,
            ..opts()
        };
        sync_out(&f(), &r, &o).0.unwrap();
        assert_eq!(
            argvs(&r).last().unwrap(),
            "flyctl secrets deploy --app mcproductlabs-portfolio-production"
        );
    }

    /// FR-7: nothing changed, nothing pruned, everything Deployed → no deploy, even with
    /// `--deploy`.
    #[test]
    fn sync_skips_deploy_when_nothing_pending() {
        let same = || fly_st(&[(OPENAI_FLY, "d1", "Deployed"), (ENC_FLY, "d2", "Deployed")]);
        let r = fake_sync(complete_item(), same(), same());
        let o = SyncOpts {
            deploy: true,
            ..opts()
        };
        let (res, out) = sync_out(&f(), &r, &o);
        res.unwrap();
        assert!(
            !called(&r, "flyctl", &["secrets", "deploy"]),
            "{:?}",
            argvs(&r)
        );
        assert!(out.contains("nothing pending; not deploying"), "{out}");
    }

    /// A == B, but a managed name is still Staged from an earlier run (a sync without
    /// --deploy, or a failed deploy): `--deploy` must deploy it.
    #[test]
    fn sync_deploys_managed_name_pending_from_earlier_run() {
        for status in ["Staged", "Partial"] {
            let same = || fly_st(&[(OPENAI_FLY, "d1", status), (ENC_FLY, "d2", "Deployed")]);
            let r = fake_sync(complete_item(), same(), same());
            let o = SyncOpts {
                deploy: true,
                ..opts()
            };
            let (res, out) = sync_out(&f(), &r, &o);
            res.unwrap();
            assert_eq!(
                argvs(&r).last().unwrap(),
                "flyctl secrets deploy --app mcproductlabs-portfolio-production",
                "{status}"
            );
            assert!(
                out.contains(&format!("pending on Fly: {OPENAI_FLY}")),
                "{out}"
            );
        }
    }

    /// With nothing staged (every secret immutable and held) there is no list B; pending
    /// is judged on list A, and `--deploy` still deploys the earlier run's staged name.
    #[test]
    fn sync_deploys_pending_when_nothing_staged() {
        let text = std::fs::read_to_string("tests/fixtures/secrets.toml").unwrap();
        let fl = crate::config::parse(&text.replace(
            "guidance = \"OpenAI platform / API keys\"",
            "guidance = \"OpenAI platform / API keys\"\nimmutable = true",
        ))
        .unwrap();
        let a = || fly_st(&[(ENC_FLY, "d2", "Staged"), (OPENAI_FLY, "d1", "Deployed")]);
        let r = FakeRunner::new([complete_item(), a(), ok(), ok()]);
        let o = SyncOpts {
            deploy: true,
            ..opts()
        };
        let (res, out) = sync_out(&fl, &r, &o);
        res.unwrap();
        let app = "mcproductlabs-portfolio-production";
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json".to_string(),
                format!("flyctl secrets list --app {app} --json"),
                format!("flyctl secrets deploy --app {app}"),
            ],
            "{out}"
        );
    }

    /// Another tool's staged secret is not secretctl's to deploy.
    #[test]
    fn unmanaged_staged_name_does_not_trigger_deploy() {
        let same = || {
            fly_st(&[
                (OPENAI_FLY, "d1", "Deployed"),
                (ENC_FLY, "d2", "Deployed"),
                ("OTHER_TOOL_TOKEN", "d9", "Staged"),
            ])
        };
        let r = fake_sync(complete_item(), same(), same());
        let o = SyncOpts {
            deploy: true,
            ..opts()
        };
        let (res, out) = sync_out(&f(), &r, &o);
        res.unwrap();
        assert!(
            !called(&r, "flyctl", &["secrets", "deploy"]),
            "{:?}",
            argvs(&r)
        );
        assert!(!out.contains("OTHER_TOOL_TOKEN"), "{out}");
    }

    /// Status never suppresses: a changed digest deploys even if Fly says Deployed.
    #[test]
    fn changed_digest_deploys_regardless_of_status() {
        let r = fake_sync(
            complete_item(),
            fly_st(&[(OPENAI_FLY, "d1", "Deployed"), (ENC_FLY, "d2", "Deployed")]),
            fly_st(&[(OPENAI_FLY, "d1b", "Deployed"), (ENC_FLY, "d2", "Deployed")]),
        );
        let o = SyncOpts {
            deploy: true,
            ..opts()
        };
        sync_out(&f(), &r, &o).0.unwrap();
        assert!(called(&r, "flyctl", &["secrets", "deploy"]));
    }

    #[test]
    fn expect_no_change_fails_when_a_digest_changed() {
        // ENC is immutable and present, so held; only OPENAI is staged, and it changed.
        // The Stripe name is prunable in prod, and --prune/--deploy are passed: the gate
        // must stop before either happens.
        let r = fake_sync(
            complete_item(),
            fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2"), (STRIPE_FLY, "d3")]),
            fly(&[(OPENAI_FLY, "d1-new"), (ENC_FLY, "d2"), (STRIPE_FLY, "d3")]),
        );
        let o = SyncOpts {
            expect_no_change: true,
            deploy: true,
            prune: true,
            ..opts()
        };
        let (res, out) = sync_out(&f(), &r, &o);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Findings(1)), "{e}");
        assert!(out.contains(OPENAI_FLY), "{out}");
        assert!(!called(&r, "flyctl", &["secrets", "deploy"]));
        assert!(!called(&r, "flyctl", &["secrets", "unset"]));
        assert_no_values(&out);
    }

    /// M3: a broken stdout must not turn the gate's Findings into a dependency error.
    #[test]
    fn expect_no_change_findings_survive_broken_stdout() {
        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let r = fake_sync(
            complete_item(),
            fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]),
            fly(&[(OPENAI_FLY, "d1-new"), (ENC_FLY, "d2")]),
        );
        // Output before staging (counts) must succeed; every write after list B fails.
        struct FailAfterStage<'a>(&'a FakeRunner, Vec<u8>);
        impl std::io::Write for FailAfterStage<'_> {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                if self.0.calls.borrow().len() >= 4 {
                    return Broken.write(b);
                }
                self.1.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let o = SyncOpts {
            expect_no_change: true,
            ..opts()
        };
        let mut w = FailAfterStage(&r, Vec::new());
        let e = run(&f(), "prod", &r, &mut w, &o).unwrap_err();
        assert!(matches!(e, Error::Findings(1)), "{e}");
    }

    /// A staged key Fly reports without a digest is unknown, so it counts as changed: the
    /// gate must not pass and a deploy must not be skipped on missing evidence.
    #[test]
    fn staged_key_without_digest_after_staging_counts_as_changed() {
        let r = fake_sync(
            complete_item(),
            fly(&[(ENC_FLY, "d2")]),
            fly(&[(ENC_FLY, "d2")]),
        );
        let o = SyncOpts {
            expect_no_change: true,
            ..opts()
        };
        let e = sync_out(&f(), &r, &o).0.unwrap_err();
        assert!(matches!(e, Error::Findings(1)), "{e}");
    }

    #[test]
    fn expect_no_change_passes_when_digests_equal() {
        let same = || fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]);
        let r = fake_sync(complete_item(), same(), same());
        let o = SyncOpts {
            expect_no_change: true,
            ..opts()
        };
        sync_out(&f(), &r, &o).0.unwrap();
    }

    // ---- immutable and --rotate -----------------------------------------------------

    #[test]
    fn immutable_present_on_fly_is_held_not_staged() {
        let a = || fly(&[(ENC_FLY, "d-enc")]);
        let r = fake_sync(complete_item(), a(), a());
        let (res, out) = sync_out(&f(), &r, &opts());
        res.unwrap();
        let stdin = import_stdin(&r).unwrap();
        assert!(!stdin.contains(ENC_FLY), "immutable key staged");
        assert!(stdin.contains(OPENAI_FLY));
        assert!(out.contains("1 held (immutable)"), "{out}");
    }

    #[test]
    fn rotate_stages_an_immutable_key() {
        let a = || fly(&[(ENC_FLY, "d-enc")]);
        let r = fake_sync(complete_item(), a(), fly(&[(ENC_FLY, "d-enc2")]));
        let o = SyncOpts {
            rotate: vec!["allumata/INTEGRATION_ENC_KEY".into()],
            ..opts()
        };
        sync_out(&f(), &r, &o).0.unwrap();
        assert!(import_stdin(&r).unwrap().contains(ENC_FLY));
    }

    #[test]
    fn rotate_entries_are_validated_before_any_call() {
        let fl = fleet_with(
            "[products.allumata.keys.STAGING_ONLY]\nkind = \"secret\"\n\
             environments = [\"staging\"]\nimmutable = true\n",
        );
        for bad in [
            "allumata/NOPE",                // undeclared key
            "nosuch/INTEGRATION_ENC_KEY",   // undeclared product
            "allumata/OPENAI_API_KEY",      // not immutable
            "allumata/STAGING_ONLY",        // not desired in prod
            "allumata-INTEGRATION_ENC_KEY", // malformed
            "allumata/",                    // malformed
        ] {
            let r = FakeRunner::new([]);
            let o = SyncOpts {
                rotate: vec!["allumata/INTEGRATION_ENC_KEY".into(), bad.into()],
                ..all_flags()
            };
            let e = run(&fl, "prod", &r, &mut Vec::new(), &o).unwrap_err();
            assert!(matches!(e, Error::Config(_)), "{bad}: {e}");
            assert!(e.to_string().contains(bad), "{bad}: {e}");
            assert!(r.calls.borrow().is_empty(), "{bad}: calls made");
        }
    }

    /// A rotate entry for an immutable key that is skipped by mode is not desired.
    #[test]
    fn rotate_rejects_mode_skipped_key() {
        let fl = fleet_with(
            "[products.allumata.keys.STRIPE_WEBHOOK]\nkind = \"secret\"\n\
             environments = [\"staging\", \"prod\"]\nimmutable = true\n\
             rules = { prefix_by_mode = { mode = \"payments\", values = { test = \"whsec_\" }, \
             skip = [\"off\"] } }\n",
        );
        let r = FakeRunner::new([]);
        let o = SyncOpts {
            rotate: vec!["allumata/STRIPE_WEBHOOK".into()],
            ..all_flags()
        };
        let e = run(&fl, "prod", &r, &mut Vec::new(), &o).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        assert!(r.calls.borrow().is_empty());
    }

    // ---- --prune --------------------------------------------------------------------

    fn fly_with_prunable() -> crate::runner::Output {
        // prod has payments = "off", so the Stripe key is managed but not desired → prune.
        fly(&[(STRIPE_FLY, "d-s"), ("OTHER_TOOL_TOKEN", "d-o")])
    }

    #[test]
    fn sync_never_prunes_without_flag() {
        let r = fake_sync(complete_item(), fly_with_prunable(), fly_with_prunable());
        sync_out(&f(), &r, &opts()).0.unwrap();
        assert!(
            !called(&r, "flyctl", &["secrets", "unset"]),
            "{:?}",
            argvs(&r)
        );
    }

    #[test]
    fn sync_prunes_only_managed_names_with_flag() {
        let r = fake_sync(complete_item(), fly_with_prunable(), fly_with_prunable());
        let o = SyncOpts {
            prune: true,
            ..opts()
        };
        sync_out(&f(), &r, &o).0.unwrap();
        assert!(
            argvs(&r).contains(&format!(
                "flyctl secrets unset {STRIPE_FLY} --app mcproductlabs-portfolio-production --stage"
            )),
            "{:?}",
            argvs(&r)
        );
        assert!(!r.argv_contains("OTHER_TOOL_TOKEN"));
    }

    #[test]
    fn prune_counts_as_a_change_for_deploy() {
        let a = || fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2"), (STRIPE_FLY, "d3")]);
        let r = fake_sync(complete_item(), a(), a());
        let o = SyncOpts {
            prune: true,
            deploy: true,
            ..opts()
        };
        sync_out(&f(), &r, &o).0.unwrap();
        assert!(called(&r, "flyctl", &["secrets", "unset"]));
        assert!(called(&r, "flyctl", &["secrets", "deploy"]));
    }

    // ---- failures -------------------------------------------------------------------

    #[test]
    fn unknown_env_is_config_error_before_any_call() {
        let r = FakeRunner::new([]);
        let e = run(&f(), "qa", &r, &mut Vec::new(), &opts()).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        let e = plan(&f(), "qa", &r, &mut Vec::new()).unwrap_err();
        assert!(matches!(e, Error::Config(_)), "{e}");
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn stage_failure_is_target_error_and_stops() {
        let r = FakeRunner::new([
            complete_item(),
            fly_empty(),
            crate::runner::Output::failure(1),
            ok(),
            ok(),
        ]);
        let o = SyncOpts {
            deploy: true,
            prune: true,
            ..opts()
        };
        let e = run(&f(), "prod", &r, &mut Vec::new(), &o).unwrap_err();
        assert!(matches!(e, Error::Target(_)), "{e}");
        assert_eq!(r.calls.borrow().len(), 3);
    }

    // ---- fly plan -------------------------------------------------------------------

    fn plan_out(r: &FakeRunner) -> (Result<(), Error>, String) {
        let mut out = Vec::new();
        let res = plan(&f(), "prod", r, &mut out);
        (res, text_of(&out))
    }

    #[test]
    fn plan_makes_no_mutation_and_one_op_call() {
        let r = FakeRunner::new([complete_item(), fly_with_prunable(), ok(), ok()]);
        plan_out(&r).0.unwrap();
        assert_eq!(
            argvs(&r),
            vec![
                "op item get iprd --vault vprd --format json",
                "flyctl secrets list --app mcproductlabs-portfolio-production --json",
            ]
        );
        assert_eq!(op_calls(&r), 1);
    }

    #[test]
    fn plan_prints_rows_targets_and_counts() {
        let r = FakeRunner::new([
            complete_item(),
            fly(&[
                (OPENAI_FLY, "d1"),
                (ENC_FLY, "d2"),
                (STRIPE_FLY, "d3"),
                ("OTHER_TOOL_TOKEN", "d4"),
            ]),
        ]);
        let (res, out) = plan_out(&r);
        res.unwrap();
        assert!(
            out.contains("1 to stage, 1 held (immutable), 1 to prune"),
            "{out}"
        );
        assert!(out.contains("potentially changed"), "{out}");
        assert!(out.contains(STRIPE_FLY), "{out}");
        assert!(out.contains("1 unmanaged on Fly"), "{out}");
        assert_no_values(&out);
    }

    #[test]
    fn plan_reports_new_keys_absent_from_fly() {
        let r = FakeRunner::new([complete_item(), fly_empty()]);
        let (res, out) = plan_out(&r);
        res.unwrap();
        assert!(
            out.contains("2 to stage, 0 held (immutable), 0 to prune"),
            "{out}"
        );
        assert!(out.contains("absent (new)"), "{out}");
    }

    #[test]
    fn plan_with_blocking_rows_is_findings_and_names_only() {
        let r = FakeRunner::new([
            complete_with(secret("allumata", "OPENAI_API_KEY", "sk-or-FIXTUREVALUE")),
            fly_empty(),
        ]);
        let (res, out) = plan_out(&r);
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Findings(1)), "{e}");
        assert!(out.contains("fails rule not_prefix"), "{out}");
        assert_no_values(&out);
        assert_no_values(&e.to_string());
    }
}
