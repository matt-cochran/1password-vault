//! `fly plan` / `fly sync` use cases (FR-5..FR-8).

use std::io::Write;

use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::CommandRunner;

/// Flags of `fly sync`.
#[derive(Debug, Default, Clone)]
pub struct SyncOpts {
    pub deploy: bool,
    pub prune: bool,
    pub rotate: Vec<String>,
    pub expect_no_change: bool,
}

pub fn run(
    _fleet: &Fleet,
    _env_name: &str,
    _r: &dyn CommandRunner,
    _out: &mut dyn Write,
    _opts: &SyncOpts,
) -> Result<(), Error> {
    todo!()
}

pub fn plan(
    _fleet: &Fleet,
    _env_name: &str,
    _r: &dyn CommandRunner,
    _out: &mut dyn Write,
) -> Result<(), Error> {
    todo!()
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
    fn no_import(r: &FakeRunner) -> bool {
        !called(r, "flyctl", &["secrets", "import"])
    }

    // ---- fly sync: refusal before staging -------------------------------------------

    #[test]
    fn sync_refuses_when_anything_missing_and_stages_nothing() {
        let r = fake_with(item_without("allumata", "OPENAI_API_KEY"), fly_empty());
        let e = run(&f(), "prod", &r, &mut Vec::new(), &opts()).unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
        assert!(e.to_string().contains("OPENAI_API_KEY"), "{e}");
        assert_no_values(&e.to_string());
        assert!(
            r.calls
                .borrow()
                .iter()
                .all(|c| !(c.program == "flyctl" && c.args.contains(&"import".to_string())))
        );
    }

    /// Review Focus 2: a product section missing from the item → every key Missing, the
    /// sync refuses, and nothing is staged (the only flyctl call is list A).
    #[test]
    fn sync_refuses_when_product_section_missing() {
        let r = fake_with(item(&[]), fly_empty());
        let (res, out) = sync_out(&f(), &r, &opts());
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
        for k in ["OPENAI_API_KEY", "INTEGRATION_ENC_KEY", "SIGNUP_POLICY"] {
            assert!(e.to_string().contains(k), "{e}");
        }
        assert!(no_import(&r));
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
            let r = fake_with(item, fly_empty());
            let (res, out) = sync_out(&f(), &r, &opts());
            let e = res.unwrap_err();
            assert!(matches!(e, Error::Policy(_)), "{e}");
            assert_no_values(&e.to_string());
            assert_no_values(&out);
            assert!(no_import(&r));
        }
    }

    /// A value Fly's import parser would mangle is refused before anything is staged.
    #[test]
    fn sync_validates_import_before_staging() {
        let r = fake_with(
            complete_with(secret("allumata", "OPENAI_API_KEY", "sk-a\"#FIXTUREVALUE")),
            fly_empty(),
        );
        let (res, out) = sync_out(&f(), &r, &opts());
        let e = res.unwrap_err();
        assert!(matches!(e, Error::Policy(_)), "{e}");
        assert!(e.to_string().contains(OPENAI_FLY), "{e}");
        assert_no_values(&e.to_string());
        assert_no_values(&out);
        assert!(no_import(&r));
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

    /// FR-7: no effective change → no deploy, even with `--deploy`.
    #[test]
    fn sync_skips_deploy_when_no_effective_change() {
        let same = || fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]);
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
        assert!(out.contains("no effective change"), "{out}");
    }

    #[test]
    fn expect_no_change_fails_when_a_digest_changed() {
        let r = fake_sync(
            complete_item(),
            fly(&[(OPENAI_FLY, "d1")]),
            fly(&[(OPENAI_FLY, "d1-new")]),
        );
        let o = SyncOpts {
            expect_no_change: true,
            deploy: true,
            ..opts()
        };
        let (res, out) = sync_out(&f(), &r, &o);
        let e = res.unwrap_err();
        // OPENAI changed and ENC was absent in A and B (counts as unchanged digest: none).
        assert!(matches!(e, Error::Findings(1)), "{e}");
        assert!(out.contains(OPENAI_FLY), "{out}");
        assert!(!called(&r, "flyctl", &["secrets", "deploy"]));
        assert_no_values(&out);
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
                ..opts()
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
            ..opts()
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
