//! Temp-repo tests for [`super`] (design Part V, row `retire`): each builds a real git
//! repository through the real [`ProcessRunner`] and asserts one public outcome.

use super::*;
use crate::runner::{Call, Outcome, ProcessRunner};
use std::path::Path;

/// A contract with a `shared` `dev` and a `production` `prod`, both carrying `API_KEY`.
const TWO_ENVS: &str = "[environments.dev]\n\
tier = \"shared\"\n\
boundaries.app = { vault_id = \"vdev0000000000000000000001\", item_id = \"app\" }\n\n\
[environments.prod]\n\
tier = \"production\"\n\
boundaries.app = { vault_id = \"vprod000000000000000000001\", item_id = \"app\" }\n\n\
[products.app.keys.API_KEY]\n\
kind = \"secret\"\n\
environments = [\"dev\", \"prod\"]\n";

fn runner() -> ProcessRunner {
    ProcessRunner::default()
}

/// Run one git command through the real [`ProcessRunner`]; panic unless it exits 0.
fn git(r: &ProcessRunner, dir: &Path, args: &[&str]) {
    let mut argv = vec!["-C", dir.to_str().expect("utf-8 temp path")];
    argv.extend_from_slice(args);
    match r.write(&Call::new("git", &argv)).unwrap() {
        Outcome::Done(_) => {}
        other => panic!("git {args:?} did not exit 0: {other:?}"),
    }
}

/// A fresh repository whose default branch is `main`.
fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let r = runner();
    git(&r, dir.path(), &["init", "-q"]);
    git(&r, dir.path(), &["symbolic-ref", "HEAD", "refs/heads/main"]);
    git(
        &r,
        dir.path(),
        &["config", "user.email", "test@example.com"],
    );
    git(&r, dir.path(), &["config", "user.name", "Test"]);
    dir
}

/// Write `text` at `path` under `dir`, creating its parent directories.
fn write(dir: &Path, path: &str, text: &str) {
    let full = dir.join(path);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(full, text).unwrap();
}

/// Commit `path` at `HEAD`.
fn commit(dir: &Path, path: &str) {
    let r = runner();
    git(&r, dir, &["add", path]);
    git(&r, dir, &["commit", "-q", "--no-gpg-sign", "-m", "work"]);
}

fn fleet(text: &str) -> Fleet {
    crate::config::parse(text).expect("the contract loads")
}

/// A `deployed` map naming `envs` at `HEAD`, in the shape the caller passes.
fn deployed(envs: &[&str]) -> BTreeMap<String, Option<String>> {
    envs.iter()
        .map(|e| ((*e).to_string(), Some("HEAD".to_string())))
        .collect()
}

/// A synthetic halt, to make a run stop part-way in a test.
fn stopped() -> Error {
    Cause::NeedsUndeclared {
        names: vec!["STOP".into()],
        product: None,
    }
    .into()
}

/// Retire with a step recorder, returning the report and the steps recorded so far.
fn run(
    fleet: &Fleet,
    dir: &Path,
    deployed: &BTreeMap<String, Option<String>>,
) -> (Result<RetireReport, Error>, Vec<RetireStep>) {
    let mut steps = Vec::new();
    let mut out = Vec::new();
    let result = retire(
        fleet,
        &runner(),
        dir,
        "app",
        "API_KEY",
        deployed,
        &mut |step| {
            steps.push(step);
            Ok(())
        },
        &mut out,
    );
    (result, steps)
}

// --- the deployed-revision gate ------------------------------------------------------------

#[test]
fn a_key_still_read_at_the_deployed_revision_refuses_with_the_dedicated_code() {
    let dir = repo();
    write(
        dir.path(),
        "src/lib.rs",
        "fn read() { let _ = std::env::var(\"API_KEY\"); }\n",
    );
    commit(dir.path(), "src/lib.rs");
    let (result, _) = run(&fleet(TWO_ENVS), dir.path(), &deployed(&["dev"]));
    assert_eq!(result.unwrap_err().code_str(), "retire_still_read");
}

#[test]
fn a_still_read_key_names_the_file_that_reads_it() {
    let dir = repo();
    write(
        dir.path(),
        "src/lib.rs",
        "fn read() { let _ = std::env::var(\"API_KEY\"); }\n",
    );
    commit(dir.path(), "src/lib.rs");
    let (result, _) = run(&fleet(TWO_ENVS), dir.path(), &deployed(&["dev"]));
    assert!(result.unwrap_err().mentions("src/lib.rs:1"));
}

#[test]
fn a_missing_deployed_receipt_refuses_with_the_same_code() {
    let dir = repo();
    write(dir.path(), "src/lib.rs", "fn main() {}\n");
    commit(dir.path(), "src/lib.rs");
    let no_receipt = BTreeMap::from([("dev".to_string(), None)]);
    let (result, _) = run(&fleet(TWO_ENVS), dir.path(), &no_receipt);
    assert_eq!(result.unwrap_err().code_str(), "retire_still_read");
}

#[test]
fn a_key_read_only_in_the_working_tree_proceeds() {
    let dir = repo();
    write(dir.path(), "src/lib.rs", "fn main() {}\n");
    commit(dir.path(), "src/lib.rs");
    write(
        dir.path(),
        "src/lib.rs",
        "fn read() { let _ = std::env::var(\"API_KEY\"); }\n",
    );
    let (result, _) = run(&fleet(TWO_ENVS), dir.path(), &deployed(&["dev"]));
    assert!(result.is_ok());
}

// --- the step order ------------------------------------------------------------------------

#[test]
fn shared_tiers_are_pruned_before_production() {
    let dir = repo();
    write(dir.path(), "src/lib.rs", "fn main() {}\n");
    commit(dir.path(), "src/lib.rs");
    let (result, _) = run(&fleet(TWO_ENVS), dir.path(), &deployed(&["prod", "dev"]));
    assert_eq!(
        result.unwrap().pruned,
        vec!["dev".to_string(), "prod".to_string()]
    );
}

#[test]
fn the_last_step_marks_the_key_retired() {
    let dir = repo();
    write(dir.path(), "src/lib.rs", "fn main() {}\n");
    commit(dir.path(), "src/lib.rs");
    let (_, steps) = run(&fleet(TWO_ENVS), dir.path(), &deployed(&["dev"]));
    assert_eq!(steps.last(), Some(&RetireStep::MarkRetired));
}

// --- resumability --------------------------------------------------------------------------

#[test]
fn a_re_run_after_a_partial_run_prunes_only_the_rest() {
    let dir = repo();
    write(dir.path(), "src/lib.rs", "fn main() {}\n");
    commit(dir.path(), "src/lib.rs");
    let both = deployed(&["dev", "prod"]);
    let mut out = Vec::new();
    // The first run prunes `dev`, then stops before pruning `prod`.
    let _ = retire(
        &fleet(TWO_ENVS),
        &runner(),
        dir.path(),
        "app",
        "API_KEY",
        &both,
        &mut |step| match step {
            RetireStep::Prune { ref env } if env == "prod" => Err(stopped()),
            _ => Ok(()),
        },
        &mut out,
    );
    // The caller's plan no longer holds the key in `dev`, so it retries with `prod` only.
    let rest = BTreeMap::from([("prod".to_string(), Some("HEAD".to_string()))]);
    let (second, _) = run(&fleet(TWO_ENVS), dir.path(), &rest);
    assert_eq!(second.unwrap().pruned, vec!["prod".to_string()]);
}

// --- the retiring prune guard ---------------------------------------------------------------

#[test]
fn the_prune_step_releases_a_retiring_key() {
    let step = RetireStep::Prune {
        env: "dev".to_string(),
    };
    assert!(step.retiring_prune());
}

// --- the prune step: `opv sync <env> --prune --retire` (#179) -----------------------------
//
// Through the real sync path on the fixture's Fly targets, against a [`FakeRunner`] that
// answers each call in order: no terminal, no person, exactly as a CI job runs it.

mod prune_step {
    use super::super::*;
    use crate::app::ready::{EnvInput, TargetInput};
    use crate::app::sync::SyncOpts;
    use crate::app::testutil::*;
    use crate::domain::{KeyState, Kind, Row, TargetState};
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    /// The retiring key's managed name on both Fly targets.
    const OLD_FLY: &str = "FLEET__ALLUMATA__OLD_KEY";

    /// `OLD_KEY`, retiring, present in staging (shared) and prod (production).
    const RETIRING: &str = "[products.allumata.keys.OLD_KEY]\n\
        kind = \"secret\"\n\
        environments = [\"staging\", \"prod\"]\n\
        lifecycle = \"retiring\"\n";

    fn retiring() -> Fleet {
        fleet_with(RETIRING)
    }

    /// [`retiring`] with `confirm_env = true` on prod.
    fn guarded() -> Fleet {
        let text = crate::config::merged_text("tests/fixtures/secrets.toml");
        crate::config::parse(&format!(
            "{}\n{RETIRING}",
            text.replace(
                "modes.allumata.payments = \"off\"",
                "modes.allumata.payments = \"off\"\nconfirm_env = true",
            )
        ))
        .unwrap()
    }

    fn item_with_old() -> Output {
        let mut fs = complete_fields();
        fs.push(secret("allumata", "OLD_KEY", "old-FIXTUREVALUE"));
        // Staging's payments mode is `test`, so it needs a test key too.
        fs.push(secret(
            "allumata",
            "STRIPE_SECRET_KEY",
            "sk_test_FIXTUREVALUE",
        ));
        item(&fs)
    }

    /// A Fly listing of prod's names, with the retiring one when `old`.
    fn prod_list(old: bool) -> Output {
        let mut names = vec![(OPENAI_FLY, "d1"), (ENC_FLY, "d2")];
        if old {
            names.push((OLD_FLY, "d9"));
        }
        fly(&names)
    }

    /// A sync of prod after `before` (the reads the tier order makes first): item, list A,
    /// the two preflight reads, import, list B, then spare answers for the delivery
    /// recording and the unset.
    fn prod_run(before: Vec<Output>) -> FakeRunner {
        let [st, rel] = fly_preflight_ok();
        let mut answers = before;
        answers.extend([
            item_with_old(),
            prod_list(true),
            st,
            rel,
            ok(),
            prod_list(true),
            ok(),
            ok(),
            ok(),
            ok(),
        ]);
        FakeRunner::new(answers)
    }

    fn retire_opts() -> SyncOpts {
        SyncOpts {
            prune: true,
            retire: true,
            ..SyncOpts::default()
        }
    }

    /// The code reads nothing at the scanned revision.
    fn unread() -> Readers {
        Readers::of(BTreeMap::new())
    }

    /// The code still reads `OLD_KEY` at `src/app.rs:3`.
    fn still_read() -> Readers {
        Readers::of(BTreeMap::from([(
            "OLD_KEY".to_string(),
            vec!["src/app.rs:3".to_string()],
        )]))
    }

    fn run_on(
        fleet: &Fleet,
        env: &str,
        r: &FakeRunner,
        opts: &SyncOpts,
        readers: &Readers,
    ) -> Result<(), Error> {
        prune(fleet, env, r, &mut Vec::new(), opts, readers)
    }

    /// True when a call unset the retiring key's name on the target.
    fn unset_old(r: &FakeRunner) -> bool {
        r.calls.borrow().iter().any(|c| {
            c.program == "flyctl"
                && c.args.iter().any(|a| a == "unset")
                && c.args.iter().any(|a| a == OLD_FLY)
        })
    }

    // The needs check.

    #[test]
    fn a_retiring_key_the_code_still_reads_refuses_with_the_dedicated_code() {
        let r = FakeRunner::new([]);
        let e = run_on(&retiring(), "staging", &r, &retire_opts(), &still_read()).unwrap_err();
        assert_eq!(e.code_str(), "retire_still_read");
    }

    #[test]
    fn a_retiring_key_the_code_still_reads_names_the_file() {
        let r = FakeRunner::new([]);
        let e = run_on(&retiring(), "staging", &r, &retire_opts(), &still_read()).unwrap_err();
        assert!(e.mentions("src/app.rs:3"));
    }

    #[test]
    fn a_still_read_refusal_calls_nothing() {
        let r = FakeRunner::new([]);
        let _ = run_on(&retiring(), "staging", &r, &retire_opts(), &still_read());
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn a_revision_that_cannot_be_scanned_refuses_like_a_key_still_read() {
        let r = FakeRunner::new([]);
        let none = Readers { files: None };
        let e = run_on(&retiring(), "staging", &r, &retire_opts(), &none).unwrap_err();
        assert_eq!(e.code_str(), "retire_still_read");
    }

    // The flags.

    #[test]
    fn retire_without_prune_is_a_usage_error_naming_prune() {
        let r = FakeRunner::new([]);
        let opts = SyncOpts {
            retire: true,
            ..SyncOpts::default()
        };
        let e = run_on(&retiring(), "staging", &r, &opts, &unread()).unwrap_err();
        assert!(matches!(
            e.parts().0,
            Cause::Usage {
                problem: UsageProblem::NeedsFlag { .. }
            }
        ));
    }

    #[test]
    fn retire_with_an_expected_plan_is_refused() {
        let r = FakeRunner::new([]);
        let opts = SyncOpts {
            expect_plan: Some("abc".into()),
            ..retire_opts()
        };
        let e = run_on(&retiring(), "staging", &r, &opts, &unread()).unwrap_err();
        assert!(matches!(
            e.parts().0,
            Cause::Usage {
                problem: UsageProblem::ConflictsWith { .. }
            }
        ));
    }

    // The tier order.

    #[test]
    fn production_refuses_while_a_shared_environment_still_holds_the_key() {
        let r = prod_run(vec![fly(&[(OLD_FLY, "d9")])]);
        let e = run_on(&retiring(), "prod", &r, &retire_opts(), &unread()).unwrap_err();
        assert!(matches!(
            e.parts().0,
            Cause::Guard {
                guard: Guard::RetireOutOfOrder { .. }
            }
        ));
    }

    #[test]
    fn an_out_of_order_refusal_prunes_nothing() {
        let r = prod_run(vec![fly(&[(OLD_FLY, "d9")])]);
        let _ = run_on(&retiring(), "prod", &r, &retire_opts(), &unread());
        assert!(!unset_old(&r));
    }

    #[test]
    fn an_out_of_order_refusal_names_the_environment_to_prune_first() {
        let r = prod_run(vec![fly(&[(OLD_FLY, "d9")])]);
        let e = run_on(&retiring(), "prod", &r, &retire_opts(), &unread()).unwrap_err();
        assert!(e.mentions("opv sync staging --prune --retire"));
    }

    #[test]
    fn production_is_pruned_once_no_shared_environment_holds_the_key() {
        let r = prod_run(vec![fly_empty()]);
        run_on(&retiring(), "prod", &r, &retire_opts(), &unread()).unwrap();
        assert!(unset_old(&r));
    }

    #[test]
    fn a_shared_environment_is_pruned_without_reading_any_other() {
        let [st, rel] = fly_preflight_ok();
        let staging_list = || fly(&[(ENC_FLY, "d2"), (STRIPE_FLY, "d3"), (OLD_FLY, "d9")]);
        let r = FakeRunner::new([
            item_with_old(),
            staging_list(),
            st,
            rel,
            ok(),
            staging_list(),
            ok(),
            ok(),
            ok(),
            ok(),
        ]);
        run_on(&retiring(), "staging", &r, &retire_opts(), &unread()).unwrap();
        assert!(unset_old(&r));
    }

    // confirm_env.

    #[test]
    fn a_guarded_environment_refuses_without_its_confirmation() {
        let r = prod_run(vec![fly_empty()]);
        let e = run_on(&guarded(), "prod", &r, &retire_opts(), &unread()).unwrap_err();
        assert_eq!(e.code_str(), "confirm_required");
    }

    #[test]
    fn a_guarded_refusal_prunes_nothing() {
        let r = prod_run(vec![fly_empty()]);
        let _ = run_on(&guarded(), "prod", &r, &retire_opts(), &unread());
        assert!(!unset_old(&r));
    }

    #[test]
    fn a_guarded_environment_is_pruned_with_its_confirmation() {
        let r = prod_run(vec![fly_empty()]);
        let opts = SyncOpts {
            confirm: Some("prod".into()),
            ..retire_opts()
        };
        run_on(&guarded(), "prod", &r, &opts, &unread()).unwrap();
        assert!(unset_old(&r));
    }

    // Resuming.

    #[test]
    fn a_re_run_on_an_environment_already_pruned_unsets_nothing() {
        let [st, rel] = fly_preflight_ok();
        let pruned = || fly(&[(ENC_FLY, "d2"), (STRIPE_FLY, "d3")]);
        let r = FakeRunner::new([
            item_with_old(),
            pruned(),
            st,
            rel,
            ok(),
            pruned(),
            ok(),
            ok(),
            ok(),
        ]);
        run_on(&retiring(), "staging", &r, &retire_opts(), &unread()).unwrap();
        assert!(!r.argv_contains("unset"));
    }

    #[test]
    fn a_plain_sync_after_the_prune_does_not_put_the_key_back() {
        let [st, rel] = fly_preflight_ok();
        let pruned = || fly(&[(ENC_FLY, "d2"), (STRIPE_FLY, "d3")]);
        let r = FakeRunner::new([
            item_with_old(),
            pruned(),
            st,
            rel,
            ok(),
            pruned(),
            ok(),
            ok(),
            ok(),
        ]);
        crate::app::sync::run(
            &retiring(),
            "staging",
            &r,
            &mut Vec::new(),
            &SyncOpts::default(),
        )
        .unwrap();
        assert!(!import_stdin(&r).unwrap_or_default().contains(OLD_FLY));
    }

    // Who runs it.

    #[test]
    fn the_prune_step_runs_without_a_terminal_as_ci_does() {
        let r = prod_run(vec![fly_empty()]);
        let result = run_on(&retiring(), "prod", &r, &retire_opts(), &unread());
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn the_prune_step_never_writes_1password() {
        let r = prod_run(vec![fly_empty()]);
        run_on(&retiring(), "prod", &r, &retire_opts(), &unread()).unwrap();
        let writes = r.calls.borrow().iter().any(|c| {
            c.program == "op"
                && c.args
                    .iter()
                    .any(|a| matches!(a.as_str(), "edit" | "create" | "delete" | "archive"))
        });
        assert!(!writes, "{:?}", argvs(&r));
    }

    // `ready`.

    fn row(key: &str, target: TargetState) -> Row {
        Row {
            product: "allumata".into(),
            key: key.into(),
            kind: Kind::Secret,
            state: KeyState::Ready,
            target,
            guidance: String::new(),
            source: None,
            shared_by: Vec::new(),
        }
    }

    fn env_holding(name: &str, held: bool) -> EnvInput {
        // Fly shows no digest opv can compare, so a held name is `unknown`.
        let state = if held {
            TargetState::Unknown
        } else {
            TargetState::Absent
        };
        EnvInput {
            name: name.into(),
            target: Some(vec![TargetInput {
                name: "portfolio".into(),
                provider: "Fly".into(),
                locator: "app".into(),
                grants_missing: None,
                rows: Ok(vec![row("OLD_KEY", state)]),
            }]),
            rows: Ok(Vec::new()),
            title: None,
            audience: None,
            personal_item: Default::default(),
        }
    }

    #[test]
    fn ready_lists_an_unfinished_retirement() {
        let envs = [env_holding("staging", false), env_holding("prod", true)];
        let codes: Vec<String> = findings(&retiring(), &envs)
            .into_iter()
            .map(|f| f.code)
            .collect();
        assert_eq!(codes, vec!["retirement_incomplete".to_string()]);
    }

    #[test]
    fn an_unfinished_retirement_names_the_environments_left_in_tier_order() {
        let envs = [env_holding("prod", true), env_holding("staging", true)];
        let f = findings(&retiring(), &envs).remove(0);
        let message = f.message.unwrap_or_default();
        let (staging, prod) = (message.find("from staging"), message.find("from prod"));
        assert!(staging.is_some() && staging < prod, "{message}");
    }

    #[test]
    fn an_unfinished_retirement_s_first_step_is_the_ci_prune() {
        let envs = [env_holding("staging", false), env_holding("prod", true)];
        let f = findings(&retiring(), &envs).remove(0);
        assert_eq!(f.prerequisite, "opv sync prod --prune --retire");
    }

    #[test]
    fn a_retirement_pruned_everywhere_is_left_to_a_person() {
        let envs = [env_holding("staging", false), env_holding("prod", false)];
        let f = findings(&retiring(), &envs).remove(0);
        assert_eq!(f.actor, "owner");
    }

    #[test]
    fn an_unfinished_retirement_never_blocks() {
        let envs = [env_holding("prod", true)];
        let f = findings(&retiring(), &envs).remove(0);
        assert!(!f.blocking);
    }

    #[test]
    fn a_retirement_pruned_everywhere_names_the_apply_of_its_plan() {
        let envs = [env_holding("staging", false), env_holding("prod", false)];
        let f = findings(&retiring(), &envs).remove(0);
        assert_eq!(
            f.prerequisite,
            format!(
                "opv apply {}",
                archive_plan(&retiring(), "allumata", "OLD_KEY").plan_id
            )
        );
    }

    #[test]
    fn a_retired_key_has_no_unfinished_retirement() {
        let retired = fleet_with(&RETIRING.replace("\"retiring\"", "\"retired\""));
        let envs = [env_holding("staging", false), env_holding("prod", false)];
        assert!(findings(&retired, &envs).is_empty());
    }

    #[test]
    fn a_retirement_plan_id_changes_with_the_items_it_edits() {
        let mut moved = retiring();
        moved
            .environments
            .get_mut("prod")
            .unwrap()
            .boundaries
            .values_mut()
            .flatten()
            .for_each(|b| b.item_id = "another".into());
        assert_ne!(
            archive_plan(&moved, "allumata", "OLD_KEY").plan_id,
            archive_plan(&retiring(), "allumata", "OLD_KEY").plan_id
        );
    }
}
