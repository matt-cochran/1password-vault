//! `run <env> --product <p> -- <cmd>` use case, delegating to `op run` (FR-4, §10.4).
//!
//! opv reads the item once (FR-43: to tidy it for a person, or to find misplaced fields)
//! and gives `op run` a child environment of `op://` references
//! (`KEY=op://<vault_id>/<item_id>/<product>/<KEY>`, or `.../<field id>` for a field not yet
//! where the convention puts it); `op run` resolves them and execs the command, so `op run`
//! keeps masking the values in the child's output. Every key is a reference, always: when a
//! read-only identity (service account, CI) reads a value a person's tidy would normalize
//! (trailing newline or space, missing `ensure_prefix`), the child gets the stored value
//! through its reference and opv prints one warning per such key naming the fix (`opv
//! login <env>`, after which a run tidies it). No value passes through opv, argv or files
//! (SR-1, SR-3, SR-4).

use std::io;

use super::local_delivery::{OUTER_VAR, Outer};
use super::personal;
use crate::cause::{
    Cause, Closest, EnvName, Guard, IoKind, NameKind, ProfileName, Unusable, UsageProblem,
};
use crate::domain::{Fleet, KeySpec};
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

const OP: &str = "op";

/// 0.9.0: running an app with the secrets of an environment that sets `confirm_env`
/// (production, typically) needs the environment's name again, as `sync` does: one
/// deliberate step before its values reach a local process. Checked before anything is
/// read. `--preview` reads no value and needs none. The step is the person's own run with
/// `--confirm <env>`, built from the invocation by the cause (a person's handoff); the
/// caller's `_retry` text is no longer shown.
pub fn require_confirmation(
    fleet: &Fleet,
    env_name: &str,
    confirm: Option<&str>,
    _retry: &str,
) -> Result<(), Error> {
    let env = fleet.environment(env_name)?;
    match confirm {
        Some(c) if c != env_name => Err(Cause::ConfirmMismatch {
            given: c.to_string(),
            env: EnvName::new(env_name),
        }
        .into()),
        None if env.confirm_env => Err(Cause::NeedsConfirm {
            env: EnvName::new(env_name),
        }
        .into()),
        _ => Ok(()),
    }
}

/// `run <env> --product <p> -- <cmd>`: without `--product`, the one product with keys
/// desired in `env_name` is used (D10/FR-34); a named product is validated by [`run`].
pub fn run_for(
    fleet: &Fleet,
    env_name: &str,
    product: Option<&str>,
    role: Option<&str>,
    command: &[String],
    runner: &dyn CommandRunner,
) -> Result<i32, Error> {
    let product = match product {
        Some(p) => p.to_string(),
        None => super::pick_product(fleet, env_name, None)?,
    };
    run_with_role(fleet, env_name, &product, role, command, runner)
}

/// Run `command` under `op run` with the product's references for `env_name` in its
/// environment. Returns the child's exit code, which `main` uses as the process exit code.
///
/// Keys passed: every key of `product` declared for `env_name` whose rules apply
/// ([`crate::domain::rules::applies`]). Keys skipped by a mode (e.g. `payments = "off"`) are left out,
/// because their field may be empty and `op run` fails on an empty reference.
pub fn run(
    fleet: &Fleet,
    env_name: &str,
    product: &str,
    command: &[String],
    runner: &dyn CommandRunner,
) -> Result<i32, Error> {
    run_with_role(fleet, env_name, product, None, command, runner)
}

/// [`run`] with `--role` (#136): the keys are selected once, by
/// [`crate::app::delivery_preview::select`],
/// so a role withheld key is neither referenced on `op run`'s command line nor written by
/// the local delivery step nor put in the child environment.
pub fn run_with_role(
    fleet: &Fleet,
    env_name: &str,
    product: &str,
    role: Option<&str>,
    command: &[String],
    runner: &dyn CommandRunner,
) -> Result<i32, Error> {
    launch(
        fleet,
        env_name,
        product,
        role,
        Launch::Local(command),
        runner,
    )
}

/// `opv run <env> --product <p> [--role <r>] --remote <profile>` (#139): the same selection
/// and references as a local run, delivered by `op run`'s child `opv remote-send` to the
/// profile's pinned host, where the pinned command runs. The profile, its environments and
/// its roles are checked before anything is read.
pub fn run_remote(
    fleet: &Fleet,
    env_name: &str,
    product: Option<&str>,
    role: Option<&str>,
    remote: &str,
    runner: &dyn CommandRunner,
) -> Result<i32, Error> {
    let product = match product {
        Some(p) => p.to_string(),
        None => super::pick_product(fleet, env_name, None)?,
    };
    launch(
        fleet,
        env_name,
        &product,
        role,
        Launch::Remote(remote),
        runner,
    )
}

/// 09.42: the product and remote profile a `run --remote` names, checked before anything
/// asks for a terminal (no 1Password call).
pub fn check_remote(
    fleet: &Fleet,
    env_name: &str,
    product: Option<&str>,
    role: Option<&str>,
    remote: &str,
) -> Result<(), Error> {
    let product = match product {
        Some(p) => p.to_string(),
        None => super::pick_product(fleet, env_name, None)?,
    };
    remote_profile(fleet, env_name, &product, role, remote).map(|_| ())
}

/// Where a run's values go: a local command, or a reviewed remote profile (#139).
#[derive(Clone, Copy)]
enum Launch<'a> {
    Local(&'a [String]),
    Remote(&'a str),
}

/// The profile `name` of `product`, if it may receive `env_name`'s values for `role` (#139).
/// Checked before any 1Password read; every refusal says nothing was read.
pub fn remote_profile<'a>(
    fleet: &'a Fleet,
    env_name: &str,
    product: &str,
    role: Option<&str>,
    name: &str,
) -> Result<&'a crate::domain::model::Remote, Error> {
    let prod = fleet
        .products
        .get(product)
        .ok_or_else(|| super::undefined_product(fleet, product, Some(env_name)))?;
    let Some(r) = prod.remotes.get(name) else {
        let known: Vec<&str> = prod.remotes.keys().map(String::as_str).collect();
        return Err(Cause::NotDeclared {
            kind: NameKind::RemoteProfile,
            given: name.to_string(),
            candidates: known.iter().map(|k| k.to_string()).collect(),
            closest: Closest::unique(&super::suggest::close(name, known.iter().copied())),
        }
        .into());
    };
    // 07.20: the refusal names what the profile allows; its step never repeats the run.
    let refuses = |asked: String, allowed: &[String]| -> Error {
        Cause::Guard {
            guard: Guard::RemoteProfileRefuses {
                profile: ProfileName::new(name),
                asked,
                allowed: allowed.to_vec(),
            },
        }
        .into()
    };
    if !r.environments.iter().any(|e| e == env_name) {
        return Err(refuses(format!("environment {env_name}"), &r.environments));
    }
    if let (Some(allowed), Some(role)) = (&r.roles, role)
        && !allowed.iter().any(|x| x == role)
    {
        return Err(refuses(format!("role {role}"), allowed));
    }
    Ok(r)
}

fn launch(
    fleet: &Fleet,
    env_name: &str,
    product: &str,
    role: Option<&str>,
    to: Launch<'_>,
    runner: &dyn CommandRunner,
) -> Result<i32, Error> {
    let env = fleet.environment(env_name)?;
    let prod = fleet
        .products
        .get(product)
        .ok_or_else(|| super::undefined_product(fleet, product, Some(env_name)))?;
    if prod.source_only {
        return Err(super::source_only(fleet, product, Some(env_name)));
    }
    let remote = match to {
        Launch::Local([]) => {
            return Err(Cause::Usage {
                problem: UsageProblem::NeedsFlag {
                    flag: "run".into(),
                    needs: "a command after --".into(),
                },
            }
            .into());
        }
        Launch::Local(_) => None,
        Launch::Remote(name) => Some((name, remote_profile(fleet, env_name, product, role, name)?)),
    };

    let selection = super::delivery_preview::select(env_name, env, product, prod, role)?;
    let selected: Vec<(&String, &KeySpec)> = selection.delivered;
    // FR-55: a personal key's value is in the person's own item. Locate it before the read
    // and before `op run`, so a missing personal item stops the run and names the keys.
    let personal_env = if selected
        .iter()
        .any(|(_, spec)| personal::is_personal(fleet, spec))
    {
        let project = personal::project_name(runner, &std::env::current_dir().unwrap_or_default());
        match personal::locate(runner, fleet, env_name, &project) {
            Ok(Some(e)) => Some(e),
            // A missing personal vault or item is personal's own cause (its step sets it
            // up), naming the personal keys this run needs (J6); a sign-in, network or op
            // failure is its own cause.
            Err(e) => {
                let keys: Vec<(&str, &str)> = selected
                    .iter()
                    .filter(|(_, spec)| personal::is_personal(fleet, spec))
                    .map(|(key, _)| (product, key.as_str()))
                    .collect();
                return Err(personal::naming_keys(e, env_name, &keys));
            }
            // `locate` answers `None` only when the environment declares no personal key,
            // and a personal key was just selected for it.
            Ok(None) => {
                return Err(Cause::Bug {
                    site: "run: a selected personal key whose environment declares none",
                }
                .into());
            }
        }
    } else {
        None
    };

    // FR-43: one tolerant item read first, which tidies the item when a person runs opv.
    // A key whose field is still not where the convention puts it (a read-only run) is
    // referenced by field id. If the read fails, `op run` reports the problem itself.
    let read = super::tidy::active()
        .then(|| super::tidy::read(fleet, env_name, runner).ok())
        .flatten();
    let by_id = read.as_ref().map(|r| &r.refs);
    let normalized = read.as_ref().map(|r| &r.normalized);
    let who = read.as_ref().and_then(|r| r.identity);
    // Found live: an empty key reached the app as "" with no word. A tidy that wrote
    // already named these keys.
    if let Some(r) = read.as_ref().filter(|r| r.changes.is_empty()) {
        super::tidy::note_needing_values(runner, env_name, &r.needing_values);
    }
    let refs: Vec<(&str, String)> = selected
        .iter()
        .map(|(key, spec)| -> Result<(&str, String), Error> {
            // FR-55: a personal key references the person's own item, never the team item.
            if personal::is_personal(fleet, spec) {
                let pe = personal_env.as_ref().expect("located above");
                return Ok((key.as_str(), personal::reference(pe, product, key, spec)));
            }
            // A shared key (FR-45) is exported under its own name, referencing its source's
            // field in the source's boundary item (FR-57).
            let (fp, fk) = spec.source().unwrap_or((product, key));
            let field = format!("{fp}/{fk}");
            let b = fleet.boundary(env_name, fp)?;
            // The field's key: the source's for a shared key (FR-45).
            let id = (fp.to_string(), fk.to_string());
            // Read-only and not yet normalized in 1Password (FR-43): still the reference, so
            // `op run` masks the value; the person who can tidy it is told how.
            if normalized.is_some_and(|m| m.contains_key(&id)) {
                let name = crate::domain::key_label(fp, fk);
                // M4: worded by why it is not tidied; a person whose own tidy did not
                // complete is not told to sign in as themselves.
                let how = match who {
                    Some(super::tidy::Identity::Person) => {
                        "opv could not tidy it in this run (see the note above)".to_string()
                    }
                    Some(super::tidy::Identity::DeployCredentials) => format!(
                        "run opv check {env_name} (without deploy credentials) and opv will tidy it"
                    ),
                    Some(_) => {
                        format!("run as yourself (opv login {env_name}) and opv will tidy it")
                    }
                    None => "opv does not tidy this item (see the note above)".to_string(),
                };
                runner.note(&format!(
                    "{name} has a fixable formatting problem in 1Password; {how}"
                ));
            }
            let reference = by_id
                .and_then(|m| m.get(&id))
                .cloned()
                .unwrap_or_else(|| format!("op://{}/{}/{field}", b.vault_id, b.item_id));
            Ok((key.as_str(), reference))
        })
        .collect::<Result<_, Error>>()?;
    let mut env_pairs: Vec<(&str, &str)> = refs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    // X25: the delivery step's errors name this run, never the hidden step.
    let outer = Outer::new(
        env_name,
        product,
        remote.map(|(name, _)| name),
        &crate::error::invocation(),
    );

    // #136, #137: a product with `[products.<p>.local]` runs its app through opv's local
    // delivery step, as `op run`'s child: it keeps only what the product declares and
    // writes `file` keys to a private RAM directory (names and paths only in argv).
    let delivery = match (remote, &to) {
        // #139: the remote step carries the profile and the names; the command is pinned.
        (Some((name, r)), _) => Some(remote_args(name, r, prod, &selected, &outer)?),
        (None, _) => prod
            .local
            .as_ref()
            .map(|l| delivery_args(l, &selected))
            .transpose()?,
    };
    let outer_json = serde_json::to_string(&outer).map_err(|_| -> Error {
        Cause::Bug {
            site: "run: the delivery step's run",
        }
        .into()
    })?;
    if remote.is_none() && delivery.is_some() && outer.is_valid() {
        env_pairs.push((OUTER_VAR, outer_json.as_str()));
    }
    let mut args: Vec<&str> = vec!["run", "--"];
    if let Some(d) = &delivery {
        args.extend(d.iter().map(String::as_str));
    }
    if let Launch::Local(command) = to {
        args.extend(command.iter().map(String::as_str));
    }

    // Clear all declared keys, including other products and mode-skipped keys.
    // Keep PATH and authentication context; add only selected references afterward.
    let remove: Vec<String> = fleet
        .products
        .values()
        .flat_map(|p| p.keys.keys().cloned())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    ensure_native(runner)?;
    runner
        .run_inherited_clean(OP, &args, &env_pairs, &remove)
        .map_err(|e| op_unusable(e.kind()))
}

/// `op` could not be started for the run.
fn op_unusable(kind: io::ErrorKind) -> Error {
    if kind == io::ErrorKind::NotFound {
        let host = Host::detect();
        Cause::ToolMissing {
            tool: OP.into(),
            platform: host.platform,
            shell: host.shell,
            ci: host.ci,
        }
        .into()
    } else {
        Cause::ToolUnusable {
            tool: OP.into(),
            why: Unusable::SpawnFailed {
                io: IoKind::from(kind),
            },
        }
        .into()
    }
}

/// This opv binary, which `op run` starts as the delivery step.
fn own_binary() -> Result<String, Error> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .ok_or_else(|| {
            Cause::Bug {
                site: "run: locating this opv binary",
            }
            .into()
        })
}

/// `opv remote-send --plan <json>` (#139): this opv binary and the plan (the profile's
/// pinned connection, key names, file paths, directory variable, working directory and
/// command). Names, paths and a public key only, never a value.
fn remote_args(
    name: &str,
    remote: &crate::domain::model::Remote,
    prod: &crate::domain::Product,
    selected: &[(&String, &KeySpec)],
    outer: &Outer,
) -> Result<Vec<String>, Error> {
    let exe = own_binary()?;
    let keys = selected.iter().map(|(k, _)| (*k).clone()).collect();
    let files = selected
        .iter()
        .filter_map(|(k, spec)| spec.file.as_ref().map(|f| ((*k).clone(), f.clone())))
        .collect();
    let dir_env = prod.local.as_ref().and_then(|l| l.secrets_dir_env.clone());
    let plan =
        super::remote_delivery::Plan::new(name, remote, keys, files, dir_env, Some(outer.clone()));
    let json = serde_json::to_string(&plan).map_err(|_| -> Error {
        Cause::Bug {
            site: "run: the remote plan",
        }
        .into()
    })?;
    Ok(vec![
        exe,
        "remote-send".to_string(),
        "--plan".to_string(),
        json,
    ])
}

/// The local delivery step's command line before the app's (#136, #137): this opv binary,
/// `local-delivery`, the selected key names, the environment mode, the directory variable
/// and each file key's path, then `--`. Names and paths only, never a value.
fn delivery_args(
    local: &crate::domain::model::Local,
    selected: &[(&String, &KeySpec)],
) -> Result<Vec<String>, Error> {
    let exe = own_binary()?;
    let mut a = vec![exe, "local-delivery".to_string()];
    for (key, spec) in selected {
        a.extend(["--key".to_string(), (*key).clone()]);
        if let Some(path) = &spec.file {
            a.extend(["--file".to_string(), format!("{key}={path}")]);
        }
    }
    if local.environment == crate::domain::model::LocalEnvironment::DeclaredOnly {
        a.push("--declared-only".to_string());
    }
    if let Some(v) = &local.secrets_dir_env {
        a.extend(["--dir-env".to_string(), v.clone()]);
    }
    a.push("--".to_string());
    Ok(a)
}

/// Windows op.exe can read metadata from WSL, but cannot execute a Linux child.
pub fn ensure_native(runner: &dyn CommandRunner) -> Result<(), Error> {
    runner.local_run_supported().map_err(|e| -> Error {
        let why = if e.kind() == io::ErrorKind::Unsupported {
            Unusable::WindowsExeFromWsl
        } else {
            Unusable::SpawnFailed {
                io: IoKind::from(e.kind()),
            }
        };
        Cause::ToolUnusable {
            tool: OP.into(),
            why,
        }
        .into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::testutil::*;
    use crate::runner::Output;
    use crate::runner::fake::FakeRunner;

    fn cmd(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    fn env_of(r: &FakeRunner) -> Vec<(String, String)> {
        r.calls.borrow()[0].env.clone()
    }

    #[test]
    fn spawns_one_op_run_call_with_the_command() {
        let r = FakeRunner::new([Output::success(Vec::new())]);
        let code = run(&fleet(), "staging", "allumata", &cmd(&["env", "-0"]), &r).unwrap();
        assert_eq!(code, 0);
        let calls = r.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "op");
        assert_eq!(calls[0].args, vec!["run", "--", "env", "-0"]);
        assert!(calls[0].inherited && calls[0].stdin.is_none());
    }

    /// #136, #137: the fixture's allumata delivers OPENAI_API_KEY as a file, declared-only.
    fn local_fleet() -> Fleet {
        let text = crate::config::merged_text("tests/fixtures/secrets.toml").replace(
            "guidance = \"OpenAI platform / API keys\"",
            "guidance = \"OpenAI platform / API keys\"\nfile = \"openai/api-key\"",
        );
        crate::config::parse(&format!(
            "{text}\n[products.allumata.local]\nenvironment = \"declared_only\"\nsecrets_dir_env = \"APP_SECRETS_DIR\"\n"
        ))
        .unwrap()
    }

    fn local_args() -> Vec<String> {
        let r = FakeRunner::new([Output::success(Vec::new())]);
        run(&local_fleet(), "prod", "allumata", &cmd(&["app"]), &r).unwrap();
        r.calls.borrow()[0].args.clone()
    }

    #[test]
    fn a_local_product_runs_through_the_delivery_step() {
        assert_eq!(local_args()[3], "local-delivery");
    }

    #[test]
    fn the_delivery_step_is_declared_only() {
        assert!(local_args().contains(&"--declared-only".to_string()));
    }

    #[test]
    fn the_delivery_step_gets_each_file_path() {
        assert!(local_args().contains(&"OPENAI_API_KEY=openai/api-key".to_string()));
    }

    #[test]
    fn the_delivery_step_ends_with_the_apps_command() {
        let a = local_args();
        assert_eq!(&a[a.len() - 2..], ["--", "app"]);
    }

    /// The person's run (names and flags, X25) is the one other variable the step gets.
    #[test]
    fn the_delivery_step_gets_references_never_values() {
        let r = FakeRunner::new([Output::success(Vec::new())]);
        run(&local_fleet(), "prod", "allumata", &cmd(&["app"]), &r).unwrap();
        assert!(
            env_of(&r)
                .iter()
                .filter(|(k, _)| k != OUTER_VAR)
                .all(|(_, v)| v.starts_with("op://"))
        );
    }

    #[test]
    fn a_product_without_local_runs_its_command_directly() {
        let r = FakeRunner::new([Output::success(Vec::new())]);
        run(&fleet(), "prod", "allumata", &cmd(&["app"]), &r).unwrap();
        assert_eq!(r.calls.borrow()[0].args, ["run", "--", "app"]);
    }

    #[test]
    fn env_holds_references_by_plain_key_name() {
        let r = FakeRunner::new([Output::success(Vec::new())]);
        run(&fleet(), "prod", "allumata", &cmd(&["env"]), &r).unwrap();
        let env = env_of(&r);
        assert!(env.contains(&(
            "OPENAI_API_KEY".to_string(),
            "op://vprd/iprd/allumata/OPENAI_API_KEY".to_string()
        )));
        assert!(env.contains(&(
            "SIGNUP_POLICY".to_string(),
            "op://vprd/iprd/allumata/SIGNUP_POLICY".to_string()
        )));
        assert!(
            env.iter()
                .all(|(k, v)| !k.starts_with("FLEET__") && v.starts_with("op://"))
        );
    }

    #[test]
    fn only_keys_declared_for_the_env_are_passed() {
        // OPENAI_API_KEY is declared for prod only.
        let r = FakeRunner::new([Output::success(Vec::new())]);
        run(&fleet(), "staging", "allumata", &cmd(&["env"]), &r).unwrap();
        let names: Vec<String> = env_of(&r).into_iter().map(|(k, _)| k).collect();
        assert!(!names.contains(&"OPENAI_API_KEY".to_string()), "{names:?}");
        assert!(names.contains(&"STRIPE_SECRET_KEY".to_string()));
        assert!(names.contains(&"INTEGRATION_ENC_KEY".to_string()));
    }

    #[test]
    fn mode_skipped_keys_are_left_out() {
        // prod has payments = "off", so STRIPE_SECRET_KEY may be empty and is not passed.
        let r = FakeRunner::new([Output::success(Vec::new())]);
        run(&fleet(), "prod", "allumata", &cmd(&["env"]), &r).unwrap();
        let names: Vec<String> = env_of(&r).into_iter().map(|(k, _)| k).collect();
        assert!(
            !names.contains(&"STRIPE_SECRET_KEY".to_string()),
            "{names:?}"
        );
    }

    #[test]
    fn no_value_reaches_argv_or_env() {
        let r = FakeRunner::new([Output::success(Vec::new())]);
        run(&fleet(), "prod", "allumata", &cmd(&["env"]), &r).unwrap();
        assert_no_values_in_argv(&r);
        let dbg = format!("{:?}", r.calls.borrow());
        assert_no_values(&dbg);
    }

    #[test]
    fn unknown_env_product_or_empty_command_make_no_call() {
        let cases: [(&str, &str, Vec<String>, &str); 3] = [
            ("nope", "allumata", cmd(&["env"]), "nope"),
            ("prod", "nope", cmd(&["env"]), "nope"),
            ("prod", "allumata", cmd(&[]), "command"),
        ];
        for (e, p, c, needle) in cases {
            let r = FakeRunner::new([]);
            // A configuration or name error (exit 2; an undeclared product is the catalog's
            // `NotDeclared`), naming what was wrong.
            match run(&fleet(), e, p, &c, &r) {
                Err(e) if e.exit_code() == 2 => assert!(e.to_string().contains(needle), "{e}"),
                other => panic!("expected a configuration error, got {other:?}"),
            }
            assert!(r.calls.borrow().is_empty());
        }
    }

    /// I5: `run` needs no Fly app (no more placeholder apps for local-only environments).
    #[test]
    fn works_without_fly_section() {
        let fl = fleet_with(
            "[environments.dev]\nboundaries.allumata = { vault_id = \"vdev\", item_id = \"idev\" }\n\
             [products.allumata.keys.DEV_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
        );
        let r = FakeRunner::new([Output::success(Vec::new())]);
        run(&fl, "dev", "allumata", &cmd(&["env"]), &r).unwrap();
        assert_eq!(
            env_of(&r),
            vec![(
                "DEV_KEY".to_string(),
                "op://vdev/idev/allumata/DEV_KEY".to_string()
            )]
        );
    }

    #[test]
    fn child_exit_code_is_passed_through() {
        let r = FakeRunner::new([Output::failure(7)]);
        assert_eq!(
            run(&fleet(), "prod", "allumata", &cmd(&["false"]), &r).unwrap(),
            7
        );
    }

    #[test]
    fn missing_op_is_a_dependency_error() {
        let r = FakeRunner::new([]);
        r.push_io_error(io::ErrorKind::NotFound);
        assert_eq!(
            run(&fleet(), "prod", "allumata", &cmd(&["env"]), &r)
                .unwrap_err()
                .code_str(),
            "dependency_missing"
        );
    }

    #[test]
    fn clears_mode_skipped_managed_keys() {
        let r = FakeRunner::new([Output::success(Vec::new())]);
        run(&fleet(), "prod", "allumata", &cmd(&["true"]), &r).unwrap();
        assert!(
            r.calls.borrow()[0]
                .removed
                .contains(&"STRIPE_SECRET_KEY".to_string())
        );
    }

    #[test]
    fn clears_another_products_managed_keys() {
        let f = fleet_with(
            "[products.other]\nboundary = \"allumata\"\n[products.other.keys.OTHER_KEY]\nkind = \"secret\"\nenvironments = [\"prod\"]\n",
        );
        let r = FakeRunner::new([Output::success(Vec::new())]);
        run(&f, "prod", "allumata", &cmd(&["true"]), &r).unwrap();
        assert!(
            r.calls.borrow()[0]
                .removed
                .contains(&"OTHER_KEY".to_string())
        );
    }

    #[test]
    fn incompatible_windows_cli_fails_before_child_launch() {
        let r = FakeRunner::new([]);
        *r.local_run_error.borrow_mut() = Some(io::ErrorKind::Unsupported);
        let result = run(&fleet(), "prod", "allumata", &cmd(&["true"]), &r);
        assert!(result.unwrap_err().to_string().contains("Windows build"));
        assert!(r.calls.borrow().is_empty());
    }

    /// `shared` is source-only and `api` reads it with `from` (FR-47).
    fn source_only_fleet() -> Fleet {
        crate::config::parse(
            r#"
[environments.ci]
boundaries.core = { vault_id = "vci", item_id = "ici" }
[environments.ci.targets.app]
fly.app = "app"
fly.secret_name = "FLEET__{PRODUCT}__{KEY}"
state_vault_id = "sci"
[products.shared]
source_only = true
boundary = "core"
[products.shared.keys.TOKEN]
kind = "secret"
environments = ["ci"]
[products.api]
boundary = "core"
[products.api.keys.TOKEN]
kind = "secret"
from = "shared/TOKEN"
environments = ["ci"]
"#,
        )
        .unwrap()
    }

    #[test]
    fn run_refuses_a_source_only_product() {
        let r = FakeRunner::new([]);
        let e = run(&source_only_fleet(), "ci", "shared", &cmd(&["env"]), &r).unwrap_err();
        assert_eq!(e.code_str(), "source_only");
    }

    #[test]
    fn run_without_product_uses_the_only_non_source_only_product() {
        let r = FakeRunner::new([Output::success(Vec::new())]);
        run_for(&source_only_fleet(), "ci", None, None, &cmd(&["env"]), &r).unwrap();
        assert_eq!(argvs(&r), vec!["op run -- env"]);
    }

    fn guarded() -> Fleet {
        crate::config::parse(
            r#"[environments.prod]
confirm_env = true
boundaries.api = { vault_id = "vprod", item_id = "iprod" }

[environments.dev]
boundaries.api = { vault_id = "vdev", item_id = "idev" }

[products.api.keys.TOKEN]
kind = "secret"
environments = ["prod", "dev"]
"#,
        )
        .unwrap()
    }

    #[test]
    fn a_guarded_environment_needs_its_name_again() {
        let e = require_confirmation(&guarded(), "prod", None, "retry").unwrap_err();
        assert_eq!(e.code_str(), "confirm_required");
    }

    #[test]
    fn a_guarded_environment_runs_when_confirmed() {
        assert!(require_confirmation(&guarded(), "prod", Some("prod"), "retry").is_ok());
    }

    #[test]
    fn a_confirmation_naming_another_environment_is_refused() {
        let e = require_confirmation(&guarded(), "prod", Some("dev"), "retry").unwrap_err();
        assert_eq!(e.code_str(), "confirm_mismatch");
    }

    #[test]
    fn an_unguarded_environment_needs_no_confirmation() {
        assert!(require_confirmation(&guarded(), "dev", None, "retry").is_ok());
    }

    /// 07.37: the step addresses the person, and an agent only in passing. Was a caller's
    /// retry string with the child's words; the catalog builds it from the invocation.
    #[test]
    fn the_refusal_asks_the_person_to_make_sure() {
        let e = require_confirmation(&guarded(), "prod", None, "retry").unwrap_err();
        let inv = crate::cause::Invocation::from_cli(&cmd(&["opv", "run", "prod"]));
        let text = match e.cause() {
            Some((c, _)) => crate::cause::render::render_text(c, None, &inv, false, false, false),
            None => String::new(),
        };
        assert!(
            text.contains("Do: make sure prod is the environment you mean"),
            "{text}"
        );
    }

    /// The local delivery step gets the person's run (X25).
    #[test]
    fn the_delivery_step_gets_the_persons_run() {
        let r = FakeRunner::new([Output::success(Vec::new())]);
        run(&local_fleet(), "prod", "allumata", &cmd(&["app"]), &r).unwrap();
        assert!(env_of(&r).iter().any(|(k, _)| k == OUTER_VAR));
    }
}
