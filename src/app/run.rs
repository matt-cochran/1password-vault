//! `run <env> --product <p> -- <cmd>` use case, delegating to `op run` (FR-4, §10.4).
//!
//! opv never hands values to the child. It reads the item once (FR-43: to tidy it for a
//! person, or to find misplaced fields) and gives `op run` a child environment of `op://`
//! references (`KEY=op://<vault_id>/<item_id>/<product>/<KEY>`, or `.../<field id>` for a
//! field not yet where the convention puts it); `op run` resolves them and execs the
//! command. No values pass through argv, the child's env or files (SR-1, SR-3, SR-4).

use std::io;

use crate::adapters::onepassword;
use crate::domain::{Fleet, SIMPLE_PRODUCT, rules};
use crate::error::Error;
use crate::host::Host;
use crate::runner::CommandRunner;

const OP: &str = "op";

/// `run <env> [--product <p>] -- <cmd>`: the fleet profile needs `--product`; the simple
/// profile (FR-20) takes none and passes every declared key, referenced as an unsectioned
/// field (`KEY=op://<vault_id>/<item_id>/<KEY>`). Both errors happen before any call.
pub fn run_for(
    fleet: &Fleet,
    env_name: &str,
    product: Option<&str>,
    command: &[String],
    runner: &dyn CommandRunner,
) -> Result<i32, Error> {
    match (fleet.is_simple(), product) {
        (false, Some(p)) => run(fleet, env_name, p, command, runner),
        (false, None) => Err(Error::Config(format!(
            "--product is required. Choose one of: {}. Usage: opv run {env_name} --product <name> -- <command>",
            fleet
                .products
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ).into())),
        (true, None) => run(fleet, env_name, SIMPLE_PRODUCT, command, runner),
        (true, Some(_)) => Err(Error::Config(
            "--product is not used under the simple profile (usage: run <env> -- <cmd>...)".into(),
        )),
    }
}

/// Run `command` under `op run` with the product's references for `env_name` in its
/// environment. Returns the child's exit code, which `main` uses as the process exit code.
///
/// Keys passed: every key of `product` declared for `env_name` whose rules apply
/// ([`rules::applies`]). Keys skipped by a mode (e.g. `payments = "off"`) are left out,
/// because their field may be empty and `op run` fails on an empty reference.
pub fn run(
    fleet: &Fleet,
    env_name: &str,
    product: &str,
    command: &[String],
    runner: &dyn CommandRunner,
) -> Result<i32, Error> {
    let env = fleet.environment(env_name)?;
    let prod = fleet.products.get(product).ok_or_else(|| {
        let known: Vec<&str> = fleet.products.keys().map(String::as_str).collect();
        Error::Config(
            format!(
                "undefined product {product:?} (defined: {})",
                known.join(", ")
            )
            .into(),
        )
    })?;
    if command.is_empty() {
        return Err(Error::Config(
            "no command given (usage: run <env> --product <p> -- <cmd>...)".into(),
        ));
    }

    // FR-43: one tolerant item read first, which tidies the item when a person runs opv.
    // A key whose field is still not where the convention puts it (a read-only run) is
    // referenced by field id. If the read fails, `op run` reports the problem itself.
    let by_id = if super::tidy::active() {
        super::tidy::read(fleet, env_name, runner)
            .map(|read| read.refs)
            .unwrap_or_default()
    } else {
        std::collections::BTreeMap::new()
    };
    let refs: Vec<(&str, String)> = prod
        .keys
        .iter()
        .filter(|(_, spec)| rules::applies(spec, env_name, env, product))
        .map(|(key, spec)| {
            // A shared key (FR-45) is exported under its own name, referencing its source's
            // field in the same item.
            let (fp, fk) = spec.source().unwrap_or((product, key));
            let field = if fp == SIMPLE_PRODUCT {
                fk.to_string()
            } else {
                format!("{fp}/{fk}")
            };
            let reference = by_id
                .get(&(product.to_string(), key.clone()))
                .cloned()
                .unwrap_or_else(|| format!("op://{}/{}/{field}", env.vault_id, env.item_id));
            (key.as_str(), reference)
        })
        .collect();
    let env_pairs: Vec<(&str, &str)> = refs.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let mut args: Vec<&str> = vec!["run", "--"];
    args.extend(command.iter().map(String::as_str));

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
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => onepassword::op_missing(&Host::detect()),
            k => Error::Dependency(format!("cannot run {OP} ({k})").into()),
        })
}

/// Windows op.exe can read metadata from WSL, but cannot execute a Linux child.
pub fn ensure_native(runner: &dyn CommandRunner) -> Result<(), Error> {
    runner.local_run_supported().map_err(|e| {
        if e.kind() == io::ErrorKind::Unsupported {
            Error::Dependency(format!("Windows op.exe cannot run a Linux child; install/sign in to Linux op, then retry. See {}/local-development.md#wsl.", crate::DOCS_URL).into())
        } else { Error::Dependency(format!("cannot inspect native op ({})", e.kind()).into()) }
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
            match run(&fleet(), e, p, &c, &r) {
                Err(Error::Config(m)) => assert!(m.contains(needle), "{m}"),
                other => panic!("expected Config, got {other:?}"),
            }
            assert!(r.calls.borrow().is_empty());
        }
    }

    /// I5: `run` needs no Fly app (no more placeholder apps for local-only environments).
    #[test]
    fn works_without_fly_section() {
        let fl = fleet_with(
            "[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n\
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
        assert!(matches!(
            run(&fleet(), "prod", "allumata", &cmd(&["env"]), &r),
            Err(Error::Dependency(_))
        ));
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
            "[products.other.keys.OTHER_KEY]\nkind = \"secret\"\nenvironments = [\"prod\"]\n",
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
        assert!(result.unwrap_err().to_string().contains("Linux child"));
        assert!(r.calls.borrow().is_empty());
    }
}
