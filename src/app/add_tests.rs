//! Tests for `opv add` (H2): edits keep the file's comments, every edit is validated by the
//! loader before it is written, and the write is atomic.

use std::fs;
use std::path::PathBuf;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::adapters::onepassword_manifest::template;
use crate::app::testutil::text_of;
use crate::config_store::{FileStore, Found, ManifestStore, Matched, Snapshot, manifest_title};
use crate::domain::Kind;

const COMMENTED: &str = "# Our services. Values live in 1Password.\n\n\
[environments.dev]   # local only\nboundaries.api = { vault_id = \"vdev\", item_id = \"idev\" }\n\n\
[environments.prod]\nboundaries.api = { vault_id = \"vprd\", item_id = \"iprd\" }\n\
[environments.prod.targets.app]\nstate_vault_id = \"sprod\"\nfly.app = \"myapp\"\n\
fly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"\n\n\
# The API\n[products.api.keys.DATABASE_URL]\nkind = \"secret\"\n\
environments = [\"dev\", \"prod\"]   # both\n";

struct Added {
    _dir: tempfile::TempDir,
    path: PathBuf,
    res: Result<(), Error>,
    out: String,
}

/// `text` as a project keeps it (D-G): the contract without its ids.
fn without_ids(text: &str) -> String {
    crate::config::bindings::split(text).0
}

impl Added {
    fn text(&self) -> String {
        crate::config::read_merged(&self.path).unwrap()
    }
    /// The contract file itself, its ids in the bindings file beside it.
    fn contract(&self) -> String {
        fs::read_to_string(&self.path).unwrap()
    }
    fn err(&self) -> String {
        self.res.as_ref().unwrap_err().to_string()
    }
    fn fleet(&self) -> crate::domain::Fleet {
        config::parse(&self.text()).unwrap()
    }
}

fn add_to(file: &str, a: AddArgs) -> Added {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    crate::config::bindings::write_split(&path, file).unwrap();
    let mut out = Vec::new();
    let store = FileStore { path: path.clone() };
    let res = run(&a, &store, &FakeOp::default(), &mut out);
    Added {
        _dir: dir,
        path,
        res,
        out: text_of(&out),
    }
}

/// The CLI invocation `opv <words>`, for rendering a cause's step.
fn cli(words: &[&str]) -> crate::cause::Invocation {
    let argv: Vec<String> = std::iter::once("opv")
        .chain(words.iter().copied())
        .map(str::to_string)
        .collect();
    crate::cause::Invocation::from_cli(&argv)
}

/// The Next an error renders against `inv`, as a command line.
fn next_of(e: &Error, inv: &crate::cause::Invocation) -> Option<String> {
    let (cause, _) = e.cause().expect("a catalog cause");
    crate::cause::render::next_text(&cause.step(inv).1, inv)
}

fn new_key(name: &str) -> AddArgs {
    AddArgs {
        name: name.into(),
        kind: Some("secret".into()),
        ..AddArgs::default()
    }
}

#[test]
fn adding_a_key_keeps_every_comment_and_line() {
    let a = add_to(COMMENTED, new_key("api/STRIPE_KEY"));
    assert!(
        a.contract().starts_with(&without_ids(COMMENTED)),
        "{}",
        a.contract()
    );
}

#[test]
fn added_key_loads_with_its_kind() {
    let mut args = new_key("api/LOG_LEVEL");
    args.kind = Some("config".into());
    let a = add_to(COMMENTED, args);
    assert_eq!(
        a.fleet().products["api"].keys["LOG_LEVEL"].kind,
        Kind::Config
    );
}

#[test]
fn without_env_the_key_is_declared_for_every_environment() {
    let a = add_to(COMMENTED, new_key("api/STRIPE_KEY"));
    assert_eq!(
        a.fleet().products["api"].keys["STRIPE_KEY"].environments,
        vec!["dev", "prod"]
    );
}

#[test]
fn env_limits_the_environments() {
    let mut args = new_key("api/STRIPE_KEY");
    args.envs = vec!["prod".into()];
    let a = add_to(COMMENTED, args);
    assert_eq!(
        a.fleet().products["api"].keys["STRIPE_KEY"].environments,
        vec!["prod"]
    );
}

#[test]
fn a_name_colliding_on_a_target_is_refused() {
    let file = format!(
        "{COMMENTED}\n[products.my_app.keys.K]\nkind = \"secret\"\nenvironments = [\"prod\"]\n"
    )
    .replace(
        "[environments.prod]\n",
        "[environments.prod]\nboundaries.my_app = { vault_id = \"vprd\", item_id = \"iprd\" }\n",
    );
    let a = add_to(&file, new_key("my-app/K"));
    assert_eq!(a.res.as_ref().unwrap_err().exit_code(), 2, "{:?}", a.res);
}

#[test]
fn a_refused_add_leaves_the_file_byte_for_byte() {
    let file = format!(
        "{COMMENTED}\n[products.my_app.keys.K]\nkind = \"secret\"\nenvironments = [\"prod\"]\n"
    )
    .replace(
        "[environments.prod]\n",
        "[environments.prod]\nboundaries.my_app = { vault_id = \"vprd\", item_id = \"iprd\" }\n",
    );
    let a = add_to(&file, new_key("my-app/K"));
    assert_eq!(a.contract(), without_ids(&file));
}

#[test]
fn the_write_leaves_no_temporary_file() {
    let a = add_to(COMMENTED, new_key("api/STRIPE_KEY"));
    let mut names: Vec<String> = fs::read_dir(a.path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["secrets.bindings.toml", "secrets.toml"]);
}

#[test]
fn a_numeric_rule_is_written_as_a_number() {
    let mut args = new_key("api/JWT_KEY");
    args.rules = vec!["base64_bytes=32".into()];
    let a = add_to(COMMENTED, args);
    assert_eq!(
        a.fleet().products["api"].keys["JWT_KEY"].rules.base64_bytes,
        Some(32)
    );
}

#[test]
fn a_text_rule_is_written_as_text() {
    let mut args = new_key("api/STRIPE_KEY");
    args.rules = vec!["prefix=sk_".into()];
    let a = add_to(COMMENTED, args);
    assert_eq!(
        a.fleet().products["api"].keys["STRIPE_KEY"]
            .rules
            .prefix
            .as_deref(),
        Some("sk_")
    );
}

#[test]
fn a_comma_separated_enum_is_written_as_a_list() {
    let mut args = new_key("api/LOG_LEVEL");
    args.kind = Some("config".into());
    args.rules = vec!["enum=debug,info".into()];
    let a = add_to(COMMENTED, args);
    assert_eq!(
        a.fleet().products["api"].keys["LOG_LEVEL"].rules.r#enum,
        Some(vec!["debug".to_string(), "info".to_string()])
    );
}

#[test]
fn a_flag_rule_by_name_is_true() {
    let mut args = new_key("api/HOOK_URL");
    args.rules = vec!["https_url".into()];
    let a = add_to(COMMENTED, args);
    assert!(a.fleet().products["api"].keys["HOOK_URL"].rules.https_url);
}

#[test]
fn an_unknown_rule_is_refused_naming_it() {
    let mut args = new_key("api/STRIPE_KEY");
    args.rules = vec!["prefixx=sk_".into()];
    let a = add_to(COMMENTED, args);
    assert!(a.err().contains("--rule prefixx"), "{}", a.err());
}

#[test]
fn an_invalid_rule_value_is_refused_by_the_loader() {
    let mut args = new_key("api/STRIPE_KEY");
    args.rules = vec!["regex=([a-z".into()];
    let a = add_to(COMMENTED, args);
    // The loader's refusal is a catalog cause (audit 03.01); its field is the rule.
    assert!(
        a.err().contains(".rules.regex is not valid syntax"),
        "{}",
        a.err()
    );
}

#[test]
fn guidance_and_immutable_are_written() {
    let mut args = new_key("api/JWT_KEY");
    args.guidance = Some("32 random bytes".into());
    args.immutable = true;
    let a = add_to(COMMENTED, args);
    let k = &a.fleet().products["api"].keys["JWT_KEY"];
    assert_eq!(
        (k.guidance.as_str(), k.immutable),
        ("32 random bytes", true)
    );
}

#[test]
fn a_new_key_without_kind_is_refused() {
    let mut args = new_key("api/STRIPE_KEY");
    args.kind = None;
    let a = add_to(COMMENTED, args);
    assert!(a.err().contains("--kind"), "{}", a.err());
}

/// 05.19: an undeclared environment is the catalog's NotDeclared (audit 03.02), never the
/// `opv init <env> --add-env` that needs an existing item.
#[test]
fn an_unknown_environment_is_not_declared() {
    let mut args = new_key("api/STRIPE_KEY");
    args.envs = vec!["qa".into()];
    let a = add_to(COMMENTED, args);
    assert_eq!(a.res.unwrap_err().code_str(), "unknown_env");
}

#[test]
fn an_unknown_environment_never_names_init_add_env() {
    let mut args = new_key("api/STRIPE_KEY");
    args.envs = vec!["qa".into()];
    let a = add_to(COMMENTED, args);
    let inv = cli(&["add", "api/STRIPE_KEY", "--kind", "secret", "--env", "qa"]);
    assert!(!next_of(a.res.as_ref().unwrap_err(), &inv).is_some_and(|n| n.contains("init")));
}

#[test]
fn an_unknown_environment_is_refused() {
    let mut args = new_key("api/STRIPE_KEY");
    args.envs = vec!["qa".into()];
    let a = add_to(COMMENTED, args);
    assert!(a.res.is_err());
}

/// 05.20: a bare KEY no product declares needs its product (a usage error).
#[test]
fn a_new_key_without_product_is_a_usage_error() {
    let a = add_to(COMMENTED, new_key("STRIPE_KEY"));
    assert_eq!(a.res.unwrap_err().code_str(), "usage");
}

/// 05.20: a bare KEY that exactly one product declares names that product's key, as the
/// help promises.
#[test]
fn a_bare_key_one_product_declares_is_that_products_key() {
    let mut args = new_key("DATABASE_URL");
    args.kind = None;
    let a = add_to(COMMENTED, args);
    assert!(
        a.out.contains("api/DATABASE_URL is already declared"),
        "{}",
        a.out
    );
}

#[test]
fn a_bare_key_several_products_declare_is_ambiguous() {
    let file = format!(
        "{COMMENTED}\n[products.web.keys.DATABASE_URL]\nkind = \"secret\"\nenvironments = [\"dev\"]\n"
    )
    .replace(
        "[environments.dev]   # local only\n",
        "[environments.dev]   # local only\nboundaries.web = { vault_id = \"vdev\", item_id = \"idev\" }\n",
    );
    let mut args = new_key("DATABASE_URL");
    args.kind = None;
    let a = add_to(&file, args);
    assert_eq!(a.res.unwrap_err().code_str(), "ambiguous_name");
}

#[test]
fn a_declared_key_gains_the_new_environment_in_its_own_array() {
    // Another key keeps dev's boundary in use, so the file loads before the add.
    let file = format!(
        "{COMMENTED}\n[products.api.keys.OTHER]\nkind = \"secret\"\nenvironments = [\"dev\"]\n"
    )
    .replace("[\"dev\", \"prod\"]", "[\"prod\"]");
    let mut args = new_key("api/DATABASE_URL");
    args.kind = None;
    args.envs = vec!["dev".into()];
    let a = add_to(&file, args);
    assert!(
        a.text()
            .contains("environments = [\"prod\", \"dev\"]   # both\n"),
        "{}",
        a.text()
    );
}

#[test]
fn a_declared_key_with_new_rules_is_refused() {
    let mut args = new_key("api/DATABASE_URL");
    args.rules = vec!["prefix=postgres://".into()];
    let a = add_to(COMMENTED, args);
    // Pinned wording changed with the catalog: a hand edit is AlreadyDeclared's step.
    assert_eq!(a.res.unwrap_err().code_str(), "already_declared");
}

#[test]
fn a_declared_key_already_in_every_environment_changes_nothing() {
    let mut args = new_key("api/DATABASE_URL");
    args.kind = None;
    let a = add_to(COMMENTED, args);
    assert_eq!(a.contract(), without_ids(COMMENTED));
}

#[test]
fn the_next_step_checks_the_environment_which_adds_the_field() {
    let mut args = new_key("api/STRIPE_KEY");
    args.envs = vec!["prod".into()];
    let a = add_to(COMMENTED, args);
    assert!(
        a.out.ends_with("Next: opv check prod --product api\n"),
        "{}",
        a.out
    );
}

#[test]
fn a_refusal_points_at_the_add_help() {
    let a = add_to(COMMENTED, new_key("api/bad"));
    let inv = cli(&["add", "api/bad", "--kind", "secret"]);
    assert_eq!(
        next_of(a.res.as_ref().unwrap_err(), &inv).as_deref(),
        Some("opv add --help")
    );
}

/// 05.38: the field is created by a signed-in person's check.
#[test]
fn the_then_line_says_the_check_adds_the_field_when_signed_in() {
    let mut args = new_key("api/STRIPE_KEY");
    args.envs = vec!["prod".into()];
    let a = add_to(COMMENTED, args);
    assert!(
        a.out
            .contains("adds the field to the item when you are signed in"),
        "{}",
        a.out
    );
}

/// C14: the loader refuses the text `add` built, so nothing was written.
fn refused_proposal() -> Added {
    let mut args = new_key("api/STRIPE_KEY");
    args.rules = vec!["regex=([a-z".into()];
    add_to(COMMENTED, args)
}

/// C14: the refusal of add's proposed text uses the catalog wording that says nothing
/// was written.
#[test]
fn a_refusal_of_the_proposed_text_says_nothing_was_written() {
    let a = refused_proposal();
    assert!(a.err().contains("nothing was written"), "{}", a.err());
}

/// C14: the refusal is the catalog's proposed-change cause, not the file's own invalid one.
#[test]
fn a_refusal_of_the_proposed_text_is_marked_from_the_proposal() {
    let a = refused_proposal();
    assert!(matches!(
        a.res.as_ref().unwrap_err().cause(),
        Some((
            Cause::ConfigProposalInvalid {
                from_proposal: true,
                ..
            },
            _
        ))
    ));
}

// --- a manifest in 1Password (FR-44): the same edit through ConfigStore ---

/// A manifest holding `body`, and its store as discovery returns it.
fn manifest(body: &str) -> (FakeOp, Found) {
    let op = FakeOp::default();
    let id = op.insert(
        "myapp-dev",
        template(&manifest_title("myapp"), "myapp", &[], body),
    );
    let row = crate::adapters::onepassword_manifest::Row {
        id,
        title: manifest_title("myapp"),
        tags: Vec::new(),
        version: 1,
        vault: crate::adapters::onepassword_manifest::VaultRef {
            id: "vdev0000000000000000000001".into(),
            name: "myapp-dev".into(),
        },
    };
    let found = Found::Manifest(ManifestStore::from_row(&row, None, Matched::Given));
    (op, found)
}

fn add_to_manifest(body: &str, a: AddArgs) -> (FakeOp, Found, Result<(), Error>, String) {
    let (op, found) = manifest(body);
    let mut out = Vec::new();
    let res = run(&a, found.store(), &op, &mut out);
    (op, found, res, text_of(&out))
}

#[test]
fn adding_to_a_manifest_saves_the_key_in_it() {
    let (op, found, res, _) = add_to_manifest(COMMENTED, new_key("api/STRIPE_KEY"));
    res.unwrap();
    let fleet = found.load(&op).unwrap();
    assert!(fleet.products["api"].keys.contains_key("STRIPE_KEY"));
}

#[test]
fn adding_to_a_manifest_keeps_its_comments() {
    let (op, found, res, _) = add_to_manifest(COMMENTED, new_key("api/STRIPE_KEY"));
    res.unwrap();
    let text = found.store().read(&op).unwrap().text;
    assert!(
        text.starts_with("# Our services. Values live in 1Password."),
        "{text}"
    );
}

#[test]
fn a_refused_add_to_a_manifest_edits_nothing() {
    let mut args = new_key("api/STRIPE_KEY");
    args.rules = vec!["regex=([a-z".into()];
    let (op, _, res, _) = add_to_manifest(COMMENTED, args);
    assert!(res.is_err() && op.count(&["op", "item", "edit"]) == 0);
}

#[test]
fn a_manifest_add_names_the_manifest_in_its_summary() {
    let (_, _, res, out) = add_to_manifest(COMMENTED, new_key("api/STRIPE_KEY"));
    res.unwrap();
    assert!(out.contains("manifest \"opv · myapp\""), "{out}");
}

#[test]
fn a_broken_manifest_names_the_manifest_and_points_at_config_edit() {
    let broken = COMMENTED.replace("kind = \"secret\"", "kind = \"secre\"");
    let (_, _, res, _) = add_to_manifest(&broken, new_key("api/STRIPE_KEY"));
    let e = res.unwrap_err();
    // A catalog cause names its source: the manifest, whose Do says opv config edit.
    assert!(
        e.to_string()
            .starts_with("the 1Password manifest opv · myapp of project myapp"),
        "{e}"
    );
}

#[test]
fn a_manifest_changed_since_it_was_read_is_refused() {
    let (op, found) = manifest(COMMENTED);
    let base: Snapshot = found.store().read(&op).unwrap();
    let Found::Manifest(m) = &found else {
        unreachable!()
    };
    op.bump(&m.item_id);
    let e = crate::config_store::save(found.store(), &op, &base, COMMENTED).unwrap_err();
    assert_eq!(e.code_str(), "config_changed", "{e}");
}

#[test]
fn a_file_changed_since_it_was_read_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    crate::config::bindings::write_split(&path, COMMENTED).unwrap();
    let store = FileStore { path: path.clone() };
    let base = store.read(&FakeOp::default()).unwrap();
    fs::write(
        &path,
        format!("{}\n# someone else\n", without_ids(COMMENTED)),
    )
    .unwrap();
    let e = crate::config_store::save(&store, &FakeOp::default(), &base, COMMENTED).unwrap_err();
    assert_eq!(e.code_str(), "config_changed", "{e}");
}

// #97: --from, --personal, --allow-same-value -------------------------------------------

#[test]
fn from_declares_a_shared_key() {
    // `web` is declared already (its boundary is `api`'s), so only the shared key is new.
    let file = format!(
        "{COMMENTED}\n[products.web]\nboundary = \"api\"\n\n\
         [products.web.keys.SESSION]\nkind = \"secret\"\nenvironments = [\"dev\", \"prod\"]\n"
    );
    let mut args = new_key("web/DATABASE_URL");
    args.from = Some("api/DATABASE_URL".into());
    let a = add_to(&file, args);
    assert_eq!(
        a.fleet().products["web"].keys["DATABASE_URL"]
            .from
            .as_deref(),
        Some("api/DATABASE_URL")
    );
}

#[test]
fn personal_declares_a_personal_key() {
    let mut args = new_key("api/OPENAI_API_KEY");
    args.envs = vec!["dev".into()];
    args.personal = true;
    let a = add_to(COMMENTED, args);
    assert!(a.fleet().products["api"].keys["OPENAI_API_KEY"].personal);
}

#[test]
fn a_personal_key_for_a_deployed_environment_is_refused() {
    let mut args = new_key("api/OPENAI_API_KEY");
    args.envs = vec!["prod".into()];
    args.personal = true;
    assert!(add_to(COMMENTED, args).res.is_err());
}

#[test]
fn allow_same_value_is_written() {
    let mut args = new_key("api/SHARED_TOKEN");
    args.allow_same_value = true;
    let a = add_to(COMMENTED, args);
    assert!(a.fleet().products["api"].keys["SHARED_TOKEN"].allow_same_value);
}

#[test]
fn a_declared_key_cannot_become_personal_through_add() {
    let mut args = new_key("api/DATABASE_URL");
    args.kind = None;
    args.personal = true;
    assert!(add_to(COMMENTED, args).res.is_err());
}
