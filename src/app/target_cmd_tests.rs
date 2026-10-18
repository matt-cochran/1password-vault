//! Tests for `opv target add` and `opv target list` (FR-56, §5.2): every written table is
//! validated by the loader before it is saved, every refusal names its problem and writes
//! nothing, and the state vault is created once and reused after. Names only (SR-1).

use std::path::PathBuf;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::app::testutil::text_of;
use crate::config_store::FileStore;

/// One deployable product and a dev environment: enough to declare a first target.
const FLEET: &str = "\
# Our services. Values live in 1Password.

[environments.dev]
boundaries.api = { vault_id = \"vdev\", item_id = \"idev\" }

[environments.prod]

[products.api.keys.OPENAI_API_KEY]
kind = \"secret\"
environments = [\"dev\"]
";

/// A fleet whose one key only the `serve` process reads (delivery-transports §4.4).
const ROLE_FLEET: &str = "\
[environments.dev]
boundaries.api = { vault_id = \"vdev\", item_id = \"idev\" }

[products.api.keys.OPENAI_API_KEY]
kind = \"secret\"
environments = [\"dev\"]
roles = [\"serve\"]
";

/// The same fleet with a target `site` already declared in dev.
const WITH_TARGET: &str = "\
[environments.dev]
boundaries.api = { vault_id = \"vdev\", item_id = \"idev\" }

[environments.dev.targets.site]
fly.app = \"existing\"
fly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"
products = [\"api\"]
state_vault_id = \"sdev\"

[products.api.keys.OPENAI_API_KEY]
kind = \"secret\"
environments = [\"dev\"]
";

/// A fleet that also declares a source-only product `shared` (FR-47).
const WITH_SOURCE_ONLY: &str = "\
[environments.dev]
boundaries.api = { vault_id = \"vdev\", item_id = \"idev\" }
boundaries.shared = { vault_id = \"vsh\", item_id = \"ish\" }

[products.api.keys.OPENAI_API_KEY]
kind = \"secret\"
environments = [\"dev\"]

[products.shared]
source_only = true

[products.shared.keys.TOKEN]
kind = \"secret\"
environments = [\"dev\"]
";

/// The same fleet with a target in dev and another in prod.
const TWO_ENVS: &str = "\
[environments.dev]
boundaries.api = { vault_id = \"vdev\", item_id = \"idev\" }

[environments.dev.targets.site]
fly.app = \"existing\"
fly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"
products = [\"api\"]
state_vault_id = \"sdev\"

[environments.prod.targets.web]
fly.app = \"prod-web\"
fly.secret_name = \"FLEET__{PRODUCT}__{KEY}\"
products = [\"api\"]
state_vault_id = \"sprod\"

[products.api.keys.OPENAI_API_KEY]
kind = \"secret\"
environments = [\"dev\"]
";

/// The result of one `target add` run.
struct Added {
    _dir: tempfile::TempDir,
    path: PathBuf,
    res: Result<(), Error>,
    out: String,
}

impl Added {
    fn text(&self) -> String {
        crate::config::read_merged(&self.path).unwrap()
    }
    fn err(&self) -> String {
        self.res.as_ref().unwrap_err().to_string()
    }
    fn fleet(&self) -> Fleet {
        config::parse(&self.text()).unwrap()
    }
}

/// `target add` arguments for `env`/`name`, with a `--fly-app` and a fixed `--project`.
fn add_args(env: &str, name: &str) -> AddArgs {
    AddArgs {
        env: env.into(),
        name: name.into(),
        fields: BTreeMap::from([("fly-app".to_string(), format!("{name}-app"))]),
        project: Some("myapp".into()),
        ..AddArgs::default()
    }
}

fn add_with(file: &str, a: AddArgs, op: &FakeOp) -> Added {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    crate::config::bindings::write_split(&path, file).unwrap();
    let mut out = Vec::new();
    let store = FileStore { path: path.clone() };
    let res = add(&a, &store, op, &mut out);
    Added {
        _dir: dir,
        path,
        res,
        out: text_of(&out),
    }
}

fn add_to(file: &str, a: AddArgs) -> Added {
    add_with(file, a, &FakeOp::default())
}

/// The ID FakeOp recorded for the vault titled `title`.
fn vault_id(op: &FakeOp, title: &str) -> Option<String> {
    op.vaults
        .borrow()
        .iter()
        .find(|(_, name)| name == title)
        .map(|(id, _)| id.clone())
}

// --- what target add writes ------------------------------------------------------------

#[test]
fn add_writes_the_target_table_under_its_environment() {
    let a = add_to(FLEET, add_args("dev", "site"));
    assert!(
        a.text().contains("\n[environments.dev.targets.site]\n"),
        "{}",
        a.text()
    );
}

#[test]
fn add_writes_a_comment_saying_it_wrote_the_target() {
    let a = add_to(FLEET, add_args("dev", "site"));
    assert!(
        a.text()
            .contains("# deploy target site in dev; added by opv target add\n"),
        "{}",
        a.text()
    );
}

#[test]
fn add_writes_the_provider_section() {
    let a = add_to(FLEET, add_args("dev", "site"));
    assert!(
        a.text().contains("fly.app = \"site-app\"\n"),
        "{}",
        a.text()
    );
}

#[test]
fn add_writes_the_products_it_was_given() {
    let mut args = add_args("dev", "site");
    args.products = vec!["api".into()];
    let a = add_to(FLEET, args);
    assert!(a.text().contains("products = [\"api\"]\n"), "{}", a.text());
}

#[test]
fn add_writes_the_created_state_vaults_id() {
    let op = FakeOp::default();
    let a = add_with(FLEET, add_args("dev", "site"), &op);
    let id = vault_id(&op, "myapp-dev-site-state").unwrap();
    assert_eq!(
        a.fleet().environments["dev"].targets["site"].state_vault_id,
        Some(id)
    );
}

#[test]
fn the_written_target_loads_with_its_provider() {
    let a = add_to(FLEET, add_args("dev", "site"));
    assert_eq!(
        a.fleet().environments["dev"].targets["site"]
            .config
            .target_locator(),
        "app site-app"
    );
}

#[test]
fn the_written_target_loads_with_its_products() {
    let mut args = add_args("dev", "site");
    args.products = vec!["api".into()];
    let a = add_to(FLEET, args);
    assert_eq!(
        a.fleet().environments["dev"].targets["site"].products,
        Some(vec!["api".to_string()])
    );
}

#[test]
fn add_keeps_every_existing_line() {
    let a = add_to(FLEET, add_args("dev", "site"));
    assert!(
        FLEET.lines().all(|line| a.text().contains(line)),
        "{}",
        a.text()
    );
}

#[test]
fn add_ends_with_the_access_next_step() {
    let a = add_to(FLEET, add_args("dev", "site"));
    assert!(
        a.out.ends_with("Next: opv access dev --target site\n"),
        "{}",
        a.out
    );
}

// --- refusals: each names its problem ------------------------------------------------

#[test]
fn an_unknown_environment_is_refused_naming_it() {
    let a = add_to(FLEET, add_args("qa", "site"));
    assert!(a.err().contains("qa"), "{}", a.err());
}

#[test]
fn an_unknown_environment_writes_nothing() {
    let a = add_to(FLEET, add_args("qa", "site"));
    assert_eq!(a.text(), FLEET);
}

#[test]
fn an_invalid_target_name_is_refused_naming_the_shape() {
    let a = add_to(FLEET, add_args("dev", "Site"));
    assert!(a.err().contains("^[a-z][a-z0-9-]*$"), "{}", a.err());
}

#[test]
fn an_invalid_target_name_writes_nothing() {
    let a = add_to(FLEET, add_args("dev", "Site"));
    assert_eq!(a.text(), FLEET);
}

#[test]
fn a_duplicate_target_name_is_refused_naming_it() {
    let a = add_to(WITH_TARGET, add_args("dev", "site"));
    assert!(a.err().contains("is already declared"), "{}", a.err());
}

#[test]
fn a_duplicate_target_name_points_to_config_edit() {
    let a = add_to(WITH_TARGET, add_args("dev", "site"));
    assert_eq!(
        a.res.as_ref().unwrap_err().next_text().unwrap_or_default(),
        "opv config edit"
    );
}

// --- regressions of the audit findings (06-targets.md) -------------------------------

/// The fragment `target add` builds for dev/site.
fn site_body() -> String {
    target_table(
        "dev",
        "site",
        "fly.app = \"x\"\n",
        &[],
        &[],
        None,
        None,
        &[],
    )
}

#[test]
fn an_inline_targets_table_points_to_config_edit() {
    // 06.27: a configuration-shape refusal leads to `opv config edit`, never `--help`.
    let original = "[environments.dev]\ntargets = {}\n";
    let e = insert_target(original, "dev", "site", &site_body(), "# c").unwrap_err();
    assert_eq!(e.next_text().unwrap_or_default(), "opv config edit");
}

#[test]
fn an_unparsable_configuration_never_shows_its_lines() {
    // 06.53: the raw toml_edit error would print the offending line.
    let original = "[environments.dev]\nbad = = \"LINEMARKER\"\n";
    let e = insert_target(original, "dev", "site", &site_body(), "# c").unwrap_err();
    assert!(!e.to_string().contains("LINEMARKER"), "{e}");
}

#[test]
fn a_duplicate_target_name_writes_nothing() {
    let a = add_to(WITH_TARGET, add_args("dev", "site"));
    assert_eq!(a.text(), WITH_TARGET);
}

#[test]
fn an_unknown_product_is_refused_naming_it() {
    let mut args = add_args("dev", "site");
    args.products = vec!["ghost".into()];
    let a = add_to(FLEET, args);
    assert!(a.err().contains("ghost"), "{}", a.err());
}

#[test]
fn an_unknown_product_writes_nothing() {
    let mut args = add_args("dev", "site");
    args.products = vec!["ghost".into()];
    let a = add_to(FLEET, args);
    assert_eq!(a.text(), FLEET);
}

#[test]
fn a_source_only_product_is_refused_naming_it() {
    let mut args = add_args("dev", "site");
    args.products = vec!["shared".into()];
    let a = add_to(WITH_SOURCE_ONLY, args);
    assert!(a.err().contains("source-only"), "{}", a.err());
}

#[test]
fn a_source_only_product_writes_nothing() {
    let mut args = add_args("dev", "site");
    args.products = vec!["shared".into()];
    let a = add_to(WITH_SOURCE_ONLY, args);
    assert_eq!(a.text(), WITH_SOURCE_ONLY);
}

#[test]
fn an_unknown_provider_is_refused_naming_it() {
    let mut args = add_args("dev", "site");
    args.provider = Some("aws".into());
    let a = add_to(FLEET, args);
    assert!(a.err().contains("aws"), "{}", a.err());
}

/// FR-58, E2: target add records each placement's delivery item in the same step, so the
/// first sync records evidence without another opv bootstrap.
#[test]
fn add_records_a_delivery_item_for_each_placement() {
    let a = add_to(FLEET, add_args("dev", "site"));
    assert!(
        !a.fleet().environments["dev"].targets["site"]
            .delivery_items
            .is_empty(),
        "{}",
        a.text()
    );
}

#[test]
fn an_explicit_provider_writes_its_section() {
    let mut args = add_args("dev", "site");
    args.provider = Some("fly".into());
    assert!(add_to(FLEET, args).text().contains("site-app"));
}

#[test]
fn without_provider_or_its_options_add_is_refused_naming_both() {
    let mut args = add_args("dev", "site");
    args.fields.clear();
    let a = add_to(FLEET, args);
    assert!(a.err().contains("--provider"), "{}", a.err());
}

#[test]
fn options_of_two_providers_are_refused() {
    let mut args = add_args("dev", "site");
    args.fields.insert("github-repo".into(), "org/site".into());
    let a = add_to(FLEET, args);
    assert!(a.err().contains("cannot be used together"), "{}", a.err());
}

#[test]
fn a_required_provider_option_missing_is_refused_naming_it() {
    let mut args = add_args("dev", "site");
    args.provider = Some("fly".into());
    args.fields.clear();
    let a = add_to(FLEET, args);
    assert!(a.err().contains("--fly-app"), "{}", a.err());
}

#[test]
fn a_refusal_offers_a_next_step() {
    let a = add_to(FLEET, add_args("qa", "site"));
    assert!(a.res.as_ref().unwrap_err().cause().is_some());
}

// --- the state vault (FR-58): created once, then reused ------------------------------

#[test]
fn add_creates_the_state_vault_titled_after_the_target() {
    let op = FakeOp::default();
    add_with(FLEET, add_args("dev", "site"), &op);
    assert!(vault_id(&op, "myapp-dev-site-state").is_some());
}

#[test]
fn add_creates_exactly_one_state_vault() {
    let op = FakeOp::default();
    add_with(FLEET, add_args("dev", "site"), &op);
    assert_eq!(op.count(&["op", "vault", "create"]), 1);
}

#[test]
fn add_reuses_an_existing_state_vault() {
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push(("vst1".into(), "myapp-dev-site-state".into()));
    let a = add_with(FLEET, add_args("dev", "site"), &op);
    assert_eq!(
        a.fleet().environments["dev"].targets["site"]
            .state_vault_id
            .as_deref(),
        Some("vst1")
    );
}

#[test]
fn add_creates_no_vault_when_one_already_exists() {
    let op = FakeOp::default();
    op.vaults
        .borrow_mut()
        .push(("vst1".into(), "myapp-dev-site-state".into()));
    add_with(FLEET, add_args("dev", "site"), &op);
    assert_eq!(op.count(&["op", "vault", "create"]), 0);
}

// --- --dry-run changes nothing --------------------------------------------------------

#[test]
fn dry_run_changes_nothing() {
    let mut args = add_args("dev", "site");
    args.dry_run = true;
    let a = add_to(FLEET, args);
    assert_eq!(a.text(), FLEET);
}

#[test]
fn dry_run_creates_no_state_vault() {
    let mut args = add_args("dev", "site");
    args.dry_run = true;
    let op = FakeOp::default();
    add_with(FLEET, args, &op);
    assert_eq!(op.count(&["op", "vault", "create"]), 0);
}

#[test]
fn dry_run_reports_the_target_it_would_add() {
    let mut args = add_args("dev", "site");
    args.dry_run = true;
    let a = add_to(FLEET, args);
    assert!(
        a.out.contains("would add [environments.dev.targets.site]"),
        "{}",
        a.out
    );
}

#[test]
fn dry_run_reports_the_state_vault_it_would_create() {
    let mut args = add_args("dev", "site");
    args.dry_run = true;
    let a = add_to(FLEET, args);
    assert!(
        a.out
            .contains("would create state vault myapp-dev-site-state"),
        "{}",
        a.out
    );
}

// --- --json (A5): the documented fields ----------------------------------------------

#[test]
fn add_json_names_the_written_target() {
    let mut args = add_args("dev", "site");
    args.json = true;
    let a = add_to(FLEET, args);
    let v: serde_json::Value = serde_json::from_str(&a.out).unwrap();
    assert_eq!(v["target"], "site");
}

#[test]
fn add_json_reports_the_state_vault_id() {
    let mut args = add_args("dev", "site");
    args.json = true;
    let op = FakeOp::default();
    let a = add_with(FLEET, args, &op);
    let v: serde_json::Value = serde_json::from_str(&a.out).unwrap();
    assert_eq!(
        v["state_vault_id"],
        vault_id(&op, "myapp-dev-site-state").unwrap()
    );
}

#[test]
fn add_json_dry_run_reports_the_state_vault_it_would_create() {
    let mut args = add_args("dev", "site");
    args.json = true;
    args.dry_run = true;
    let a = add_to(FLEET, args);
    let v: serde_json::Value = serde_json::from_str(&a.out).unwrap();
    assert_eq!(v["created_state_vault"], true);
}

#[test]
fn add_json_ends_with_the_next_step() {
    let mut args = add_args("dev", "site");
    args.json = true;
    let a = add_to(FLEET, args);
    let v: serde_json::Value = serde_json::from_str(&a.out).unwrap();
    assert_eq!(v["next"], "opv access dev --target site");
}

// --- target list (FR-56): read-only, every field a person needs ----------------------

fn list_text(fleet: &Fleet, args: &ListArgs) -> String {
    let mut out = Vec::new();
    list(fleet, args, &mut out).unwrap();
    text_of(&out)
}

fn declared() -> Fleet {
    config::parse(WITH_TARGET).unwrap()
}

#[test]
fn list_prints_the_environment() {
    assert!(list_text(&declared(), &ListArgs::default()).starts_with("dev "));
}

#[test]
fn list_prints_the_target_name() {
    assert!(list_text(&declared(), &ListArgs::default()).contains(" site "));
}

#[test]
fn list_prints_the_provider() {
    assert!(list_text(&declared(), &ListArgs::default()).contains("fly "));
}

#[test]
fn list_prints_the_locator() {
    assert!(list_text(&declared(), &ListArgs::default()).contains("app existing"));
}

#[test]
fn list_prints_the_products() {
    assert!(list_text(&declared(), &ListArgs::default()).contains("products: api"));
}

#[test]
fn list_prints_whether_deploy_credentials_are_set() {
    assert!(list_text(&declared(), &ListArgs::default()).contains("deploy_credentials: none"));
}

#[test]
fn list_with_env_limits_to_that_environment() {
    let fleet = config::parse(TWO_ENVS).unwrap();
    let args = ListArgs {
        env: Some("prod".into()),
        json: false,
    };
    assert_eq!(
        list_text(&fleet, &args),
        "prod web fly app prod-web products: api deploy_credentials: none\n"
    );
}

#[test]
fn list_without_targets_says_none() {
    let fleet = config::parse(FLEET).unwrap();
    assert_eq!(
        list_text(&fleet, &ListArgs::default()),
        "no environment declares a deploy target\nNext: opv target add --help\n"
    );
}

#[test]
fn list_of_an_environment_without_targets_names_it() {
    // 06.44: the empty listing says which environment has none.
    let fleet = config::parse(FLEET).unwrap();
    let args = ListArgs {
        env: Some("prod".into()),
        json: false,
    };
    assert!(list_text(&fleet, &args).contains("environment prod has no deploy targets"));
}

#[test]
fn list_unknown_environment_is_refused() {
    let args = ListArgs {
        env: Some("qa".into()),
        json: false,
    };
    let mut out = Vec::new();
    let err = list(&declared(), &args, &mut out).unwrap_err();
    assert!(err.to_string().contains("qa"), "{err}");
}

#[test]
fn list_json_prints_every_documented_field() {
    let args = ListArgs {
        env: None,
        json: true,
    };
    let out = list_text(&declared(), &args);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        v,
        serde_json::json!([{
            "environment": "dev",
            "name": "site",
            "provider": "fly",
            "locator": "app existing",
            "products": ["api"],
            "deploy_credentials": false,
        }])
    );
}

#[test]
fn add_writes_the_roles_it_was_given() {
    let mut args = add_args("dev", "site");
    args.roles = vec!["serve".into()];
    let a = add_to(ROLE_FLEET, args);
    assert!(a.text().contains("roles = [\"serve\"]\n"), "{}", a.text());
}

#[test]
fn add_writes_a_repeated_role_once() {
    let mut args = add_args("dev", "site");
    args.roles = vec!["serve".into(), "serve".into()];
    let a = add_to(ROLE_FLEET, args);
    assert!(a.text().contains("roles = [\"serve\"]\n"), "{}", a.text());
}

#[test]
fn the_written_target_loads_with_its_roles() {
    let mut args = add_args("dev", "site");
    args.roles = vec!["serve".into()];
    let a = add_to(ROLE_FLEET, args);
    assert_eq!(
        a.fleet().environments["dev"].targets["site"].roles,
        Some(vec!["serve".to_string()])
    );
}

#[test]
fn add_without_roles_for_a_role_scoped_key_is_config_invalid() {
    let a = add_to(ROLE_FLEET, add_args("dev", "site"));
    assert_eq!(a.res.as_ref().unwrap_err().code_str(), "config_invalid");
}
