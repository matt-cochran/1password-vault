//! Tests for the target builders `opv propose target` uses and for `opv target list`
//! (FR-56, §5.2). Names only (SR-1).

use super::*;
use crate::app::testutil::text_of;
use crate::config;

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

// --- the state vault (FR-58): created once, then reused ------------------------------

// --- --dry-run changes nothing --------------------------------------------------------

// --- --json (A5): the documented fields ----------------------------------------------

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
