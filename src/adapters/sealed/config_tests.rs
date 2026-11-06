//! The sealed target's load rules through `config::parse` (design `sealed-target` §3.1, D11,
//! D12, G4, T1, T5, T14): the example loads, and each rule refuses its violation by field
//! path or code. One assertion per test. Keys are public test keys (no secret anywhere).

use super::*;
use crate::cause::Cause;

const R1: &str = "age13ts5aywwye8k4qr653hu89n89lt2eexd7szjadl9u3m47fzneggstxdxvs";
const R2: &str = "age12phym722kt7nqqudcn3hylhatgx96eattaxvf2dz2zz27u98nc3s4gxm9w";
const S1: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNsg+yKsUThHH7nZ6IW5uovkXhn/YPafac8XHSwvmSJ opv-sealed-1";
const S2: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJDLU/HvYSykUVjDt+27aTNV6+QD1JsXLLZpsfXVJg4x opv-sealed-2";
const ECDSA: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDXFOBG6JR7netlKNPVKTHIsQFTsXmZaxdXYRDBPIIQ5Co3mcchKrON46Ic6zGtFXR1i+woR0vbA5fe5s4BhDMY=";

/// One sealed target per environment, each with its own recipient and signer.
fn example() -> String {
    format!(
        r#"
[environments.staging]
boundaries.api = {{ vault_id = "vapis", item_id = "iapis" }}

[environments.prod]
boundaries.api = {{ vault_id = "vapi", item_id = "iapi" }}

[environments.staging.targets.box]
state_vault_id = "sstaging"
deploy_credentials = "op://Ops Staging/opv-sealed-staging-signer"
sealed.out = "sealed/staging/{{product}}.opv-sealed"
sealed.env_name = "{{KEY}}"
sealed.recipients = ["{R1}"]
sealed.signer = "{S1}"

[environments.prod.targets.box]
state_vault_id = "sprod"
deploy_credentials = "op://Ops Prod/opv-sealed-prod-signer"
sealed.out = "sealed/prod/{{product}}.opv-sealed"
sealed.env_name = "{{KEY}}"
sealed.recipients = ["{R2}"]
sealed.signer = "{S2}"

[products.api.keys.DATABASE_URL]
kind = "secret"
"#
    )
}

/// `example()` with `from` replaced by `to` once (the replacement must apply).
fn with(from: &str, to: &str) -> String {
    let text = example();
    assert!(text.contains(from), "fixture lacks {from}");
    text.replacen(from, to, 1)
}

/// The prod target's lines replaced: `from` → `to` after the prod section header.
fn prod_with(from: &str, to: &str) -> String {
    let text = example();
    let at = text
        .find("[environments.prod.targets.box]")
        .expect("prod target");
    let (head, tail) = text.split_at(at);
    assert!(tail.contains(from), "prod target lacks {from}");
    format!("{head}{}", tail.replacen(from, to, 1))
}

/// The refusal's code and field.
fn refused(text: &str) -> (String, String) {
    let e = crate::config::parse(text).expect_err("the configuration must be refused");
    let field = match e.parts().0 {
        Cause::ConfigInvalid { field, .. } => field.to_string(),
        other => format!("{other:?}"),
    };
    (e.code_str().to_string(), field)
}

fn refused_field(text: &str) -> String {
    refused(text).1
}

fn refused_code(text: &str) -> String {
    refused(text).0
}

/// The parsed sealed target of `env`.
fn sealed_of(text: &str, env: &str) -> SealedTarget {
    let fleet = crate::config::parse(text).expect("the configuration loads");
    fleet.environments[env].targets["box"]
        .config
        .as_any()
        .downcast_ref::<SealedTarget>()
        .expect("a sealed target")
        .clone()
}

#[test]
fn the_example_loads() {
    assert!(crate::config::parse(&example()).is_ok());
}

// --- D11: trust groups (§3.1-2, §3.1-4, T1) ---------------------------------------------

#[test]
fn a_recipient_shared_across_two_trust_groups_is_refused() {
    assert_eq!(refused_code(&prod_with(R2, R1)), "sealed_recipient_shared");
}

#[test]
fn a_recipient_and_signer_shared_within_one_trust_group_are_accepted() {
    let text = prod_with(R2, R1).replacen(S2, S1, 1).replace(
        "sealed.env_name = \"{KEY}\"",
        "sealed.env_name = \"{KEY}\"\nsealed.trust_group = \"platform\"",
    );
    assert!(crate::config::parse(&text).is_ok());
}

#[test]
fn a_staging_signer_reused_for_a_prod_target_is_refused() {
    assert_eq!(refused_code(&prod_with(S2, S1)), "sealed_signer_shared");
}

#[test]
fn a_shared_signer_is_refused_at_the_signer_field() {
    assert_eq!(
        refused_field(&prod_with(S2, S1)),
        "environments.staging.targets.box.sealed.signer"
    );
}

#[test]
fn a_trust_group_named_like_an_environment_is_still_another_group() {
    let text = with(
        "sealed.env_name = \"{KEY}\"",
        "sealed.env_name = \"{KEY}\"\nsealed.trust_group = \"prod\"",
    )
    .replacen(R2, R1, 1);
    assert_eq!(refused_code(&text), "sealed_recipient_shared");
}

#[test]
fn a_trust_group_that_is_not_a_name_is_refused() {
    let text = with(
        "sealed.env_name = \"{KEY}\"",
        "sealed.env_name = \"{KEY}\"\nsealed.trust_group = \"Platform One\"",
    );
    assert_eq!(
        refused_field(&text),
        "environments.staging.targets.box.sealed.trust_group"
    );
}

// --- recipients and signer (§3.1-1, §3.1-3) ----------------------------------------------

#[test]
fn an_empty_recipient_list_is_refused() {
    assert_eq!(
        refused_field(&prod_with(&format!("[\"{R2}\"]"), "[]")),
        "environments.prod.targets.box.sealed.recipients"
    );
}

#[test]
fn a_duplicate_recipient_is_refused() {
    assert_eq!(
        refused_field(&prod_with(
            &format!("[\"{R2}\"]"),
            &format!("[\"{R2}\", \"{R2}\"]")
        )),
        "environments.prod.targets.box.sealed.recipients"
    );
}

#[test]
fn an_ssh_recipient_is_refused() {
    assert_eq!(
        refused_field(&prod_with(&format!("[\"{R2}\"]"), &format!("[\"{S2}\"]"))),
        "environments.prod.targets.box.sealed.recipients"
    );
}

#[test]
fn an_ecdsa_signer_is_refused() {
    assert_eq!(
        refused_field(&prod_with(S2, ECDSA)),
        "environments.prod.targets.box.sealed.signer"
    );
}

// --- sealed.out (§3.1-5, D12) ------------------------------------------------------------

#[test]
fn an_out_path_with_dotdot_is_refused() {
    assert_eq!(
        refused_field(&prod_with(
            "sealed/prod/{product}",
            "../store/prod/{product}"
        )),
        "environments.prod.targets.box.sealed.out"
    );
}

#[test]
fn an_absolute_out_path_is_refused() {
    assert_eq!(
        refused_field(&prod_with("sealed/prod/{product}", "/srv/sealed/{product}")),
        "environments.prod.targets.box.sealed.out"
    );
}

#[test]
fn a_home_out_path_is_refused() {
    assert_eq!(
        refused_field(&prod_with("sealed/prod/{product}", "~/sealed/{product}")),
        "environments.prod.targets.box.sealed.out"
    );
}

#[test]
fn an_out_path_with_another_placeholder_is_refused() {
    assert_eq!(
        refused_field(&prod_with(
            "sealed/prod/{product}",
            "sealed/{env}/{product}"
        )),
        "environments.prod.targets.box.sealed.out"
    );
}

#[test]
fn an_out_path_without_product_for_two_products_is_refused() {
    let text = format!(
        "{}\n[products.worker.keys.QUEUE_URL]\nkind = \"secret\"\n",
        prod_with("sealed/prod/{product}", "sealed/prod/bundle")
    )
    .replace(
        "boundaries.api = { vault_id = \"vapi\", item_id = \"iapi\" }",
        "boundaries.api = { vault_id = \"vapi\", item_id = \"iapi\" }\n\
         boundaries.worker = { vault_id = \"vwrk\", item_id = \"iwrk\" }",
    )
    .replace(
        "boundaries.api = { vault_id = \"vapis\", item_id = \"iapis\" }",
        "boundaries.api = { vault_id = \"vapis\", item_id = \"iapis\" }\n\
         boundaries.worker = { vault_id = \"vwrks\", item_id = \"iwrks\" }",
    );
    assert_eq!(
        refused_field(&text),
        "environments.prod.targets.box.sealed.out"
    );
}

#[test]
fn two_targets_rendering_one_bundle_path_are_refused() {
    let text = prod_with("sealed/prod/{product}", "sealed/{product}").replacen(
        "sealed/staging/{product}",
        "sealed/api",
        1,
    );
    assert_eq!(
        refused_field(&text),
        "environments.staging.targets.box.sealed.out"
    );
}

#[test]
fn the_bundle_path_resolves_under_the_sealed_root_when_given() {
    let sealed = sealed_of(&example(), "prod");
    assert_eq!(
        sealed.bundle_path("api", Some(Path::new("/checkout/store"))),
        PathBuf::from("/checkout/store/sealed/prod/api.opv-sealed")
    );
}

#[test]
fn the_bundle_path_is_relative_to_the_configuration_without_a_root() {
    let sealed = sealed_of(&example(), "prod");
    assert_eq!(
        sealed.bundle_path("api", None),
        PathBuf::from("sealed/prod/api.opv-sealed")
    );
}

// --- names (§3.1-6) -------------------------------------------------------------------------

#[test]
fn an_env_name_without_key_is_refused() {
    assert_eq!(
        refused_field(&prod_with(
            "sealed.env_name = \"{KEY}\"",
            "sealed.env_name = \"APP\""
        )),
        "environments.prod.targets.box.sealed.env_name"
    );
}

#[test]
fn an_env_name_rendering_op_names_is_refused() {
    assert_eq!(
        refused_field(
            &prod_with(
                "sealed.env_name = \"{KEY}\"",
                "sealed.env_name = \"{PRODUCT}_{KEY}\""
            )
            .replace("[products.api.keys", "[products.op.keys")
            .replace("boundaries.api", "boundaries.op")
        ),
        "environments.prod.targets.box.sealed.env_name"
    );
}

// --- deploy_credentials and what is never sealed (§3.1-7, §3.1-8, G4, T14) -----------------

#[test]
fn a_sealed_target_without_deploy_credentials_is_refused() {
    assert_eq!(
        refused_field(&prod_with(
            "deploy_credentials = \"op://Ops Prod/opv-sealed-prod-signer\"\n",
            ""
        )),
        "environments.prod.targets.box.deploy_credentials"
    );
}

#[test]
fn a_key_read_from_the_deploy_credentials_item_is_refused() {
    assert_eq!(
        refused_field(&prod_with(
            "op://Ops Prod/opv-sealed-prod-signer",
            "op://vapi/iapi"
        )),
        "products.api.keys.DATABASE_URL"
    );
}

#[test]
fn an_age_identity_key_is_refused() {
    let text = format!(
        "{}\n[products.api.keys.OPV_SEALED_IDENTITY]\nkind = \"secret\"\nrules = {{ age_identity = true }}\n",
        example()
    );
    assert_eq!(
        refused_field(&text),
        "products.api.keys.OPV_SEALED_IDENTITY"
    );
}

#[test]
fn a_key_shared_from_an_age_identity_is_refused() {
    let text = format!(
        "{}\n[products.api.keys.OPV_SEALED_IDENTITY]\nkind = \"secret\"\nenvironments = [\"staging\"]\n\
         rules = {{ age_identity = true }}\n\
         [products.api.keys.IDENTITY_COPY]\nkind = \"secret\"\nenvironments = [\"staging\"]\n\
         from = \"api/OPV_SEALED_IDENTITY\"\n",
        example()
    );
    assert!(matches!(
        refused_field(&text).as_str(),
        "products.api.keys.IDENTITY_COPY" | "products.api.keys.OPV_SEALED_IDENTITY"
    ));
}

// --- #287: an infrastructure key is sealed from the value supplied at sync --------------------

/// `api` gains `DB_URL`, supplied at sync (`source = "infrastructure"`) in staging.
fn with_infrastructure_key() -> String {
    format!(
        "{}\n[products.api.keys.DB_URL]\nkind = \"secret\"\nsource = \"infrastructure\"\n\
         environments = [\"staging\"]\nrules = {{ regex = \"postgres://.+\" }}\n",
        example()
    )
}

/// #287 (was refused at load by #275): the value comes from `opv sync --supply-stdin`.
#[test]
fn an_infrastructure_key_a_sealed_target_delivers_loads() {
    let text = with_infrastructure_key();
    assert!(
        crate::config::parse(&text).is_ok(),
        "{:?}",
        crate::config::parse(&text)
            .err()
            .map(|e| e.parts().0.message())
    );
}

#[test]
fn an_infrastructure_key_of_a_product_no_sealed_target_delivers_loads() {
    let text = with_infrastructure_key()
        .replace("products.api.keys.DB_URL", "products.worker.keys.DB_URL")
        .replace(
            "boundaries.api = { vault_id = \"vapis\", item_id = \"iapis\" }",
            "boundaries.api = { vault_id = \"vapis\", item_id = \"iapis\" }\n\
             boundaries.worker = { vault_id = \"vwrks\", item_id = \"iwrks\" }",
        )
        .replace(
            "[environments.staging.targets.box]\n",
            "[environments.staging.targets.box]\nproducts = [\"api\"]\n",
        )
        + "\n[environments.staging.targets.jobs]\nfly.app = \"jobs-staging\"\n\
           fly.secret_name = \"{KEY}\"\nproducts = [\"worker\"]\nstate_vault_id = \"sjobs\"\n";
    assert!(
        crate::config::parse(&text).is_ok(),
        "{:?}",
        crate::config::parse(&text)
            .err()
            .map(|e| e.parts().0.message())
    );
}

// --- channels (§3.2, T5) ----------------------------------------------------------------------

#[test]
fn file_keys_of_two_products_load_on_one_sealed_target() {
    let text = format!(
        "{}\n[products.api.local]\nsecrets_dir_env = \"APP_SECRETS_DIR\"\n\
         [products.api.keys.TLS_KEY]\nkind = \"secret\"\nfile = \"tls/key\"\n\
         [products.worker.local]\nsecrets_dir_env = \"APP_SECRETS_DIR\"\n\
         [products.worker.keys.TLS_CERT]\nkind = \"secret\"\nfile = \"tls/key\"\n",
        example()
    )
    .replace(
        "boundaries.api = { vault_id = \"vapi\", item_id = \"iapi\" }",
        "boundaries.api = { vault_id = \"vapi\", item_id = \"iapi\" }\n\
         boundaries.worker = { vault_id = \"vwrk\", item_id = \"iwrk\" }",
    )
    .replace(
        "boundaries.api = { vault_id = \"vapis\", item_id = \"iapis\" }",
        "boundaries.api = { vault_id = \"vapis\", item_id = \"iapis\" }\n\
         boundaries.worker = { vault_id = \"vwrks\", item_id = \"iwrks\" }",
    );
    let loaded = crate::config::parse(&text)
        .map(|_| ())
        .map_err(|e| e.text());
    assert_eq!(loaded, Ok(()));
}
