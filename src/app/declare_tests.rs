//! #133: declarations edit the local configuration only, before or after bootstrap.

use super::*;
use crate::runner::fake::FakeRunner;

/// Declared, not bootstrapped: no boundary or state vault is recorded yet.
const FRESH: &str = "[environments.dev]\n\n[environments.prod]\n\n[products.api.keys.API_TOKEN]\nkind = \"secret\"\nenvironments = [\"dev\", \"prod\"]\n";

fn file(text: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    std::fs::write(&path, text).unwrap();
    (dir, path)
}

fn text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn key_decl(product: &str, key: &str) -> Key {
    Key {
        product: product.into(),
        key: key.into(),
        kind: "secret".into(),
        environments: vec!["prod".into()],
        guidance: Some("from the Stripe dashboard".into()),
        ..Key::default()
    }
}

fn fly_target(name: &str) -> Target {
    Target {
        environment: "prod".into(),
        name: name.into(),
        provider: Some("fly".into()),
        fields: [("fly-app".to_string(), format!("myapp-{name}"))].into(),
        products: vec!["api".into()],
        roles: vec![],
    }
}

/// Declared, with a key only the `serve` process reads: every target that delivers it must
/// declare its `roles`.
const ROLE_SCOPED: &str = "[environments.prod]\n\n[products.api.keys.API_TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\nroles = [\"serve\"]\n";

fn kubernetes_target(secrets_dir: &str) -> Target {
    Target {
        environment: "prod".into(),
        name: "cluster".into(),
        provider: Some("kubernetes".into()),
        fields: [
            ("kubernetes-context", "ctx"),
            ("kubernetes-namespace", "app"),
            ("kubernetes-deployment", "web"),
            ("kubernetes-secrets-dir", secrets_dir),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
        products: vec!["api".into()],
        roles: vec![],
    }
}

#[test]
fn a_key_is_declared_before_bootstrap() {
    let (_d, path) = file(FRESH);
    key(
        &FakeRunner::default(),
        &path,
        &key_decl("billing", "STRIPE_KEY"),
    )
    .unwrap();
    assert!(text(&path).contains("[products.billing.keys.STRIPE_KEY]"));
}

#[test]
fn a_declared_key_carries_its_guidance() {
    let (_d, path) = file(FRESH);
    key(
        &FakeRunner::default(),
        &path,
        &key_decl("billing", "STRIPE_KEY"),
    )
    .unwrap();
    assert!(text(&path).contains("from the Stripe dashboard"));
}

#[test]
fn declaring_a_key_runs_nothing() {
    let (_d, path) = file(FRESH);
    let r = FakeRunner::default();
    key(&r, &path, &key_decl("billing", "STRIPE_KEY")).unwrap();
    assert!(r.calls.borrow().is_empty());
}

#[test]
fn guidance_on_several_lines_is_refused() {
    let (_d, path) = file(FRESH);
    let mut k = key_decl("billing", "STRIPE_KEY");
    k.guidance = Some("line one\nline two".into());
    assert!(key(&FakeRunner::default(), &path, &k).is_err());
}

#[test]
fn an_unknown_kind_is_refused() {
    let (_d, path) = file(FRESH);
    let mut k = key_decl("billing", "STRIPE_KEY");
    k.kind = "password".into();
    assert!(key(&FakeRunner::default(), &path, &k).is_err());
}

#[test]
fn an_environment_is_declared() {
    let (_d, path) = file(FRESH);
    environment(&FakeRunner::default(), &path, "staging").unwrap();
    assert!(environments(&path).unwrap().contains("staging"));
}

#[test]
fn declaring_an_existing_environment_changes_nothing() {
    let (_d, path) = file(FRESH);
    assert!(!environment(&FakeRunner::default(), &path, "dev").unwrap());
}

#[test]
fn a_target_is_declared_without_a_state_vault() {
    let (_d, path) = file(FRESH);
    target(&FakeRunner::default(), &path, &fly_target("web")).unwrap();
    assert!(
        text(&path).contains("[environments.prod.targets.web]")
            && !text(&path).contains("state_vault_id")
    );
}

#[test]
fn a_declared_target_is_planned_a_state_vault() {
    let (_d, path) = file(FRESH);
    target(&FakeRunner::default(), &path, &fly_target("web")).unwrap();
    let envs = super::super::bootstrap::plan(
        &crate::adapters::fake_op::FakeOp::default(),
        &text(&path),
        "myapp",
        &BTreeSet::new(),
    )
    .unwrap();
    let prod = envs.iter().find(|e| e.environment == "prod").unwrap();
    assert_eq!(prod.state_vaults[0].target, "web");
}

#[test]
fn an_existing_target_is_never_changed() {
    let (_d, path) = file(FRESH);
    target(&FakeRunner::default(), &path, &fly_target("web")).unwrap();
    let mut again = fly_target("web");
    again.fields = [("fly-app".to_string(), "someone-elses-app".to_string())].into();
    target(&FakeRunner::default(), &path, &again).unwrap();
    assert!(!text(&path).contains("someone-elses-app"));
}

#[test]
fn a_deploy_credential_is_never_declared() {
    let (_d, path) = file(FRESH);
    let mut t = fly_target("web");
    t.fields
        .insert("deploy-credentials".into(), "op://v/i".into());
    assert!(target(&FakeRunner::default(), &path, &t).is_err());
}

#[test]
fn a_generated_configuration_is_never_edited() {
    let (_d, path) = file(&format!("# generated by infra\n{FRESH}"));
    let e = key(
        &FakeRunner::default(),
        &path,
        &key_decl("billing", "STRIPE_KEY"),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "config_not_editable");
}

/// 05.19: a key for an undeclared environment names it; init --add-env is never the step.
#[test]
fn a_key_for_an_undeclared_environment_is_unknown_env() {
    let (_d, path) = file(FRESH);
    let mut k = key_decl("billing", "STRIPE_KEY");
    k.environments = vec!["staging".into()];
    let e = key(&FakeRunner::default(), &path, &k).unwrap_err();
    assert_eq!(e.code_str(), "unknown_env");
}

/// 05.19: its step lists the declared environments.
#[test]
fn a_key_for_an_undeclared_environment_steps_to_the_configuration() {
    let (_d, path) = file(FRESH);
    let mut k = key_decl("billing", "STRIPE_KEY");
    k.environments = vec!["staging".into()];
    let e = key(&FakeRunner::default(), &path, &k).unwrap_err();
    assert_eq!(e.next_text().unwrap_or_default(), "opv config describe");
}

#[test]
fn a_target_is_declared_with_its_roles() {
    let (_d, path) = file(ROLE_SCOPED);
    let mut t = fly_target("web");
    t.roles = vec!["serve".into()];
    target(&FakeRunner::default(), &path, &t).unwrap();
    assert!(
        text(&path).contains("roles = [\"serve\"]\n"),
        "{}",
        text(&path)
    );
}

#[test]
fn a_target_without_roles_for_a_role_scoped_key_is_config_invalid() {
    let (_d, path) = file(ROLE_SCOPED);
    let e = target(&FakeRunner::default(), &path, &fly_target("web")).unwrap_err();
    assert_eq!(e.code_str(), "config_invalid");
}

#[test]
fn a_kubernetes_target_is_declared_with_its_secrets_dir() {
    let (_d, path) = file(FRESH);
    target(
        &FakeRunner::default(),
        &path,
        &kubernetes_target("/run/secrets/{product}"),
    )
    .unwrap();
    assert!(
        text(&path).contains("kubernetes.secrets_dir = \"/run/secrets/{product}\"\n"),
        "{}",
        text(&path)
    );
}

#[test]
fn a_relative_secrets_dir_is_config_invalid() {
    let (_d, path) = file(FRESH);
    let e = target(
        &FakeRunner::default(),
        &path,
        &kubernetes_target("run/secrets"),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "config_invalid");
}

#[test]
fn a_relative_secrets_dir_refusal_names_the_field() {
    let (_d, path) = file(FRESH);
    let e = target(
        &FakeRunner::default(),
        &path,
        &kubernetes_target("run/secrets"),
    )
    .unwrap_err();
    assert!(e.mentions("kubernetes.secrets_dir"), "{}", e.text());
}

#[test]
fn a_refused_secrets_dir_is_never_written() {
    let (_d, path) = file(FRESH);
    let _ = target(
        &FakeRunner::default(),
        &path,
        &kubernetes_target("run/secrets"),
    );
    assert_eq!(text(&path), FRESH);
}

#[test]
fn a_fly_target_is_declared_with_its_config_route() {
    let (_d, path) = file(FRESH);
    let mut t = fly_target("web");
    t.fields.insert("fly-config".into(), "secrets".into());
    target(&FakeRunner::default(), &path, &t).unwrap();
    assert!(
        text(&path).contains("fly.config = \"secrets\"\n"),
        "{}",
        text(&path)
    );
}
