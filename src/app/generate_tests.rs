//! `opv generate`: self-made secrets into 1Password, never shown, never over a value.

use super::*;
use crate::adapters::fake_op::FakeOp;

const FLEET: &str = r#"[environments.dev]
boundaries.api = { vault_id = "vdev0000000000000000000001", item_id = "ITEM" }

[products.api.local]
secrets_dir_env = "API_SECRET_FILES"

[products.api.keys.SESSION_KEY]
kind = "secret"
environments = ["dev"]
rules = { base64_bytes = 32 }

[products.api.keys.WEBHOOK_HEX]
kind = "secret"
environments = ["dev"]
rules = { hex_bytes = 32 }

[products.api.keys.STRIPE_KEY]
kind = "secret"
environments = ["dev"]
rules = { prefix = "sk_" }

[products.api.keys.PLAIN]
kind = "secret"
environments = ["dev"]

[products.api.keys.OPV_SEALED_IDENTITY]
kind = "secret"
source = "generated"
environments = ["dev"]
rules = { age_identity = true }

[products.api.keys.SIGNING_IDENTITY]
kind = "secret"
source = "generated"
file = "signing-key"
rules = { ssh_ed25519 = true }
"#;

/// A fake whose dev item already holds `api/WEBHOOK_HEX` = `already-set`.
fn world() -> (crate::domain::Fleet, FakeOp, String) {
    let op = FakeOp::default();
    op.signed_in.set(true);
    let id = op.insert(
        "vdev0000000000000000000001",
        serde_json::json!({
            "title": "myapp · api · dev values", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [{"id": "f1", "label": "WEBHOOK_HEX", "type": "CONCEALED",
                        "section": {"id": "api", "label": "api"}, "value": "already-set"}],
        }),
    );
    let fleet = crate::config::parse(&FLEET.replace("ITEM", &id)).unwrap();
    (fleet, op, id)
}

fn spec(fleet: &crate::domain::Fleet, key: &str) -> KeySpec {
    fleet.products["api"].keys[key].clone()
}

fn field(op: &FakeOp, id: &str, label: &str) -> Option<String> {
    op.item(id)["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == label)
        .and_then(|f| f["value"].as_str().map(str::to_string))
}

#[test]
fn a_base64_key_is_generated_as_base64() {
    let (fleet, _, _) = world();
    assert_eq!(
        recipe("api", "SESSION_KEY", "dev", &spec(&fleet, "SESSION_KEY")).unwrap(),
        Recipe::Base64(32)
    );
}

// st-g1 (sealed-target §7.1): an `age_identity = true` key is made in memory and only
// its public recipient is shown, so it can go into `sealed.recipients`.

#[test]
fn an_age_identity_key_gets_the_age_identity_recipe() {
    let (fleet, _, _) = world();
    assert_eq!(
        recipe(
            "api",
            "OPV_SEALED_IDENTITY",
            "dev",
            &spec(&fleet, "OPV_SEALED_IDENTITY")
        )
        .unwrap(),
        Recipe::AgeIdentity
    );
}

#[test]
fn a_generated_age_identity_parses_as_an_age_x25519_identity() {
    let v = make(Recipe::AgeIdentity).unwrap();
    assert!(crate::bundle::crypto::parse_identity(v.expose()).is_ok());
}

#[test]
fn the_age_identity_recipe_names_itself() {
    assert!(
        Recipe::AgeIdentity
            .describe()
            .contains("age X25519 identity")
    );
}

// #294: an `ssh_ed25519 = true` key is a fresh Ed25519 OpenSSH keypair.

#[test]
fn an_ssh_ed25519_key_gets_the_ssh_ed25519_recipe() {
    let s = session_key_with(|s| {
        s.rules.base64_bytes = None;
        s.rules.ssh_ed25519 = true;
        s.file = Some("signing-key".into());
    });
    assert_eq!(
        recipe("api", "SESSION_KEY", "dev", &s).unwrap(),
        Recipe::SshEd25519
    );
}

#[test]
fn the_ssh_ed25519_recipe_names_itself() {
    assert_eq!(Recipe::SshEd25519.describe(), "an Ed25519 OpenSSH key");
}

#[test]
fn an_age_identity_prints_its_recipient() {
    let (fleet, op, id) = world();
    let mut out = Vec::new();
    run(
        &fleet,
        "dev",
        &["api/OPV_SEALED_IDENTITY".into()],
        &op,
        &mut out,
    )
    .unwrap();
    let recipient =
        crate::bundle::crypto::parse_identity(&field(&op, &id, "OPV_SEALED_IDENTITY").unwrap())
            .unwrap()
            .recipient()
            .to_string();
    assert!(
        String::from_utf8(out)
            .unwrap()
            .lines()
            .any(|line| line == recipient)
    );
}

#[test]
fn an_age_identity_never_prints_the_identity() {
    let (fleet, op, id) = world();
    let mut out = Vec::new();
    run(
        &fleet,
        "dev",
        &["api/OPV_SEALED_IDENTITY".into()],
        &op,
        &mut out,
    )
    .unwrap();
    let identity = field(&op, &id, "OPV_SEALED_IDENTITY").unwrap();
    assert!(!String::from_utf8(out).unwrap().contains(&identity));
}

#[test]
fn a_provider_key_with_a_prefix_is_refused() {
    let (fleet, _, _) = world();
    assert!(recipe("api", "STRIPE_KEY", "dev", &spec(&fleet, "STRIPE_KEY")).is_err());
}

/// #157: policy_refused exits 6 (policy), as its code says.
#[test]
fn a_refused_key_exits_as_its_code_says() {
    let (fleet, _, _) = world();
    let e = recipe("api", "STRIPE_KEY", "dev", &spec(&fleet, "STRIPE_KEY")).unwrap_err();
    assert!(
        crate::cause::codes::table()
            .iter()
            .any(|r| r.code == e.code_str() && r.exits.contains(&e.exit_code()))
    );
}

#[test]
fn a_key_without_a_byte_length_is_refused() {
    let (fleet, _, _) = world();
    assert!(recipe("api", "PLAIN", "dev", &spec(&fleet, "PLAIN")).is_err());
}

#[test]
fn a_base64_value_decodes_to_its_byte_count() {
    let v = make(Recipe::Base64(32)).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(v.expose())
        .unwrap();
    assert_eq!(bytes.len(), 32);
}

#[test]
fn a_hex_value_has_two_digits_per_byte() {
    assert_eq!(make(Recipe::Hex(32)).unwrap().expose().len(), 64);
}

#[test]
fn two_generated_values_differ() {
    assert_ne!(
        make(Recipe::Base64(32)).unwrap().expose(),
        make(Recipe::Base64(32)).unwrap().expose()
    );
}

#[test]
fn a_generated_value_passes_its_keys_rules() {
    let (fleet, _, _) = world();
    let v = make(Recipe::Base64(32)).unwrap();
    let ok = crate::domain::rules::check(
        "api",
        "SESSION_KEY",
        &spec(&fleet, "SESSION_KEY"),
        "dev",
        fleet.environment("dev").unwrap(),
        &v,
    );
    assert!(ok.is_ok());
}

#[test]
fn generate_writes_the_value_into_1password() {
    let (fleet, op, id) = world();
    run(
        &fleet,
        "dev",
        &["api/SESSION_KEY".into()],
        &op,
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(field(&op, &id, "SESSION_KEY").map(|v| v.len()), Some(44));
}

#[test]
fn generate_never_shows_the_value() {
    let (fleet, op, id) = world();
    let mut out = Vec::new();
    run(&fleet, "dev", &["api/SESSION_KEY".into()], &op, &mut out).unwrap();
    let value = field(&op, &id, "SESSION_KEY").unwrap();
    assert!(!String::from_utf8(out).unwrap().contains(&value));
}

#[test]
fn a_filled_field_is_never_replaced() {
    let (fleet, op, id) = world();
    let _ = run(
        &fleet,
        "dev",
        &["api/WEBHOOK_HEX".into()],
        &op,
        &mut Vec::new(),
    );
    assert_eq!(
        field(&op, &id, "WEBHOOK_HEX").as_deref(),
        Some("already-set")
    );
}

#[test]
fn one_refused_key_writes_nothing_for_the_others() {
    let (fleet, op, id) = world();
    let _ = run(
        &fleet,
        "dev",
        &["api/SESSION_KEY".into(), "api/STRIPE_KEY".into()],
        &op,
        &mut Vec::new(),
    );
    assert_eq!(field(&op, &id, "SESSION_KEY"), None);
}

#[test]
fn an_undeclared_key_is_refused() {
    let (fleet, op, _) = world();
    let e = run(&fleet, "dev", &["api/NOPE".into()], &op, &mut Vec::new()).unwrap_err();
    assert_eq!(e.code_str(), "undeclared_key");
}

// 05.11 (S2): each refusal says its own reason ------------------------------------------

fn why_of(e: &Error) -> &'static str {
    match e.cause() {
        Some((
            Cause::Guard {
                guard: Guard::GenerateRefused { reason, .. },
            },
            _,
        )) => reason.words(),
        _ => "",
    }
}

/// `api/SESSION_KEY` (base64, 32 bytes) changed by `f`.
fn session_key_with(f: impl FnOnce(&mut KeySpec)) -> KeySpec {
    let (fleet, _, _) = world();
    let mut s = spec(&fleet, "SESSION_KEY");
    f(&mut s);
    s
}

#[test]
fn a_personal_key_is_refused_as_personal() {
    let s = session_key_with(|s| s.personal = true);
    let e = recipe("api", "SESSION_KEY", "dev", &s).unwrap_err();
    assert!(why_of(&e).contains("personal"), "{e}");
}

// R4 (#293/#294): one `KeySpec` predicate decides the generate shape, and `recipe()`
// agrees with it: an identity rule never makes a personal or shared key generatable.

#[test]
fn a_personal_age_identity_key_has_no_generate_recipe() {
    let s = session_key_with(|s| {
        s.personal = true;
        s.rules.base64_bytes = None;
        s.rules.age_identity = true;
    });
    assert!(!s.has_generate_recipe());
}

#[test]
fn a_personal_age_identity_key_is_refused_as_personal() {
    let s = session_key_with(|s| {
        s.personal = true;
        s.rules.base64_bytes = None;
        s.rules.age_identity = true;
    });
    let e = recipe("api", "SESSION_KEY", "dev", &s).unwrap_err();
    assert!(why_of(&e).contains("personal"), "{e}");
}

#[test]
fn a_shared_ssh_ed25519_key_has_no_generate_recipe() {
    let s = session_key_with(|s| {
        s.from = Some("api/SESSION_KEY".into());
        s.rules.base64_bytes = None;
        s.rules.ssh_ed25519 = true;
    });
    assert!(!s.has_generate_recipe());
}

#[test]
fn a_shared_ssh_ed25519_key_is_refused_as_shared() {
    let s = session_key_with(|s| {
        s.from = Some("api/SESSION_KEY".into());
        s.rules.base64_bytes = None;
        s.rules.ssh_ed25519 = true;
    });
    let e = recipe("api", "SESSION_KEY", "dev", &s).unwrap_err();
    assert_eq!(
        why_of(&e),
        GenerateRefusal::Shared {
            from: "api/SESSION_KEY".into()
        }
        .words()
    );
}

#[test]
fn a_byte_count_out_of_range_is_refused_naming_the_range() {
    let s = session_key_with(|s| s.rules.base64_bytes = Some(8));
    let e = recipe("api", "SESSION_KEY", "dev", &s).unwrap_err();
    assert!(why_of(&e).contains("16 and 1024"), "{e}");
}

#[test]
fn a_refusal_names_the_environment() {
    let (fleet, _, _) = world();
    let e = recipe("api", "STRIPE_KEY", "dev", &spec(&fleet, "STRIPE_KEY")).unwrap_err();
    assert!(matches!(
        e.cause(),
        Some((Cause::Guard { guard: Guard::GenerateRefused { env, .. } }, _))
            if env.as_str() == "dev"
    ));
}

#[test]
fn a_filled_field_is_refused_as_already_holding_a_value() {
    let (fleet, op, _) = world();
    let e = run(
        &fleet,
        "dev",
        &["api/WEBHOOK_HEX".into()],
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(why_of(&e).contains("already holds a value"), "{e}");
}

// 05.39 (S3): argument errors carry their own codes --------------------------------------

#[test]
fn a_key_without_its_product_is_a_usage_error() {
    let (fleet, op, _) = world();
    let e = run(&fleet, "dev", &["SESSION_KEY".into()], &op, &mut Vec::new()).unwrap_err();
    assert_eq!(e.code_str(), "usage");
}

#[test]
fn a_failed_random_source_is_opvs_own_local_io() {
    // F2: the OS random source is local I/O, never a missing tool.
    assert_eq!(random_source_failed().code_str(), "local_io_failed");
}

/// #206 §4.4: an infrastructure key is never generated, even when its shape rule gives a
/// byte count.
#[test]
fn an_infrastructure_key_is_refused_as_infrastructure() {
    let s = session_key_with(|s| s.value_source = Some(crate::domain::ValueSource::Infrastructure));
    let e = recipe("api", "SESSION_KEY", "dev", &s).unwrap_err();
    assert_eq!(why_of(&e), GenerateRefusal::Infrastructure.words());
}

// A set member is written only together with its set (#253 §5.6; test 29): `generate`
// refuses it from the configuration alone, before any 1Password call.

/// A dev fleet where api/SESSION_KEY is a member of the set `grant`.
fn set_world() -> (crate::domain::Fleet, FakeOp) {
    let op = FakeOp::default();
    op.signed_in.set(true);
    let id = op.insert(
        "vdev0000000000000000000001",
        serde_json::json!({
            "title": "myapp · api · dev values", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": []
        }),
    );
    let fleet = crate::config::parse(&format!(
        "[environments.dev]\nboundaries.api = {{ vault_id = \"vdev0000000000000000000001\", \
         item_id = \"{id}\" }}\n\
         [products.api.keys.SESSION_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n\
         rules = {{ base64_bytes = 32 }}\n\
         [sets.grant]\nenvironments = [\"dev\"]\n\
         members = {{ \"api/SESSION_KEY\" = {{ generate = \"rules\" }} }}\n"
    ))
    .unwrap();
    (fleet, op)
}

#[test]
fn a_set_member_is_refused_as_a_set_member() {
    let (fleet, op) = set_world();
    let e = run(
        &fleet,
        "dev",
        &["api/SESSION_KEY".into()],
        &op,
        &mut Vec::new(),
    )
    .unwrap_err();
    let doc = crate::error::document(&e, &crate::error::invocation(), false);
    assert_eq!(doc["subject"]["guard"]["guard"], "set_member");
}

#[test]
fn a_set_member_refusal_runs_no_op_command() {
    let (fleet, op) = set_world();
    let _ = run(
        &fleet,
        "dev",
        &["api/SESSION_KEY".into()],
        &op,
        &mut Vec::new(),
    );
    assert!(op.calls.borrow().is_empty());
}

#[test]
fn declared_generated_structured_identities_load_and_share_the_recipe_guards() {
    let (fleet, _, _) = world();
    for (key, expected) in [
        ("OPV_SEALED_IDENTITY", Recipe::AgeIdentity),
        ("SIGNING_IDENTITY", Recipe::SshEd25519),
    ] {
        let base = spec(&fleet, key);
        assert!(base.has_generate_recipe());
        assert_eq!(recipe("api", key, "dev", &base).unwrap(), expected);
        for mutate in [
            (|s: &mut KeySpec| s.personal = true) as fn(&mut KeySpec),
            |s: &mut KeySpec| s.from = Some("api/SESSION_KEY".into()),
            |s: &mut KeySpec| s.rules.prefix = Some("provider_".into()),
        ] {
            let mut refused = base.clone();
            mutate(&mut refused);
            assert!(!refused.has_generate_recipe());
            assert!(recipe("api", key, "dev", &refused).is_err());
        }
    }
}

#[test]
fn an_ed25519_generated_file_key_signs_and_verifies_without_granting_trust() {
    let value = make(Recipe::SshEd25519).unwrap();
    let private = ssh_key::PrivateKey::from_openssh(value.expose()).unwrap();
    assert_eq!(private.algorithm(), ssh_key::Algorithm::Ed25519);
    assert!(!private.is_encrypted());
    let signature = private
        .sign(
            "opv-disposable-test",
            ssh_key::HashAlg::Sha256,
            b"fictional test message",
        )
        .unwrap();
    private
        .public_key()
        .verify("opv-disposable-test", b"fictional test message", &signature)
        .unwrap();
    assert!(
        private
            .public_key()
            .verify("different-namespace", b"fictional test message", &signature)
            .is_err()
    );
    let other = make(Recipe::SshEd25519).unwrap();
    assert!(
        value.expose() != other.expose(),
        "independent identities must differ"
    );
}

#[test]
fn ed25519_generation_stores_multiline_bytes_and_reports_only_public_metadata() {
    let (fleet, op, id) = world();
    let mut output = Vec::new();
    run(
        &fleet,
        "dev",
        &["api/SIGNING_IDENTITY".into()],
        &op,
        &mut output,
    )
    .unwrap();
    let stored = field(&op, &id, "SIGNING_IDENTITY").unwrap();
    let private = ssh_key::PrivateKey::from_openssh(&stored).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(stored.ends_with('\n'));
    assert!(text.contains(&private.public_key().to_openssh().unwrap()));
    assert!(
        text.contains(
            &private
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string()
        )
    );
    assert!(!text.contains("BEGIN OPENSSH PRIVATE KEY"));
    assert!(!text.contains(&stored));
    assert!(
        op.calls
            .borrow()
            .iter()
            .all(|call| call.args.iter().all(|arg| !arg.contains(&stored)))
    );
    let before = op.count(&["op", "item", "edit"]);
    assert!(
        run(
            &fleet,
            "dev",
            &["api/SIGNING_IDENTITY".into()],
            &op,
            &mut Vec::new()
        )
        .is_err()
    );
    assert_eq!(op.count(&["op", "item", "edit"]), before);
    assert!(
        field(&op, &id, "SIGNING_IDENTITY").as_deref() == Some(stored.as_str()),
        "existing identity must be preserved"
    );
}

#[test]
fn structured_rules_validate_actual_bytes_including_private_file_delivery() {
    let (fleet, _, _) = world();
    for (name, recipe) in [
        ("OPV_SEALED_IDENTITY", Recipe::AgeIdentity),
        ("SIGNING_IDENTITY", Recipe::SshEd25519),
    ] {
        let spec = spec(&fleet, name);
        let valid = make(recipe).unwrap();
        let check = |value: &SecretValue| {
            crate::domain::rules::check_verbatim(
                "api",
                name,
                &spec,
                "dev",
                fleet.environment("dev").unwrap(),
                value,
                spec.file.is_some(),
            )
        };
        assert!(check(&valid).is_ok());
        let invalid = SecretValue::new("fictional-invalid-private-material".into());
        let failure = check(&invalid).unwrap_err();
        assert!(!format!("{failure:?}").contains(invalid.expose()));
        if recipe == Recipe::SshEd25519 {
            assert!(
                crate::domain::rules::check(
                    "api",
                    name,
                    &spec,
                    "dev",
                    fleet.environment("dev").unwrap(),
                    &valid
                )
                .is_err()
            );
        }
    }
}

#[test]
fn conflicting_generation_formats_and_nonsecret_or_nonfile_ssh_are_refused_at_load() {
    for rules in [
        "age_identity = true, ssh_ed25519 = true",
        "age_identity = true, base64_bytes = 32",
        "ssh_ed25519 = true, hex_bytes = 32",
    ] {
        let text = FLEET.replace(
            "rules = { ssh_ed25519 = true }",
            &format!("rules = {{ {rules} }}"),
        );
        assert!(crate::config::parse(&text).is_err());
    }
    assert!(crate::config::parse(&FLEET.replace("file = \"signing-key\"\n", "")).is_err());
    assert!(
        crate::config::parse(&FLEET.replace(
            "[products.api.keys.SIGNING_IDENTITY]\nkind = \"secret\"",
            "[products.api.keys.SIGNING_IDENTITY]\nkind = \"config\""
        ))
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn a_generated_ed25519_key_is_delivered_byte_exact_in_a_private_file() {
    use std::os::unix::fs::PermissionsExt;
    let value = make(Recipe::SshEd25519).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let open = crate::app::local_delivery::OpenDir::open_private(dir.path()).unwrap();
    crate::app::local_delivery::write_file(&open, "signing-key", value.expose().as_bytes())
        .unwrap();
    let path = dir.path().join("signing-key");
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        bytes == value.expose().as_bytes(),
        "file delivery must preserve all private bytes"
    );
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o400
    );
    let private = ssh_key::PrivateKey::from_openssh(bytes).unwrap();
    assert_eq!(private.algorithm(), ssh_key::Algorithm::Ed25519);
}

#[test]
fn structured_generation_is_supported_for_team_shared_and_production_tiers() {
    for tier in ["shared", "production"] {
        let text = FLEET.replace(
            "[environments.dev]",
            &format!("[environments.dev]\ntier = \"{tier}\""),
        );
        let fleet = crate::config::parse(&text).unwrap();
        for key in ["OPV_SEALED_IDENTITY", "SIGNING_IDENTITY"] {
            assert!(recipe("api", key, "dev", &spec(&fleet, key)).is_ok());
        }
    }
}
