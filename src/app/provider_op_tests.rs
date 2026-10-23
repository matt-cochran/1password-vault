//! Step 0 of target operations (#234 §11): every step refuses as not yet available, with
//! opv's policy code and no call of any program. One assertion each.

use super::*;
use crate::runner::fake::FakeRunner;

fn request() -> Request {
    Request {
        env: "prod".into(),
        target: "web".into(),
        op: Operation::RegistryPush,
        image: Some("registry.fly.io/shop:v1".into()),
        machine: None,
        confirm: None,
    }
}

fn admitted() -> Admitted {
    Admitted {
        env: "prod".into(),
        target: "web".into(),
        app: "shop".into(),
        credentials: ItemRef {
            vault: "vprod".into(),
            item: "ideploy".into(),
        },
        op: Operation::MachineUpdate,
        image: None,
        machine: None,
        docker_endpoint: None,
    }
}

fn fleet() -> Fleet {
    crate::config::parse(
        r#"[environments.prod]
boundaries.core = { vault_id = "vprod", item_id = "iprod" }

[products.api]
boundary = "core"

[products.api.keys.STRIPE_KEY]
kind = "secret"
environments = ["prod"]
"#,
    )
    .expect("config")
}

#[test]
fn admission_is_refused_by_policy_until_operations_ship() {
    let e = admit(&fleet(), &request(), &Host::detect()).unwrap_err();
    assert_eq!(e.code_str(), "policy_refused");
}

#[test]
fn a_refused_operation_exits_with_the_policy_exit_code() {
    let e = execute(&admitted(), &FakeRunner::default()).unwrap_err();
    assert_eq!(e.exit_code(), 6);
}

#[test]
fn the_refusal_names_the_operation_and_its_target() {
    let e = execute(&admitted(), &FakeRunner::default()).unwrap_err();
    assert!(
        e.text().contains("machine-update on prod/web"),
        "{}",
        e.text()
    );
}

#[test]
fn preflight_calls_no_program() {
    let r = FakeRunner::default();
    let _ = preflight(&mut admitted(), &r);
    assert!(r.calls.borrow().is_empty());
}
