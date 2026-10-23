//! Behaviour of the Fly Machines operations (#234, `docs/design/provider-operations.md` §2,
//! §5.2): one declarative scenario and one assertion each.

use super::*;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const ID: &str = "8edd22dc379d68";
const IMAGE: &str = "registry.fly.io/shop:v1";
const MARK: &str = "sk-proj-LEAKCANARY";

// unrecorded: built from flyctl docs, replace with the first real reply (#234 §8.1)
const LISTING: &str = r#"[
  {
    "id": "8edd22dc379d68",
    "name": "opv-canary",
    "state": "started",
    "region": "iad",
    "instance_id": "01HZ",
    "private_ip": "fdaa:0:1::2",
    "config": {
      "image": "registry.fly.io/shop:deployment-01",
      "env": { "OPVCANARY": "sk-proj-LEAKCANARY" },
      "metadata": { "fly_platform_version": "v2" }
    },
    "image_ref": {
      "registry": "registry.fly.io",
      "repository": "shop",
      "tag": "deployment-01",
      "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    }
  }
]"#;

fn parsed() -> Vec<Machine> {
    let r = FakeRunner::new([Output::success(LISTING)]);
    machines(&r, "shop").expect("the sample listing parses")
}

#[test]
fn machines_argv_is_machine_list_with_the_app_bound() {
    assert_eq!(
        machines_args("shop"),
        ["machine", "list", "--app", "shop", "--json"]
    );
}

#[test]
fn machine_update_argv_carries_only_the_id_and_image_with_the_app_bound() {
    assert_eq!(
        machine_update_args("shop", ID, IMAGE),
        [
            "machine", "update", ID, "--app", "shop", "--image", IMAGE, "--yes"
        ]
    );
}

#[test]
fn a_listing_projects_the_id() {
    assert_eq!(parsed()[0].id, ID);
}

#[test]
fn a_listing_projects_the_name() {
    assert_eq!(parsed()[0].name, "opv-canary");
}

#[test]
fn a_listing_projects_the_state() {
    assert_eq!(parsed()[0].state, "started");
}

#[test]
fn a_listing_projects_the_region() {
    assert_eq!(parsed()[0].region, "iad");
}

#[test]
fn a_listing_projects_the_image() {
    assert_eq!(parsed()[0].image(), "registry.fly.io/shop:deployment-01");
}

#[test]
fn a_listing_never_keeps_a_value_hidden_in_config_env() {
    assert!(!format!("{:?}", parsed()).contains(MARK));
}

#[test]
fn a_listing_missing_a_required_field_is_unexpected_output() {
    let r = FakeRunner::new([Output::success(
        r#"[{"id":"8edd22dc379d68","name":"n","state":"started","config":{"image":"img"}}]"#,
    )]);
    let e = machines(&r, "shop").unwrap_err();
    assert_eq!(e.code_str(), "unexpected_output");
}

#[test]
fn a_machine_not_in_the_listing_is_refused_by_policy() {
    let r = FakeRunner::new([Output::success(LISTING)]);
    let e = machine_update(&r, "prod", "web", "shop", "00000000000000", IMAGE).unwrap_err();
    assert_eq!(e.code_str(), "policy_refused");
}

#[test]
fn a_machine_not_in_the_listing_makes_no_update_call() {
    let r = FakeRunner::new([Output::success(LISTING)]);
    let _ = machine_update(&r, "prod", "web", "shop", "00000000000000", IMAGE);
    assert_eq!(r.calls.borrow().len(), 1);
}

#[test]
fn a_listed_machine_is_updated() {
    let r = FakeRunner::new([Output::success(LISTING), Output::success("")]);
    machine_update(&r, "prod", "web", "shop", ID, IMAGE).unwrap();
    assert_eq!(r.calls.borrow().len(), 2);
}
