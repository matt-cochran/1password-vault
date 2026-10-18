//! The shared agent-view builders (j8): one document for the MCP tools and the CLI.

use super::*;
use crate::app::bootstrap::{BoundaryPlan, BoundaryStep, EnvPlan, StatePlan, StateStep};
use crate::app::structure::{DeliveryStep, FieldStep, Plan};

const ACCOUNT: &str = "ACCOUNTAAA000000000000AAAA";
const VAULT_ID: &str = "vdev0000000000000000000001";
const ITEM_ID: &str = "item00000000000000000aaaaaa";
const STATE_ID: &str = "vdev0000000000000000000009";

fn plan() -> Plan {
    Plan {
        plan_id: "sp-0123456789abcdef".into(),
        project: "myapp".into(),
        account_id: ACCOUNT.into(),
        environments: vec![EnvPlan {
            environment: "dev".into(),
            boundaries: vec![
                BoundaryPlan {
                    boundary: "core".into(),
                    products: vec!["web".into()],
                    step: BoundaryStep::Create {
                        vault: "myapp-core-dev".into(),
                        item: "myapp · core · dev values".into(),
                    },
                },
                BoundaryPlan {
                    boundary: "old".into(),
                    products: vec!["api".into()],
                    step: BoundaryStep::Ok {
                        vault_id: VAULT_ID.into(),
                        item_id: ITEM_ID.into(),
                    },
                },
            ],
            state_vaults: vec![StatePlan {
                target: "web".into(),
                step: StateStep::Create {
                    vault: "myapp-dev-web-state".into(),
                },
            }],
        }],
        delivery_items: vec![DeliveryStep {
            environment: "dev".into(),
            target: "web".into(),
            product: "web".into(),
            item: "myapp · web · delivery".into(),
        }],
        fields: vec![FieldStep {
            environment: "dev".into(),
            boundary: "core".into(),
            product: "web".into(),
            key: "SESSION_KEY".into(),
            kind: "secret",
        }],
        generated: false,
    }
}

fn config_text() -> String {
    format!(
        r#"[environments.dev]
boundaries.core = {{ vault_id = "{VAULT_ID}", item_id = "{ITEM_ID}" }}

[environments.dev.targets.web]
fly.app = "myapp-web-dev"
fly.secret_name = "MYAPP__WEB__{{KEY}}"
state_vault_id = "{STATE_ID}"
products = ["web"]

[products.web]
boundary = "core"
[products.web.keys.SESSION_KEY]
kind = "secret"
environments = ["dev"]
"#
    )
}

#[test]
fn plan_projection_marks_each_boundary_by_action() {
    let actions: Vec<String> = {
        let doc = plan_projection(&plan());
        doc["structure"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["action"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(actions, ["create", "ok", "create"]);
}

#[test]
fn plan_projection_carries_the_shared_plan_id() {
    assert_eq!(plan_projection(&plan())["plan_id"], "sp-0123456789abcdef");
}

#[test]
fn plan_projection_lists_a_delivery_item_and_empty_field_by_name() {
    let doc = plan_projection(&plan());
    assert_eq!(
        (
            doc["delivery_items"][0]["product"].clone(),
            doc["fields"][0]["key"].clone()
        ),
        (serde_json::json!("web"), serde_json::json!("SESSION_KEY"))
    );
}

#[test]
fn configuration_projection_never_echoes_a_vault_or_item_id() {
    let fleet = crate::config::parse(&config_text()).unwrap();
    let text = configuration_projection(&fleet).to_string();
    assert!(
        !text.contains(VAULT_ID) && !text.contains(ITEM_ID) && !text.contains(STATE_ID),
        "{text}"
    );
}

#[test]
fn configuration_projection_names_the_target_and_its_product() {
    let fleet = crate::config::parse(&config_text()).unwrap();
    let target = &configuration_projection(&fleet)["targets"][0];
    assert_eq!(
        (target["name"].clone(), target["products"].clone()),
        (serde_json::json!("web"), serde_json::json!(["web"]))
    );
}
