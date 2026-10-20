//! Inventory document (design Part V, row `inventory-doc`): one behavioural outcome per
//! test through the public `build` seam. The document itself is the public outcome; no test
//! asserts a private detail. No value, length or digest appears in any document.

use std::collections::BTreeMap;

use super::{CellInputs, ReceiptUse, ReceiptView, build};
use crate::config;
use crate::domain::Fleet;
use crate::domain::capability::Capability;
use crate::domain::value_state::{UnreadableCause, ValueState};

/// A two-environment fleet: one `core` boundary per environment and one product `api` with a
/// config key (attributes and an expiry) and a secret key (defaults).
fn fleet() -> Fleet {
    config::parse(
        r#"[environments.dev]
boundaries.core = { vault_id = "vdev", item_id = "idev" }

[environments.prod]
boundaries.core = { vault_id = "vprod", item_id = "iprod" }

[products.api]
boundary = "core"

[products.api.keys.DATABASE_URL]
kind = "config"
environments = ["dev", "prod"]
source = "person"
expires = "2030-01-01"
lifecycle = "retiring"

[products.api.keys.STRIPE_KEY]
kind = "secret"
environments = ["dev", "prod"]
"#,
    )
    .expect("the fleet loads")
}

/// The exact document of `fleet()` with a live state for every cell and `dev` writable, `prod`
/// readable.
const GOLDEN: &str = r#"{
  "environments": [
    {
      "env": "dev",
      "tier": "shared",
      "boundaries": {
        "core": {
          "vault_id": "vdev",
          "item_id": "idev"
        }
      }
    },
    {
      "env": "prod",
      "tier": "production",
      "boundaries": {
        "core": {
          "vault_id": "vprod",
          "item_id": "iprod"
        }
      }
    }
  ],
  "keys": [
    {
      "product": "api",
      "key": "DATABASE_URL",
      "kind": "config",
      "source": "person",
      "presence": {
        "dev": "present",
        "prod": "present"
      },
      "lifecycle": "retiring",
      "expires": "2030-01-01"
    },
    {
      "product": "api",
      "key": "STRIPE_KEY",
      "kind": "secret",
      "source": null,
      "presence": {
        "dev": "present",
        "prod": "present"
      },
      "lifecycle": "active",
      "expires": null
    }
  ],
  "cells": [
    {
      "product": "api",
      "key": "DATABASE_URL",
      "env": "dev",
      "boundary": "core",
      "state": {
        "state": "set"
      },
      "capability": "write",
      "from_receipt": null
    },
    {
      "product": "api",
      "key": "DATABASE_URL",
      "env": "prod",
      "boundary": "core",
      "state": {
        "state": "placeholder"
      },
      "capability": "read",
      "from_receipt": null
    },
    {
      "product": "api",
      "key": "STRIPE_KEY",
      "env": "dev",
      "boundary": "core",
      "state": {
        "state": "empty"
      },
      "capability": "write",
      "from_receipt": null
    },
    {
      "product": "api",
      "key": "STRIPE_KEY",
      "env": "prod",
      "boundary": "core",
      "state": {
        "state": "absent"
      },
      "capability": "read",
      "from_receipt": null
    }
  ]
}"#;

/// The `(product, key, env)` a cell is keyed by.
fn at(product: &str, key: &str, env: &str) -> (String, String, String) {
    (product.into(), key.into(), env.into())
}

#[test]
fn a_two_environment_inventory_renders_the_golden_document() {
    let cells = CellInputs {
        states: BTreeMap::from([
            (at("api", "DATABASE_URL", "dev"), ValueState::Set),
            (at("api", "DATABASE_URL", "prod"), ValueState::Placeholder),
            (at("api", "STRIPE_KEY", "dev"), ValueState::Empty),
            (at("api", "STRIPE_KEY", "prod"), ValueState::Absent),
        ]),
        capabilities: BTreeMap::from([
            ("vdev".to_string(), Capability::Write),
            ("vprod".to_string(), Capability::Read),
        ]),
        ..CellInputs::default()
    };
    let json = serde_json::to_string_pretty(&build(&fleet(), &cells, None)).expect("serializes");
    assert_eq!(json, GOLDEN);
}

#[test]
fn a_none_capability_vault_takes_the_receipts_state() {
    let cells = CellInputs {
        states: BTreeMap::from([(
            at("api", "DATABASE_URL", "prod"),
            ValueState::Unreadable {
                cause: UnreadableCause::NoAccess,
            },
        )]),
        capabilities: BTreeMap::from([("vprod".to_string(), Capability::None)]),
        ..CellInputs::default()
    };
    let receipt = ReceiptView {
        states: BTreeMap::from([(at("api", "DATABASE_URL", "prod"), ValueState::Set)]),
        generated_at: "2026-01-01T00:00:00Z".into(),
        age_seconds: Some(3600),
    };
    let inventory = build(&fleet(), &cells, Some(&receipt));
    let cell = inventory
        .cells
        .iter()
        .find(|c| c.key == "DATABASE_URL" && c.env == "prod")
        .expect("the cell exists");
    assert_eq!(cell.state, ValueState::Set);
}

#[test]
fn a_substituted_cell_carries_the_receipts_age() {
    let cells = CellInputs {
        states: BTreeMap::new(),
        capabilities: BTreeMap::from([("vprod".to_string(), Capability::None)]),
        ..CellInputs::default()
    };
    let receipt = ReceiptView {
        states: BTreeMap::from([(at("api", "STRIPE_KEY", "prod"), ValueState::Empty)]),
        generated_at: "2026-01-01T00:00:00Z".into(),
        age_seconds: Some(7200),
    };
    let inventory = build(&fleet(), &cells, Some(&receipt));
    let cell = inventory
        .cells
        .iter()
        .find(|c| c.key == "STRIPE_KEY" && c.env == "prod")
        .expect("the cell exists");
    assert_eq!(
        cell.from_receipt,
        Some(ReceiptUse {
            generated_at: "2026-01-01T00:00:00Z".into(),
            age_seconds: Some(7200),
        })
    );
}

#[test]
fn an_unbound_boundary_shows_null_ids() {
    let fleet = config::parse(
        r#"[environments.dev]
boundaries.core = {}

[products.api]
boundary = "core"

[products.api.keys.SECRET]
kind = "secret"
environments = ["dev"]
"#,
    )
    .expect("the fleet loads");
    let inventory = build(&fleet, &CellInputs::default(), None);
    assert_eq!(inventory.environments[0].boundaries["core"], None);
}

#[test]
fn a_not_wanted_key_shows_the_not_wanted_state() {
    let fleet = config::parse(
        r#"[environments.dev]
boundaries.core = { vault_id = "vdev", item_id = "idev" }

[products.api]
boundary = "core"

[products.api.keys.KEEP]
kind = "secret"
environments = ["dev"]

[products.api.keys.SECRET]
kind = "secret"
except = { dev = "no dev account" }
"#,
    )
    .expect("the fleet loads");
    let cells = CellInputs {
        states: BTreeMap::from([(at("api", "SECRET", "dev"), ValueState::Set)]),
        capabilities: BTreeMap::from([("vdev".to_string(), Capability::Write)]),
        ..CellInputs::default()
    };
    let inventory = build(&fleet, &cells, None);
    let cell = inventory
        .cells
        .iter()
        .find(|c| c.key == "SECRET")
        .expect("the cell exists");
    assert_eq!(
        cell.state,
        ValueState::NotWanted {
            reason: "no dev account".into()
        }
    );
}

#[test]
fn a_none_capability_vault_without_a_receipt_is_unreadable_never_absent() {
    let fleet = fleet();
    let env = fleet.environments.keys().next().unwrap().clone();
    let vault = fleet.environments[&env]
        .boundaries
        .values()
        .flatten()
        .next()
        .unwrap()
        .vault_id
        .clone();
    let mut cells = CellInputs::default();
    cells.capabilities.insert(vault, Capability::None);
    let inv = build(&fleet, &cells, None);
    let cell = inv.cells.iter().find(|c| c.env == env).unwrap();
    assert!(matches!(cell.state, ValueState::Unreadable { .. }));
}

/// The JSON of the one key row `product`/`key` of `fleet`'s inventory, built with no
/// live cell: the row's declared attributes are the outcome under test.
fn key_row(fleet: &Fleet, product: &str, key: &str) -> serde_json::Value {
    let document = build(fleet, &CellInputs::default(), None);
    let row = document
        .keys
        .iter()
        .find(|k| k.product == product && k.key == key)
        .expect("the key is declared");
    serde_json::to_value(row).expect("the row serializes")
}

/// One `dev` environment with the boundary `core` and product `api`, whose single secret
/// key `API_KEY` is declared for `dev` with the extra `attributes` appended.
fn fleet_with_key_attributes(attributes: &str) -> Fleet {
    config::parse(&format!(
        r#"[environments.dev]
boundaries.core = {{ vault_id = "vdev", item_id = "idev" }}

[products.api]
boundary = "core"

[products.api.keys.API_KEY]
kind = "secret"
environments = ["dev"]
{attributes}
"#
    ))
    .expect("the fleet loads")
}

/// A key declared `immutable` reports that attribute.
#[test]
fn an_immutable_key_reports_immutable() {
    let fleet = fleet_with_key_attributes("immutable = true");
    assert_eq!(key_row(&fleet, "api", "API_KEY")["immutable"], true);
}

/// A key declared `allow_same_value` reports that attribute.
#[test]
fn an_allow_same_value_key_reports_allow_same_value() {
    let fleet = fleet_with_key_attributes("allow_same_value = true");
    assert_eq!(key_row(&fleet, "api", "API_KEY")["allow_same_value"], true);
}

/// The rule names a key declares are reported; a rule's parameters never are.
#[test]
fn a_key_reports_the_names_of_its_rules_not_their_parameters() {
    let fleet = fleet_with_key_attributes(r#"rules = { prefix = "sk_test_" }"#);
    assert_eq!(
        key_row(&fleet, "api", "API_KEY")["rules"],
        serde_json::json!(["prefix"])
    );
}

/// The guidance a key declares is reported.
#[test]
fn a_key_reports_its_guidance() {
    let fleet = fleet_with_key_attributes(r#"guidance = "Stripe dashboard""#);
    assert_eq!(
        key_row(&fleet, "api", "API_KEY")["guidance"],
        "Stripe dashboard"
    );
}

/// The process roles a key declares are reported.
#[test]
fn a_key_reports_its_roles() {
    let fleet = fleet_with_key_attributes(r#"roles = ["serve", "migrate"]"#);
    assert_eq!(
        key_row(&fleet, "api", "API_KEY")["roles"],
        serde_json::json!(["serve", "migrate"])
    );
}

/// A local file key reports the relative path it is delivered at.
#[test]
fn a_local_file_key_reports_its_path() {
    let fleet = fleet_with_key_attributes(r#"file = "tls/private-key""#);
    assert_eq!(key_row(&fleet, "api", "API_KEY")["file"], "tls/private-key");
}

/// A key reports the name each target that delivers it renders for it.
#[test]
fn a_key_reports_its_delivered_name_on_each_target() {
    let fleet = config::parse(
        r#"[environments.dev]
boundaries.core = { vault_id = "vdev", item_id = "idev" }

[environments.dev.targets.web]
fly.app = "web-dev"
fly.secret_name = "SVC_{KEY}"

[products.api]
boundary = "core"

[products.api.keys.API_KEY]
kind = "secret"
environments = ["dev"]
"#,
    )
    .expect("the fleet loads");
    assert_eq!(
        key_row(&fleet, "api", "API_KEY")["targets"],
        serde_json::json!({"dev/web": "SVC_API_KEY"})
    );
}

/// A key whose explicit `environments` list leaves an environment out (no `except`) is not
/// declared there: it has no cell to read, rank or fill.
#[test]
fn a_key_left_out_of_an_environment_has_no_cell() {
    let fleet = config::parse(
        r#"[environments.dev]
boundaries.core = { vault_id = "vdev", item_id = "idev" }

[environments.prod]
boundaries.core = { vault_id = "vprod", item_id = "iprod" }

[products.api]
boundary = "core"

[products.api.keys.OTEL]
kind = "config"
environments = ["prod"]

[products.api.keys.KEEP]
kind = "secret"
"#,
    )
    .expect("the fleet loads");
    let inventory = build(&fleet, &CellInputs::default(), None);
    assert!(
        !inventory
            .cells
            .iter()
            .any(|c| c.key == "OTEL" && c.env == "dev")
    );
}

/// #179: `fleet()`'s `DATABASE_URL` is `retiring`; `dev` has no field of it.
#[test]
fn a_retiring_key_without_a_field_has_no_cell_to_fill() {
    let cells = CellInputs {
        states: BTreeMap::from([(at("api", "DATABASE_URL", "dev"), ValueState::Absent)]),
        capabilities: BTreeMap::from([("vdev".to_string(), Capability::Write)]),
        ..CellInputs::default()
    };
    let inventory = build(&fleet(), &cells, None);
    assert!(
        !inventory
            .cells
            .iter()
            .any(|c| c.key == "DATABASE_URL" && c.env == "dev")
    );
}

/// #179: a `retired` key's fields are archived; nothing is left to hold or fill.
#[test]
fn a_retired_key_has_no_cell() {
    let fleet = config::parse(
        r#"[environments.dev]
boundaries.core = { vault_id = "vdev", item_id = "idev" }

[products.api]
boundary = "core"

[products.api.keys.KEEP]
kind = "secret"

[products.api.keys.OLD]
kind = "secret"
lifecycle = "retired"
"#,
    )
    .expect("the fleet loads");
    let inventory = build(&fleet, &CellInputs::default(), None);
    assert!(!inventory.cells.iter().any(|c| c.key == "OLD"));
}

/// Delivery state per key per target (#174): one placement's evidence line for `API_KEY`,
/// bound to `core/API_KEY` in item `icore` at store version `3`, recorded when `icore` was at
/// version `5`.
mod delivery {
    use std::collections::BTreeMap;

    use crate::domain::delivery::{Evidence, Source, SuppliedMark};
    use crate::domain::inventory::{
        DeliveryState, EvidenceUnreadable, PlacementEvidence, delivery_state,
    };

    fn source() -> Source {
        Source {
            item_id: "icore".into(),
            field: "core/API_KEY".into(),
        }
    }

    fn line(attested: bool, supplied: bool) -> Evidence {
        Evidence {
            name: "API_KEY".into(),
            store_version: "3".into(),
            fingerprint: "f".into(),
            source: source(),
            attested_at: attested.then(|| "2026-10-18T00:00:00Z".into()),
            supplied: supplied.then(|| SuppliedMark {
                serial: 1,
                at: "2026-10-18T00:00:00Z".into(),
            }),
        }
    }

    fn evidence(e: Evidence) -> PlacementEvidence {
        PlacementEvidence::new(&[e], Some("v1|icore|5\n"))
    }

    fn versions(current: u64) -> BTreeMap<String, u64> {
        BTreeMap::from([("icore".to_string(), current)])
    }

    fn state_of(e: &PlacementEvidence, current: u64) -> DeliveryState {
        delivery_state(
            Ok(Some(e)),
            "API_KEY",
            Some(&source()),
            &versions(current),
            None,
        )
    }

    #[test]
    fn a_v1_line_is_delivered() {
        assert_eq!(
            state_of(&evidence(line(false, false)), 5),
            DeliveryState::Delivered
        );
    }

    #[test]
    fn an_a1_line_is_attested() {
        assert_eq!(
            state_of(&evidence(line(true, false)), 5),
            DeliveryState::Attested
        );
    }

    #[test]
    fn a_supplied_line_is_supplied() {
        assert_eq!(
            state_of(&evidence(line(false, true)), 5),
            DeliveryState::Supplied
        );
    }

    #[test]
    fn a_name_without_a_line_is_not_delivered() {
        assert_eq!(
            state_of(&PlacementEvidence::default(), 5),
            DeliveryState::NotDelivered
        );
    }

    #[test]
    fn a_placement_without_a_delivery_item_is_not_delivered() {
        let state = delivery_state(Ok(None), "API_KEY", Some(&source()), &versions(5), None);
        assert_eq!(state, DeliveryState::NotDelivered);
    }

    /// A line in a format this opv does not read (a later tag) is never counted as proven:
    /// `decode_evidence` drops it, so the name has no line.
    #[test]
    fn an_unknown_evidence_tag_is_not_delivered() {
        let lines: Vec<Evidence> =
            crate::domain::delivery::decode_evidence("API_KEY", "z9|3|f|icore|core/API_KEY")
                .into_iter()
                .collect();
        let e = PlacementEvidence::new(&lines, None);
        assert_eq!(state_of(&e, 5), DeliveryState::NotDelivered);
    }

    #[test]
    fn a_line_recorded_before_the_source_item_changed_is_stale() {
        assert_eq!(
            state_of(&evidence(line(false, false)), 6),
            DeliveryState::Stale
        );
    }

    #[test]
    fn a_line_for_another_source_field_is_stale() {
        let moved = Source {
            item_id: "icore".into(),
            field: "core/OTHER".into(),
        };
        let e = evidence(line(false, false));
        let state = delivery_state(Ok(Some(&e)), "API_KEY", Some(&moved), &versions(5), None);
        assert_eq!(state, DeliveryState::Stale);
    }

    #[test]
    fn a_line_at_an_older_store_version_than_listed_is_stale() {
        let e = evidence(line(false, false));
        let state = delivery_state(
            Ok(Some(&e)),
            "API_KEY",
            Some(&source()),
            &versions(5),
            Some("4"),
        );
        assert_eq!(state, DeliveryState::Stale);
    }

    #[test]
    fn an_unreadable_delivery_item_is_unreadable() {
        let e = EvidenceUnreadable::new();
        let state = delivery_state(Err(&e), "API_KEY", Some(&source()), &versions(5), None);
        assert_eq!(state, DeliveryState::Unreadable);
    }

    /// A source item this session could not read has no current version: not judged stale.
    #[test]
    fn an_unknown_source_version_is_not_judged_stale() {
        let e = evidence(line(false, false));
        let state = delivery_state(
            Ok(Some(&e)),
            "API_KEY",
            Some(&source()),
            &BTreeMap::new(),
            None,
        );
        assert_eq!(state, DeliveryState::Delivered);
    }
}
