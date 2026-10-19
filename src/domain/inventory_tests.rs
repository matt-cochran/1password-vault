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
