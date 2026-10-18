//! Behaviour of `opv next` (design row `next-cmd`): one atomic test per observable
//! outcome through the public `next`, `render_text` and `document` seams. Inventories are
//! built directly, so no test reads a live 1Password reply. No value, length or digest is
//! in scope here.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::domain::inventory::{BoundaryIds, Cell, EnvironmentColumn};

/// One environment column with a single `core` boundary, bound or not.
fn env(name: &str, tier: Tier, vault: Option<&str>) -> EnvironmentColumn {
    EnvironmentColumn {
        env: name.to_string(),
        tier,
        boundaries: BTreeMap::from([(
            "core".to_string(),
            vault.map(|v| BoundaryIds {
                vault_id: v.to_string(),
                item_id: "item".to_string(),
            }),
        )]),
    }
}

/// An inventory with the given environments and cells and no key rows (`next` never reads
/// them).
fn inventory(environments: Vec<EnvironmentColumn>, cells: Vec<Cell>) -> Inventory {
    Inventory {
        environments,
        keys: Vec::new(),
        cells,
    }
}

/// One cell of product `api` on the `core` boundary.
fn cell(key: &str, state: ValueState, capability: Capability) -> Cell {
    Cell {
        product: "api".to_string(),
        key: key.to_string(),
        env: "dev".to_string(),
        boundary: "core".to_string(),
        state,
        capability,
        from_receipt: None,
    }
}

/// The chosen action as `(kind, actor, command)`, the one observable outcome of `next`.
fn shown(doc: &NextDoc) -> Option<(NextKind, NextActor, String)> {
    doc.next
        .as_ref()
        .map(|a| (a.kind, a.actor, a.command.clone()))
}

fn malformed(rule: &str) -> ValueState {
    ValueState::Malformed {
        rule: rule.to_string(),
    }
}

#[test]
fn rank_one_an_unbound_boundary_asks_for_apply() {
    let inv = inventory(
        vec![env("dev", Tier::Shared, None)],
        vec![cell("A", ValueState::Absent, Capability::Write)],
    );
    assert_eq!(
        shown(&next(&inv, &Signals::default())),
        Some((NextKind::Apply, NextActor::Person, "opv apply".to_string()))
    );
}

#[test]
fn rank_two_an_absent_key_in_a_writable_vault_asks_for_a_set() {
    let inv = inventory(
        vec![env("dev", Tier::Shared, Some("vdev"))],
        vec![
            cell("B_EMPTY", ValueState::Empty, Capability::Write),
            cell("A_ABSENT", ValueState::Absent, Capability::Write),
        ],
    );
    assert_eq!(
        shown(&next(&inv, &Signals::default())),
        Some((
            NextKind::EnterValue,
            NextActor::Person,
            "opv set api/A_ABSENT --env dev".to_string()
        ))
    );
}

#[test]
fn rank_three_an_empty_key_asks_for_a_set() {
    let inv = inventory(
        vec![env("dev", Tier::Shared, Some("vdev"))],
        vec![
            cell("B_PLACEHOLDER", ValueState::Placeholder, Capability::Write),
            cell("A_EMPTY", ValueState::Empty, Capability::Write),
        ],
    );
    assert_eq!(
        shown(&next(&inv, &Signals::default())),
        Some((
            NextKind::EnterValue,
            NextActor::Person,
            "opv set api/A_EMPTY --env dev".to_string()
        ))
    );
}

#[test]
fn rank_four_a_placeholder_key_asks_for_a_set() {
    let inv = inventory(
        vec![env("dev", Tier::Shared, Some("vdev"))],
        vec![
            cell("B_MALFORMED", malformed("shape"), Capability::Write),
            cell("A_PLACEHOLDER", ValueState::Placeholder, Capability::Write),
        ],
    );
    assert_eq!(
        shown(&next(&inv, &Signals::default())),
        Some((
            NextKind::EnterValue,
            NextActor::Person,
            "opv set api/A_PLACEHOLDER --env dev".to_string()
        ))
    );
}

#[test]
fn rank_five_a_malformed_key_asks_for_a_set() {
    let inv = inventory(
        vec![env("dev", Tier::Shared, Some("vdev"))],
        vec![cell("A_MALFORMED", malformed("shape"), Capability::Write)],
    );
    assert_eq!(
        shown(&next(&inv, &Signals::default())),
        Some((
            NextKind::EnterValue,
            NextActor::Person,
            "opv set api/A_MALFORMED --env dev".to_string()
        ))
    );
}

#[test]
fn rank_six_a_stale_set_key_asks_ci_to_sync_a_deployed_environment() {
    let inv = inventory(
        vec![env("dev", Tier::Shared, Some("vdev"))],
        vec![cell("A", ValueState::Set, Capability::Write)],
    );
    assert_eq!(
        shown(&next(&inv, &Signals::default())),
        Some((NextKind::Run, NextActor::Ci, "opv sync dev".to_string()))
    );
}

#[test]
fn a_stale_set_key_in_a_local_environment_asks_the_person_to_sync() {
    let inv = inventory(
        vec![env("dev", Tier::Local, Some("vdev"))],
        vec![cell("A", ValueState::Set, Capability::Write)],
    );
    assert_eq!(
        shown(&next(&inv, &Signals::default())),
        Some((NextKind::Run, NextActor::Person, "opv sync dev".to_string()))
    );
}

#[test]
fn rank_seven_a_delivered_set_key_leaves_nothing_to_do() {
    let inv = inventory(
        vec![env("dev", Tier::Shared, Some("vdev"))],
        vec![cell("A", ValueState::Set, Capability::Write)],
    );
    let signals = Signals {
        delivered: BTreeSet::from([("api".to_string(), "A".to_string(), "dev".to_string())]),
        writers: BTreeMap::new(),
    };
    assert_eq!(shown(&next(&inv, &signals)), None);
}

#[test]
fn the_queue_holds_the_rest_of_this_sessions_actions() {
    let inv = inventory(
        vec![env("dev", Tier::Shared, Some("vdev"))],
        vec![
            cell("A_ABSENT", ValueState::Absent, Capability::Write),
            cell("B_EMPTY", ValueState::Empty, Capability::Write),
        ],
    );
    assert_eq!(
        next(&inv, &Signals::default())
            .queue
            .iter()
            .map(|a| a.command.clone())
            .collect::<Vec<_>>(),
        vec!["opv set api/B_EMPTY --env dev".to_string()]
    );
}

#[test]
fn actions_on_a_read_only_vault_wait_on_others() {
    let inv = inventory(
        vec![env("dev", Tier::Shared, Some("vdev"))],
        vec![cell("A", ValueState::Absent, Capability::Read)],
    );
    assert_eq!(
        next(&inv, &Signals::default())
            .waits_on
            .iter()
            .map(|w| w.vault.clone())
            .collect::<Vec<_>>(),
        vec!["vdev".to_string()]
    );
}

#[test]
fn waiting_actions_are_grouped_under_their_vault() {
    let inv = inventory(
        vec![env("dev", Tier::Shared, Some("vdev"))],
        vec![
            cell("A_ABSENT", ValueState::Absent, Capability::Read),
            cell("B_EMPTY", ValueState::Empty, Capability::Read),
        ],
    );
    assert_eq!(next(&inv, &Signals::default()).waits_on[0].actions.len(), 2);
}

#[test]
fn a_deployed_vault_with_one_writer_is_a_finding() {
    let inv = inventory(vec![env("dev", Tier::Shared, Some("vdev"))], Vec::new());
    let signals = Signals {
        delivered: BTreeSet::new(),
        writers: BTreeMap::from([("vdev".to_string(), 1)]),
    };
    assert_eq!(
        next(&inv, &signals)
            .findings
            .iter()
            .map(|f| f.code)
            .collect::<Vec<_>>(),
        vec!["single_writer"]
    );
}

#[test]
fn a_deployed_vault_with_two_writers_has_no_finding() {
    let inv = inventory(vec![env("dev", Tier::Shared, Some("vdev"))], Vec::new());
    let signals = Signals {
        delivered: BTreeSet::new(),
        writers: BTreeMap::from([("vdev".to_string(), 2)]),
    };
    assert!(next(&inv, &signals).findings.is_empty());
}

#[test]
fn a_local_vault_with_one_writer_has_no_finding() {
    let inv = inventory(vec![env("dev", Tier::Local, Some("vdev"))], Vec::new());
    let signals = Signals {
        delivered: BTreeSet::new(),
        writers: BTreeMap::from([("vdev".to_string(), 1)]),
    };
    assert!(next(&inv, &signals).findings.is_empty());
}

#[test]
fn the_same_inventory_gives_identical_bytes() {
    let inv = inventory(
        vec![env("dev", Tier::Shared, Some("vdev"))],
        vec![
            cell("A_ABSENT", ValueState::Absent, Capability::Write),
            cell("B_EMPTY", ValueState::Empty, Capability::Read),
        ],
    );
    let signals = Signals::default();
    assert_eq!(
        next(&inv, &signals).document().to_string(),
        next(&inv, &signals).document().to_string()
    );
}

#[test]
fn the_document_carries_a_typed_next_object() {
    let inv = inventory(
        vec![env("dev", Tier::Shared, Some("vdev"))],
        vec![cell("A", ValueState::Absent, Capability::Write)],
    );
    assert_eq!(
        next(&inv, &Signals::default()).document()["next"],
        serde_json::json!({
            "kind": "enter_value",
            "actor": "person",
            "command": "opv set api/A --env dev"
        })
    );
}

#[test]
fn the_text_names_the_next_action() {
    let inv = inventory(
        vec![env("dev", Tier::Shared, Some("vdev"))],
        vec![cell("A", ValueState::Absent, Capability::Write)],
    );
    assert_eq!(
        render_text(&next(&inv, &Signals::default())),
        "next: opv set api/A --env dev\n"
    );
}
