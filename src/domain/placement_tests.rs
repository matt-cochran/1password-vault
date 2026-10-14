//! Behaviour tests for the load-time state-vault-width check (FR-58, S6;
//! `docs/design/placements-and-access-boundaries.md` §6.3). One observable outcome per
//! test. Test inputs are names and boundary ids only: never a value or value-derived
//! digest (SR-1).

use super::*;

fn reads<'a>(target: &'a str, state_vault_id: &'a str, boundaries: &[&'a str]) -> TargetReads<'a> {
    TargetReads {
        environment: "prod",
        target,
        state_vault_id,
        boundaries: boundaries.iter().copied().collect(),
    }
}

fn finding(
    state_vault_id: &str,
    targets: &[&str],
    target: &str,
    unreadable_boundary: &str,
) -> WiderThanValues {
    WiderThanValues {
        state_vault_id: state_vault_id.into(),
        targets: targets.iter().map(|t| format!("prod/{t}")).collect(),
        environment: "prod".into(),
        target: target.into(),
        unreadable_boundary: unreadable_boundary.into(),
    }
}

#[test]
fn the_finding_code_names_the_wider_than_values_error() {
    assert_eq!(
        STATE_VAULT_WIDER_THAN_VALUES,
        "state_vault_wider_than_values"
    );
}

#[test]
fn targets_with_distinct_state_vaults_yield_no_findings() {
    let targets = [
        reads("api", "v-api", &["prod"]),
        reads("web", "v-web", &["prod"]),
    ];
    assert_eq!(wider_than_values(&targets), Vec::new());
}

#[test]
fn targets_sharing_a_state_vault_and_the_same_boundaries_yield_no_findings() {
    let targets = [reads("api", "v", &["prod"]), reads("web", "v", &["prod"])];
    assert_eq!(wider_than_values(&targets), Vec::new());
}

#[test]
fn a_target_that_cannot_read_a_boundary_its_peer_reads_yields_one_finding() {
    let targets = [
        reads("api", "v", &["prod"]),
        reads("web", "v", &["prod", "staging"]),
    ];
    assert_eq!(
        wider_than_values(&targets),
        vec![finding("v", &["api", "web"], "api", "staging")]
    );
}

#[test]
fn targets_that_each_miss_a_different_boundary_yield_one_finding_each() {
    let targets = [
        reads("api", "v", &["prod"]),
        reads("web", "v", &["staging"]),
    ];
    assert_eq!(
        wider_than_values(&targets),
        vec![
            finding("v", &["api", "web"], "api", "staging"),
            finding("v", &["api", "web"], "web", "prod"),
        ]
    );
}

#[test]
fn a_boundary_read_by_several_peers_yields_a_single_finding_per_target() {
    let targets = [
        reads("api", "v", &[]),
        reads("web", "v", &["prod"]),
        reads("db", "v", &["prod"]),
    ];
    assert_eq!(
        wider_than_values(&targets),
        vec![finding("v", &["api", "db", "web"], "api", "prod")]
    );
}

#[test]
fn findings_are_sorted_by_vault_target_and_boundary_whatever_the_input_order() {
    let targets = [
        reads("web", "v2", &["b"]),
        reads("api", "v2", &["a"]),
        reads("z", "v1", &["a"]),
        reads("a", "v1", &["b"]),
    ];
    assert_eq!(
        wider_than_values(&targets),
        vec![
            finding("v1", &["a", "z"], "a", "a"),
            finding("v1", &["a", "z"], "z", "b"),
            finding("v2", &["api", "web"], "api", "b"),
            finding("v2", &["api", "web"], "web", "a"),
        ]
    );
}

#[test]
fn sentence_returns_the_documented_text() {
    let finding = finding("v1", &["api", "web"], "api", "staging");
    assert_eq!(
        finding.sentence(),
        "state vault v1 is shared by targets prod/api, prod/web, but prod/api cannot read \
         boundary staging; that target's deploy identity would read evidence for values it \
         cannot read. Give each target its own state vault: delete state_vault_id from \
         [environments.prod.targets.api] and run opv bootstrap."
    );
}
