//! `opv propose target` (design Part V, row `propose-target`): one atomic test per
//! provider, each with exactly one assertion on a public outcome.
//!
//! The intent comes from `intent::parse` (the one document form) and the contract from
//! `config`. No test passes a runner: `propose` has no runner parameter, which is the
//! purity proof. No option value here is a secret; every one is a public name or id.

use super::*;
use crate::config::bindings::Bindings;
use crate::domain::intent;

/// Declared, not bootstrapped: no boundary or state vault is recorded yet, so a proposal is
/// judged as it will load once the structural plan records the missing ids.
const FRESH: &str = "[environments.dev]\n\n\
                     [products.app.keys.EXISTING_KEY]\nkind = \"secret\"\nenvironments = [\"dev\"]\n";

fn target_intent(json: &str) -> intent::Intent {
    intent::parse(json).expect("the intent parses")
}

fn proposal(json: &str) -> Proposal {
    propose(FRESH, &Bindings::default(), None, &target_intent(json)).expect("the target proposes")
}

#[test]
fn a_fly_target_proposal_diff_adds_the_target_section() {
    let p = proposal(
        r#"{"kind":"target","env":"dev","name":"web","provider":"fly","products":["app"],"options":{"fly-app":"myapp"}}"#,
    );
    assert!(p.diff.contains("+[environments.dev.targets.web]"));
}

#[test]
fn an_azure_target_proposal_diff_adds_the_target_section() {
    let p = proposal(
        r#"{"kind":"target","env":"dev","name":"web","provider":"azure","products":["app"],"options":{"azure-subscription":"00000000-0000-0000-0000-000000000001","azure-key-vault":"kv-app","azure-resource-group":"rg-app","azure-container-app":"ca-app"}}"#,
    );
    assert!(p.diff.contains("+[environments.dev.targets.web]"));
}

#[test]
fn a_kubernetes_target_proposal_diff_adds_the_target_section() {
    let p = proposal(
        r#"{"kind":"target","env":"dev","name":"web","provider":"kubernetes","products":["app"],"options":{"kubernetes-context":"ctx","kubernetes-namespace":"app","kubernetes-deployment":"web"}}"#,
    );
    assert!(p.diff.contains("+[environments.dev.targets.web]"));
}

#[test]
fn a_github_target_proposal_diff_adds_the_target_section() {
    let p = proposal(
        r#"{"kind":"target","env":"dev","name":"web","provider":"github","products":["app"],"options":{"github-repo":"owner/name"}}"#,
    );
    assert!(p.diff.contains("+[environments.dev.targets.web]"));
}

#[test]
fn an_unknown_provider_option_is_refused() {
    assert!(
        propose(
            FRESH,
            &Bindings::default(),
            None,
            &target_intent(
                r#"{"kind":"target","env":"dev","name":"web","provider":"fly","options":{"fly-bogus":"x"}}"#,
            ),
        )
        .is_err()
    );
}

#[test]
fn the_same_target_intent_twice_gives_the_same_plan_id() {
    let intent = target_intent(
        r#"{"kind":"target","env":"dev","name":"web","provider":"fly","products":["app"],"options":{"fly-app":"myapp"}}"#,
    );
    let first = propose(FRESH, &Bindings::default(), None, &intent).unwrap();
    let second = propose(FRESH, &Bindings::default(), None, &intent).unwrap();
    assert_eq!(first.plan_id, second.plan_id);
}
