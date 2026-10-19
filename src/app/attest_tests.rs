//! A person's attestation of a held immutable key (#201, `docs/attestation.md`): one
//! atomic scenario per test, each with exactly one assertion on a public outcome. The world
//! is the delivery tests' own (1Password as the stateful fake, Fly as a small store whose
//! listed version is a digest of the value).

use super::*;
use crate::app::attest;
use crate::cause::{AttestRefusal, Cause, Guard};
use crate::host::FakeEnv;

const TOKEN: &str = "FLEET__API__TOKEN";

/// A person at their own terminal: no CI, no assistant marker.
fn person() -> FakeEnv {
    FakeEnv::new("linux").tty()
}

/// The issue's staging case after its sync: api/TOKEN is immutable and already on Fly with
/// 1Password's value, and api's placement has its evidence key but no evidence line for it.
fn held_on_fly() -> (World, Fleet) {
    let (w, fleet) = world_with_immutable_token();
    w.app("myapp")
        .insert(TOKEN.into(), (format!("tok-{MARK}"), false));
    sync_all(&w, &fleet).unwrap();
    (w, fleet)
}

fn propose(w: &World, fleet: &Fleet, key: &str) -> Result<attest::AttestProposal, Error> {
    attest::propose(fleet, "prod", "app", &[key.to_string()], w)
}

fn apply_as(
    w: &World,
    fleet: &Fleet,
    plan_id: Option<&str>,
    host: &FakeEnv,
) -> Result<attest::Attested, Error> {
    let mut out = Vec::new();
    attest::apply(
        fleet,
        "prod",
        "app",
        &["api/TOKEN".to_string()],
        plan_id,
        host,
        &mut |_| true,
        &mut out,
        w,
    )
}

/// The refusal reason of an attestation error, if it is one.
fn reason(e: &Error) -> Option<AttestRefusal> {
    match e.parts().0 {
        Cause::Guard {
            guard: Guard::AttestRefused { reason, .. },
        } => Some(*reason),
        _ => None,
    }
}

/// The staging case attested by a person, then synced.
fn attested_and_synced() -> (World, Fleet) {
    let (w, fleet) = held_on_fly();
    apply_as(&w, &fleet, None, &person()).unwrap();
    sync_all(&w, &fleet).unwrap();
    (w, fleet)
}

#[test]
fn attesting_a_held_immutable_key_lets_the_next_sync_mint_the_revision() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = attested_and_synced();
    assert_eq!(state_of(&verify_doc(&w, &fleet), "api"), "verified");
}

#[test]
fn the_minted_receipt_lists_the_attested_name() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = attested_and_synced();
    let doc = verify_doc(&w, &fleet);
    let api = doc["placements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["product"] == "api")
        .cloned()
        .unwrap();
    assert_eq!(api["attested"], json!([TOKEN]));
}

#[test]
fn a_sync_that_writes_the_attested_name_replaces_the_attestation() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = attested_and_synced();
    w.set_value("api", "TOKEN", &format!("tok2-{MARK}"));
    let rotate = SyncOpts {
        rotate: vec!["api/TOKEN".into()],
        ..SyncOpts::default()
    };
    sync_with(&w, &fleet, rotate).0.unwrap();
    let doc = verify_doc(&w, &fleet);
    let api = doc["placements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["product"] == "api")
        .cloned()
        .unwrap();
    assert!(api.get("attested").is_none(), "{api}");
}

#[test]
fn the_proposal_names_the_held_key() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = held_on_fly();
    let p = propose(&w, &fleet, "api/TOKEN").unwrap();
    let names: Vec<&str> = p.names.iter().map(|n| n.name.as_str()).collect();
    assert_eq!(names, vec![TOKEN]);
}

#[test]
fn the_proposal_shows_no_value_and_no_digest() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = held_on_fly();
    let p = propose(&w, &fleet, "api/TOKEN").unwrap();
    let shown = format!(
        "{}{}",
        serde_json::to_string(&p).unwrap(),
        attest::describe(&p).join("\n")
    );
    let fly_digest = digest(&format!("tok-{MARK}"));
    assert!(
        !shown.contains(MARK) && !shown.contains(&fly_digest),
        "{shown}"
    );
}

#[test]
fn a_key_that_is_not_immutable_is_refused() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world();
    w.app("myapp")
        .insert(TOKEN.into(), (format!("tok-{MARK}"), false));
    let e = propose(&w, &fleet, "api/TOKEN").unwrap_err();
    assert_eq!(reason(&e), Some(AttestRefusal::NotImmutable));
}

#[test]
fn a_key_already_proven_by_the_ledger_is_refused() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world_with_immutable_token();
    sync_all(&w, &fleet).unwrap();
    let e = propose(&w, &fleet, "api/TOKEN").unwrap_err();
    assert_eq!(reason(&e), Some(AttestRefusal::Proven));
}

#[test]
fn a_key_absent_from_the_target_is_refused() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world_with_immutable_token();
    let e = propose(&w, &fleet, "api/TOKEN").unwrap_err();
    assert_eq!(reason(&e), Some(AttestRefusal::NotOnTarget));
}

#[test]
fn a_key_the_sync_does_not_hold_is_refused() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = held_on_fly();
    w.set_value("api", "TOKEN", "");
    let e = propose(&w, &fleet, "api/TOKEN").unwrap_err();
    assert_eq!(reason(&e), Some(AttestRefusal::NotHeld));
}

#[test]
fn a_key_the_target_does_not_deliver_is_refused() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = held_on_fly();
    let e = propose(&w, &fleet, "shared/KEY").unwrap_err();
    assert_eq!(reason(&e), Some(AttestRefusal::NotDelivered));
}

#[test]
fn apply_is_refused_under_ci() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = held_on_fly();
    let e = apply_as(&w, &fleet, None, &person().var("CI")).unwrap_err();
    assert_eq!(e.code_str(), "terminal_required");
}

#[test]
fn apply_is_refused_in_agent_mode() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = held_on_fly();
    let e = apply_as(&w, &fleet, None, &person().var("CLAUDECODE")).unwrap_err();
    assert_eq!(e.code_str(), "person_only");
}

#[test]
fn apply_after_the_target_changed_is_refused_as_stale() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = held_on_fly();
    let id = propose(&w, &fleet, "api/TOKEN").unwrap().plan_id;
    w.app("myapp")
        .insert(TOKEN.into(), (format!("tok-elsewhere-{MARK}"), false));
    let e = apply_as(&w, &fleet, Some(&id), &person()).unwrap_err();
    assert_eq!(e.code_str(), "stale_plan");
}

#[test]
fn apply_writes_nothing_to_the_target() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = held_on_fly();
    let before = w.app("myapp").clone();
    apply_as(&w, &fleet, None, &person()).unwrap();
    assert_eq!(*w.app("myapp"), before);
}

#[test]
fn a_placement_no_sync_has_recorded_is_refused() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world_with_immutable_token();
    w.app("myapp")
        .insert(TOKEN.into(), (format!("tok-{MARK}"), false));
    let e = propose(&w, &fleet, "api/TOKEN").unwrap_err();
    assert_eq!(reason(&e), Some(AttestRefusal::NotRecorded));
}
