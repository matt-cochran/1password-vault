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
    apply_keys(w, fleet, &["api/TOKEN"], plan_id, host).0
}

/// `opv apply [<plan_id>] --attest prod:app:<key>…` as `host`, and what it printed.
fn apply_keys(
    w: &World,
    fleet: &Fleet,
    keys: &[&str],
    plan_id: Option<&str>,
    host: &FakeEnv,
) -> (Result<attest::Attested, Error>, String) {
    let mut out = Vec::new();
    let keys: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
    let res = attest::apply(
        fleet,
        "prod",
        "app",
        &keys,
        plan_id,
        host,
        &mut |_| true,
        &mut out,
        w,
    );
    (res, String::from_utf8(out).unwrap())
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

// ---- the DESIGN-FMECA review's findings (H1, M2, M3, L4, L5) ------------------------------

/// The delivery item of `product` on target `app`, as 1Password holds it now.
fn delivery_item_now(w: &World, fleet: &Fleet, product: &str) -> Value {
    let id = fleet.environments["prod"].targets["app"].delivery_items[product].clone();
    w.op.item(&id)
}

/// The value of the field labelled `label` in `item`.
fn field_value(item: &Value, label: &str) -> String {
    item["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["label"] == label)
        .and_then(|f| f["value"].as_str())
        .unwrap_or_default()
        .to_string()
}

/// Rewrite api's delivery item as an opv before 0.12.3 does: it reads only `v1` lines, so
/// every other evidence line is dropped.
fn rewrite_as_an_older_opv(w: &World, fleet: &Fleet) {
    let id = fleet.environments["prod"].targets["app"].delivery_items["api"].clone();
    let mut items = w.op.items.borrow_mut();
    let item = items.iter_mut().find(|i| i["id"] == id.as_str()).unwrap();
    item["fields"]
        .as_array_mut()
        .unwrap()
        .retain(|f| !f["value"].as_str().is_some_and(|v| v.starts_with("a1|")));
}

#[test]
fn an_attested_evidence_line_carries_the_a1_tag() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = held_on_fly();
    apply_as(&w, &fleet, None, &person()).unwrap();
    let line = field_value(&delivery_item_now(&w, &fleet, "api"), TOKEN);
    assert!(line.starts_with("a1|"), "{line}");
}

#[test]
fn an_older_opv_dropping_the_attested_line_holds_the_key_again_with_no_receipt() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = attested_and_synced();
    rewrite_as_an_older_opv(&w, &fleet);
    let (_, out) = sync_with(&w, &fleet, SyncOpts::default());
    assert!(out.contains("delivery: api not recorded"), "{out}");
}

#[test]
fn plan_json_flags_an_attested_row() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = attested_and_synced();
    let mut out = Vec::new();
    let _ = sync::plan_with(&fleet, "prod", &w, &mut out, true);
    let doc: Value = serde_json::from_slice(&out).unwrap();
    let row = doc["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["key"] == "TOKEN")
        .cloned()
        .unwrap();
    assert_eq!(row["attested"], json!(true), "{row}");
}

#[test]
fn plan_text_says_attested_for_an_attested_row() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = attested_and_synced();
    let mut out = Vec::new();
    let _ = sync::plan_with(&fleet, "prod", &w, &mut out, false);
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.lines()
            .any(|l| l.contains("TOKEN") && l.contains("attested")),
        "{text}"
    );
}

#[test]
fn verify_flags_the_attested_name() {
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
    let token = api["names"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["name"] == TOKEN)
        .cloned()
        .unwrap();
    assert_eq!(token["attested"], json!(true), "{token}");
}

#[test]
fn verify_text_labels_the_attested_name() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = attested_and_synced();
    let mut out = Vec::new();
    let _ = verify(&fleet, "prod", None, &[], None, &w, false, &mut out);
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.lines()
            .any(|l| l.contains(TOKEN) && l.contains("attested by a person, not proven")),
        "{text}"
    );
}

#[test]
fn attesting_again_is_refused_as_already_attested() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = held_on_fly();
    apply_as(&w, &fleet, None, &person()).unwrap();
    let e = propose(&w, &fleet, "api/TOKEN").unwrap_err();
    assert_eq!(reason(&e), Some(AttestRefusal::AlreadyAttested));
}

#[test]
fn a_key_whose_ledger_line_differs_from_1password_is_refused() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world_with_immutable_token();
    sync_all(&w, &fleet).unwrap();
    w.set_value("api", "TOKEN", &format!("tok2-{MARK}"));
    // op's local cache would show the old value for a while; the change has reached it.
    w.op.cache.borrow_mut().clear();
    let e = propose(&w, &fleet, "api/TOKEN").unwrap_err();
    assert_eq!(reason(&e), Some(AttestRefusal::Differs));
}

#[test]
fn a_key_changed_on_the_target_outside_opv_is_refused() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world_with_immutable_token();
    sync_all(&w, &fleet).unwrap();
    w.app("myapp")
        .insert(TOKEN.into(), (format!("edited-{MARK}"), false));
    let e = propose(&w, &fleet, "api/TOKEN").unwrap_err();
    assert_eq!(reason(&e), Some(AttestRefusal::Drifted));
}

/// prod with the Fly target `app` and a Kubernetes target `cluster` delivering api: the
/// cluster's values are read and compared exactly.
fn with_a_cluster_target() -> (World, Fleet) {
    let op = FakeOp::default();
    let id = values_item(&op);
    let (api, web) = (
        delivery_item(&op, "api", "app"),
        delivery_item(&op, "web", "app"),
    );
    let cluster = "[environments.prod.targets.cluster]\n\
                   state_vault_id = \"vk8s0000000000000000000003\"\n\
                   kubernetes.context = \"ctx\"\n\
                   kubernetes.namespace = \"ns\"\n\
                   kubernetes.deployment = \"api\"\n\
                   kubernetes.env_name = \"FLEET__{PRODUCT}__{KEY}\"\n\
                   products = [\"api\"]\n";
    let fleet = crate::config::parse(&format!(
        "{}{}{cluster}{PRODUCTS}",
        boundaries(&id),
        target_toml("app", "myapp", &[("api", &api), ("web", &web)])
    ))
    .unwrap();
    let mut fleet = fleet;
    fleet
        .products
        .get_mut("api")
        .unwrap()
        .keys
        .get_mut("TOKEN")
        .unwrap()
        .immutable = true;
    let w = World {
        op,
        fly: RefCell::default(),
        fail_import: std::cell::Cell::new(false),
        fail_op_write_on: RefCell::default(),
    };
    (w, fleet)
}

#[test]
fn a_key_on_a_target_compared_directly_is_refused() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = with_a_cluster_target();
    let e = attest::propose(&fleet, "prod", "cluster", &["api/TOKEN".to_string()], &w).unwrap_err();
    assert_eq!(reason(&e), Some(AttestRefusal::ComparedDirectly));
}

#[test]
fn apply_without_a_terminal_is_refused() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = held_on_fly();
    let e = apply_as(&w, &fleet, None, &FakeEnv::new("linux")).unwrap_err();
    assert_eq!(e.code_str(), "terminal_required");
}

#[test]
fn apply_under_a_service_account_is_refused() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = held_on_fly();
    let host = person().var_val("OP_SERVICE_ACCOUNT_TOKEN", "ops_dummy");
    let e = apply_as(&w, &fleet, None, &host).unwrap_err();
    assert_eq!(e.code_str(), "own_session_required");
}

#[test]
fn apply_after_the_1password_value_changed_is_refused_as_stale() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = held_on_fly();
    let id = propose(&w, &fleet, "api/TOKEN").unwrap().plan_id;
    w.set_value("api", "TOKEN", &format!("tok-new-{MARK}"));
    let e = apply_as(&w, &fleet, Some(&id), &person()).unwrap_err();
    assert_eq!(e.code_str(), "stale_plan");
}

/// The staging case on two products: api/TOKEN and web/SESSION are both immutable, held on
/// Fly with 1Password's values, and synced once.
fn two_held_on_fly() -> (World, Fleet) {
    let (w, mut fleet) = world_with_immutable_token();
    fleet
        .products
        .get_mut("web")
        .unwrap()
        .keys
        .get_mut("SESSION")
        .unwrap()
        .immutable = true;
    w.app("myapp")
        .insert(TOKEN.into(), (format!("tok-{MARK}"), false));
    w.app("myapp")
        .insert("FLEET__WEB__SESSION".into(), (format!("ses-{MARK}"), false));
    sync_all(&w, &fleet).unwrap();
    (w, fleet)
}

const BOTH: &[&str] = &["api/TOKEN", "web/SESSION"];

/// An apply of [`BOTH`] whose write of web's delivery item fails; returns its plan id and
/// what it printed.
fn partly_applied(w: &World, fleet: &Fleet) -> (String, String) {
    let keys: Vec<String> = BOTH.iter().map(|k| k.to_string()).collect();
    let id = attest::propose(fleet, "prod", "app", &keys, w)
        .unwrap()
        .plan_id;
    let web = fleet.environments["prod"].targets["app"].delivery_items["web"].clone();
    *w.fail_op_write_on.borrow_mut() = Some(web);
    let (res, out) = apply_keys(w, fleet, BOTH, Some(&id), &person());
    res.expect_err("the injected failure stops the apply");
    *w.fail_op_write_on.borrow_mut() = None;
    (id, out)
}

#[test]
fn a_partial_apply_names_what_was_recorded_before_the_failure() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = two_held_on_fly();
    let (_, out) = partly_applied(&w, &fleet);
    assert!(
        out.contains("recorded before the failure: api/TOKEN"),
        "{out}"
    );
}

#[test]
fn retrying_the_same_plan_after_a_partial_apply_succeeds() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = two_held_on_fly();
    let (id, _) = partly_applied(&w, &fleet);
    let (res, out) = apply_keys(&w, &fleet, BOTH, Some(&id), &person());
    assert!(res.is_ok(), "{out}{:?}", res.err());
}

/// L4: the write re-reads the delivery item; a line recorded for the name since the plan
/// (here opv's own proof, written by a sync) is never overwritten by an attestation.
#[test]
fn recording_over_a_line_written_since_the_plan_is_refused_as_changed() {
    let _person = crate::app::tidy::activate();
    let (w, fleet) = world_with_immutable_token();
    sync_all(&w, &fleet).unwrap();
    let key = crate::app::delivery::evidence_key(&fleet, "prod", "app", "api", &w)
        .unwrap()
        .unwrap();
    let names = [crate::app::delivery::Attest {
        binding: crate::domain::delivery::BindingRef {
            name: TOKEN.into(),
            source: crate::domain::delivery::Source {
                item_id: "planned".into(),
                field: "api/TOKEN".into(),
            },
        },
        store_version: "planned".into(),
        fingerprint: "planned".into(),
        key_check: crate::app::delivery::key_check(&key),
    }];
    let wrote =
        crate::app::delivery::record_attestation(&fleet, "prod", "app", "api", &names, "t", &w);
    assert!(
        matches!(wrote, Ok(crate::app::delivery::AttestWrite::Changed)),
        "{wrote:?}"
    );
}

/// #206 §4.3: an infrastructure key is never attested; there is no 1Password value to
/// vouch for.
#[test]
fn an_infrastructure_key_is_refused_as_not_stored() {
    let (w, mut fleet) = held_on_fly();
    let token = fleet
        .products
        .get_mut("api")
        .unwrap()
        .keys
        .get_mut("TOKEN")
        .unwrap();
    token.value_source = Some(crate::domain::ValueSource::Infrastructure);
    let e = propose(&w, &fleet, "api/TOKEN").unwrap_err();
    assert_eq!(reason(&e), Some(AttestRefusal::NotStored));
}
