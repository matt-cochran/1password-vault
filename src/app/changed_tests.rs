//! `opv changed` (delivery-transports §2.2): the recorded `source versions` against the
//! items' current versions, read value-free through `op read` and `op item list`.

use serde_json::json;

use super::*;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

const VALUES_VAULT: &str = "vlt-values";
const STATE_VAULT: &str = "vlt-state";
const VALUES_ITEM: &str = "itm-values";
const DELIVERY_ITEM: &str = "itm-delivery";

/// A fleet with one product `api` and one target `app`; `delivery_items` is the TOML body of
/// the target's map (empty for "no delivery item recorded").
fn fleet_with(delivery_items: &str) -> crate::domain::Fleet {
    let toml = format!(
        "[products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
         [environments.prod]\n\
         boundaries.api = {{ vault_id = \"{VALUES_VAULT}\", item_id = \"{VALUES_ITEM}\" }}\n\
         [environments.prod.targets.app]\nstate_vault_id = \"{STATE_VAULT}\"\n\
         fly.app = \"myapp\"\nfly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n\
         delivery_items = {{ {delivery_items} }}\n"
    );
    crate::config::parse(&toml).unwrap()
}

/// A fleet with two products delivered by one target, both sourced from the one vault.
fn fleet_two_products() -> crate::domain::Fleet {
    let toml = format!(
        "[products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
         [products.web.keys.SESSION]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
         [environments.prod]\n\
         boundaries.api = {{ vault_id = \"{VALUES_VAULT}\", item_id = \"{VALUES_ITEM}\" }}\n\
         boundaries.web = {{ vault_id = \"{VALUES_VAULT}\", item_id = \"{VALUES_ITEM}\" }}\n\
         [environments.prod.targets.app]\nstate_vault_id = \"{STATE_VAULT}\"\n\
         fly.app = \"myapp\"\nfly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n\
         delivery_items = {{ api = \"itm-api\", web = \"itm-web\" }}\n"
    );
    crate::config::parse(&toml).unwrap()
}

/// The `op item list` reply naming `VALUES_ITEM` at version `v`.
fn listed(v: u64) -> Output {
    Output::success(format!("[{{\"id\":\"{VALUES_ITEM}\",\"version\":{v}}}]"))
}

/// The delivery item's recorded `source versions` field: the one source item at version `v`.
fn read(v: u64) -> Output {
    Output::success(format!("v1|{VALUES_ITEM}|{v}\n"))
}

/// Run `opv changed prod` and return its result and stdout.
fn run(r: &FakeRunner, fleet: &crate::domain::Fleet, json: bool) -> (Result<i32, Error>, Vec<u8>) {
    let mut out = Vec::new();
    let res = super::run(fleet, "prod", None, &[], r, json, &mut out);
    (res, out)
}

/// The `state` of the sole placement in a `--json` reply.
fn state_of(body: &[u8]) -> String {
    let doc: serde_json::Value = serde_json::from_slice(body).unwrap();
    doc["placements"][0]["state"].as_str().unwrap().to_string()
}

/// The number of recorded `op item list` calls.
fn item_lists(r: &FakeRunner) -> usize {
    r.calls
        .borrow()
        .iter()
        .filter(|c| c.program == "op" && c.args.first().map(String::as_str) == Some("item"))
        .filter(|c| c.args.get(1).map(String::as_str) == Some("list"))
        .count()
}

/// The number of recorded `op item get` calls.
fn item_gets(r: &FakeRunner) -> usize {
    r.calls
        .borrow()
        .iter()
        .filter(|c| c.program == "op" && c.args.first().map(String::as_str) == Some("item"))
        .filter(|c| c.args.get(1).map(String::as_str) == Some("get"))
        .count()
}

#[test]
fn an_unchanged_source_version_is_zero() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([listed(8), read(8)]);
    assert_eq!(run(&r, &fleet, false).0.unwrap(), 0);
}

#[test]
fn a_version_bump_is_source_changed() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([listed(8), read(7)]);
    assert_eq!(run(&r, &fleet, false).0.unwrap(), 10);
}

#[test]
fn a_change_names_the_item_and_both_versions() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([listed(8), read(7)]);
    let (_, out) = run(&r, &fleet, false);
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains("itm-values 7 -> 8")
    );
}

#[test]
fn a_source_item_that_is_gone_is_a_change() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([Output::success("[]"), read(7)]);
    assert_eq!(run(&r, &fleet, false).0.unwrap(), 10);
}

#[test]
fn a_missing_source_versions_field_is_no_record() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([listed(8)]);
    r.push_with_stderr(
        Output::failure(1),
        "\"source versions\" isn't a field in the item.",
    );
    let (res, out) = run(&r, &fleet, true);
    assert_eq!(
        (res.unwrap(), state_of(&out)),
        (10, "no_record".to_string())
    );
}

#[test]
fn a_missing_delivery_item_is_no_record() {
    let fleet = fleet_with("");
    let r = FakeRunner::new([listed(8)]);
    let (res, out) = run(&r, &fleet, true);
    assert_eq!(
        (res.unwrap(), state_of(&out)),
        (10, "no_record".to_string())
    );
}

#[test]
fn an_op_failure_keeps_its_own_exit() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([]);
    r.push_with_stderr(Output::failure(1), "unexpected 1Password failure");
    let (res, _) = run(&r, &fleet, false);
    assert!(!matches!(res, Ok(0) | Ok(10)));
}

#[test]
fn no_op_item_get_is_ever_recorded() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([listed(8), read(8)]);
    let _ = run(&r, &fleet, false);
    assert_eq!(item_gets(&r), 0);
}

#[test]
fn no_value_field_is_ever_read() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([listed(8), read(8)]);
    let _ = run(&r, &fleet, false);
    let reads: Vec<Vec<String>> = r
        .calls
        .borrow()
        .iter()
        .filter(|c| c.program == "op" && c.args.first().map(String::as_str) == Some("read"))
        .map(|c| c.args.clone())
        .collect();
    assert!(
        !reads.is_empty()
            && reads
                .iter()
                .all(|a| a.last().is_some_and(|r| r.ends_with("/source versions")))
    );
}

#[test]
fn one_op_item_list_covers_the_whole_vault() {
    let fleet = fleet_two_products();
    let r = FakeRunner::new([
        listed(8),
        Output::success(format!("v1|{VALUES_ITEM}|8\n")),
        Output::success(format!("v1|{VALUES_ITEM}|8\n")),
    ]);
    let _ = run(&r, &fleet, false);
    assert_eq!(item_lists(&r), 1);
}

#[test]
fn the_json_reply_matches_the_contract() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([listed(8), read(7)]);
    let (_, out) = run(&r, &fleet, true);
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        doc,
        json!({
            "schema_version": 3,
            "environment": "prod",
            "changed": true,
            "placements": [{
                "product": "api",
                "target": "app",
                "state": "changed",
                "items": [{"item_id": "itm-values", "recorded": 7, "current": 8}],
            }],
            "next": "opv sync prod --deploy",
            "do": null,
        })
    );
}

#[test]
fn a_missing_delivery_item_nexts_bootstrap() {
    let fleet = fleet_with("");
    let r = FakeRunner::new([listed(8)]);
    let (_, out) = run(&r, &fleet, true);
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["next"], "opv bootstrap");
}

#[test]
fn a_missing_source_versions_field_nexts_the_sync() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([listed(8)]);
    r.push_with_stderr(
        Output::failure(1),
        "\"source versions\" isn't a field in the item.",
    );
    let (_, out) = run(&r, &fleet, true);
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["next"], "opv sync prod --deploy");
}

#[test]
fn a_change_prints_the_next_step_in_text() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([listed(8), read(7)]);
    let (_, out) = run(&r, &fleet, false);
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains("Next: opv sync prod --deploy")
    );
}

#[test]
fn a_lone_429_is_not_a_rate_limit() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([]);
    r.push_with_stderr(Output::failure(1), "op failed with status 429");
    let (res, _) = run(&r, &fleet, false);
    assert!(!res.unwrap_err().mentions("limited the request rate"));
}

#[test]
fn a_guarded_environment_is_planned_before_the_sync() {
    let toml = format!(
        "[products.api.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\
         [environments.prod]\nconfirm_env = true\n\
         boundaries.api = {{ vault_id = \"{VALUES_VAULT}\", item_id = \"{VALUES_ITEM}\" }}\n\
         [environments.prod.targets.app]\nstate_vault_id = \"{STATE_VAULT}\"\n\
         fly.app = \"myapp\"\nfly.secret_name = \"FLEET__{{PRODUCT}}__{{KEY}}\"\n\
         delivery_items = {{ api = \"{DELIVERY_ITEM}\" }}\n"
    );
    let fleet = crate::config::parse(&toml).unwrap();
    let r = FakeRunner::new([listed(8), read(7)]);
    let (_, out) = run(&r, &fleet, true);
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(doc["next"], "opv plan prod");
}

#[test]
fn a_rate_limited_reply_is_unavailable() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([]);
    r.push_with_stderr(Output::failure(1), "429 Too Many Requests");
    let (res, _) = run(&r, &fleet, false);
    assert_eq!(res.unwrap_err().exit_code(), 9);
}

#[test]
fn a_rate_limited_reply_names_the_retry_time() {
    let fleet = fleet_with(&format!("api = \"{DELIVERY_ITEM}\""));
    let r = FakeRunner::new([]);
    r.push_with_stderr(
        Output::failure(1),
        "429 Too Many Requests. Retry after 30 seconds.",
    );
    let (res, _) = run(&r, &fleet, false);
    assert!(res.unwrap_err().mentions("30"));
}
