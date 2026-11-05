//! A matched set end to end (#262, design `owner-value-ingestion.md` §3.1, §4.7, §5.3, test
//! 71): the real binary, `opv-sim` as `op`, and `opv-e2e-producer` (`tests/sim/producer.rs`)
//! as an idempotent site get-or-create issuer, through the pseudo-terminal driver of
//! `provision.rs`.
//!
//! The set is shaped like the owner's real one, with neutral names: in `prod`, the set
//! `sites` holds five generated secrets (three identity secrets, the gateway key and a hash
//! key), three site keys the producer `site-issuer` returns, and the bundle
//! `web/SITE_SECRETS`, rendered from the producer's three site IDs (intermediates, never
//! stored as keys) and four of the generated secrets as
//! `{"version":1,"sites":[{"siteId","identitySecret","gatewaySecret"}, …]}`. The consumers
//! read the identity secrets and the gateway key as their own fields; the bundle's leaves
//! must equal them.
//!
//! Every value the issuer makes carries the `test-marker-e2e-site-` marker, so the custody
//! canaries here (and the general `no_scenario_snapshot_holds_a_value` gate) can look for
//! it in every output, receipt, file and the snapshot. Each wait is expect-style with the
//! bounded deadline of `provision.rs`; there are no sleeps.

use std::path::Path;

use serde_json::{Value, json};

use super::provision::{at_a_terminal_asking, document, steady};
use crate::coverage::{Run, Scenario, scenario_snapshots, updating};

/// The scenario snapshot this module writes (`tests/e2e/snapshots/scenarios/`).
pub(crate) const SNAPSHOTS: &[&str] = &["provision_sets"];

/// The dev account's user (`tests/e2e/app/world.json`).
const DEV_USER: &str = "UE2EDEVUSER000000000000001";
/// The web boundary's prod vault and item: the set's one item.
const WEB_PROD_VAULT: &str = "vE2EWEBPROD000000000000001";
const WEB_PROD_ITEM: &str = "iE2EWEBPROD000000000000001";

/// The marker every value the issuer makes carries (`tests/sim/producer.rs`).
const SITE_MARKER: &str = "test-marker-e2e-site-";
/// The confirmation's question (§4.4), awaited on stderr before the answer is typed.
const QUESTION: &str = "Type the environment name to provision sites in it:";
/// The issuer's state file in the project: the sites it has made (the issuer's own store,
/// where the site keys live before opv holds them, as `consent.json` in `provision.rs`).
const ISSUER: &str = "project/producer/issuer.json";

/// The generated members, the issuer's site keys, and the bundle: the nine fields.
const GENERATED: [&str; 5] = [
    "PLATFORM_IDENTITY_SECRET",
    "AGENCY_IDENTITY_SECRET",
    "OWNER_IDENTITY_SECRET",
    "SITES_GATEWAY_KEY",
    "USER_HASH_KEY",
];
const SITE_KEYS: [&str; 3] = ["PLATFORM_SITE_KEY", "AGENCY_SITE_KEY", "OWNER_SITE_KEY"];
const BUNDLE: &str = "SITE_SECRETS";
/// The issuer's site names, in the bundle's order.
const SITES: [&str; 3] = ["platform", "agency", "owner"];

fn members() -> Vec<&'static str> {
    GENERATED
        .iter()
        .chain(SITE_KEYS.iter())
        .chain(std::iter::once(&BUNDLE))
        .copied()
        .collect()
}

/// The producer's script (`project/producer/sites.json`): get-or-create the three sites.
fn issuer_script() -> String {
    format!(
        "{:#}\n",
        json!({"sites": {"names": SITES, "issuer": "producer/issuer.json"},
               "record": "producer/seen.json"})
    )
}

/// The contract's addition: the nine `web` keys, the issuer pinned to its script, the set.
fn contract(sha256: &str) -> String {
    let keys: String = members()
        .iter()
        .map(|k| {
            format!("[products.web.keys.{k}]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\n")
        })
        .collect();
    format!(
        r#"
# provision_sets (#262): a matched set of generated secrets, issued site keys and a bundle.
{keys}[producers.site-issuer]
command = ["opv-e2e-producer", "producer/sites.json"]
sha256 = "{sha256}"
outputs = ["platform_site_id", "platform_site_key", "agency_site_id", "agency_site_key",
           "owner_site_id", "owner_site_key"]
timeout = "1m"

[sets.sites]
environments = ["prod"]

[sets.sites.members]
"web/PLATFORM_IDENTITY_SECRET" = {{ generate = {{ hex_bytes = 32 }} }}
"web/AGENCY_IDENTITY_SECRET"   = {{ generate = {{ hex_bytes = 32 }} }}
"web/OWNER_IDENTITY_SECRET"    = {{ generate = {{ hex_bytes = 32 }} }}
"web/SITES_GATEWAY_KEY"        = {{ generate = {{ hex_bytes = 32 }} }}
"web/USER_HASH_KEY"            = {{ generate = {{ hex_bytes = 32 }} }}
"web/PLATFORM_SITE_KEY" = {{ producer = "site-issuer", output = "platform_site_key" }}
"web/AGENCY_SITE_KEY"   = {{ producer = "site-issuer", output = "agency_site_key" }}
"web/OWNER_SITE_KEY"    = {{ producer = "site-issuer", output = "owner_site_key" }}

[sets.sites.members."web/SITE_SECRETS".template]
version = 1
sites = [
  {{ siteId = "${{site-issuer.platform_site_id}}", identitySecret = "${{web/PLATFORM_IDENTITY_SECRET}}", gatewaySecret = "${{web/SITES_GATEWAY_KEY}}" }},
  {{ siteId = "${{site-issuer.agency_site_id}}",   identitySecret = "${{web/AGENCY_IDENTITY_SECRET}}",   gatewaySecret = "${{web/SITES_GATEWAY_KEY}}" }},
  {{ siteId = "${{site-issuer.owner_site_id}}",    identitySecret = "${{web/OWNER_IDENTITY_SECRET}}",    gatewaySecret = "${{web/SITES_GATEWAY_KEY}}" }},
]
"#
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// The app with the `sites` set, the issuer's script pinned, and the prod web vault
/// writable by the dev user.
fn sites() -> Scenario {
    let text = issuer_script();
    let pin = sha256_hex(text.as_bytes());
    Scenario::new()
        .world(|w| {
            for v in w["op"]["vaults"].as_array_mut().expect("vaults") {
                if v["id"] == WEB_PROD_VAULT {
                    v["users"] = json!([{"id": DEV_USER, "name": "E2E Dev",
                                         "email": "dev@example.com"}]);
                }
            }
        })
        .file("project/producer/sites.json", &text)
        .config(|c| c + &contract(&pin))
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// `opv provision sites --env prod`, with `extra` appended.
fn provision(extra: &[&str]) -> Vec<String> {
    let mut v = args(&["provision", "sites", "--env", "prod"]);
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

/// `opv <args>` at a person's terminal, answering `prod` when asked.
fn at_a_terminal(s: &Scenario, args: &[String]) -> Run {
    at_a_terminal_asking(s, args, QUESTION, Some("prod"))
}

/// `opv <args>` at a person's terminal that must not ask (an unchanged set, a refusal).
fn at_a_terminal_unasked(s: &Scenario, args: &[String]) -> Run {
    at_a_terminal_asking(s, args, QUESTION, None)
}

fn read(s: &Scenario, rel: &str) -> String {
    std::fs::read_to_string(s.path(rel)).unwrap_or_default()
}

fn world(s: &Scenario) -> Value {
    serde_json::from_str(&read(s, "world/world.json")).expect("world")
}

/// The prod web item in the simulated vault.
fn prod_item(s: &Scenario) -> Value {
    world(s)["op"]["items"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|i| i["id"] == WEB_PROD_ITEM)
        .cloned()
        .expect("the prod web item")
}

/// The value the prod web item holds for `label`, if any.
fn stored(s: &Scenario, label: &str) -> Option<String> {
    prod_item(s)["fields"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|f| f["label"] == label)
        .and_then(|f| f["value"].as_str().map(str::to_string))
}

/// Every member's stored value, in [`members`] order.
fn stored_members(s: &Scenario) -> Vec<Option<String>> {
    members().iter().map(|k| stored(s, k)).collect()
}

/// The issuer's state: its sites and how many it created.
fn issuer(s: &Scenario) -> Value {
    serde_json::from_str(&read(s, ISSUER)).expect("issuer state")
}

/// How many times opv-sim saw `op item edit` (one per item write).
fn item_edits(s: &Scenario) -> usize {
    read(s, "world/calls.log")
        .lines()
        .filter(|l| l.contains("item edit"))
        .count()
}

/// [`sites`], provisioned once at a terminal (the run must write).
fn provisioned() -> Scenario {
    let s = sites();
    let run = at_a_terminal(&s, &provision(&["--json"]));
    assert_eq!(
        document(&run)["result"],
        "written",
        "{}{}",
        run.stdout,
        run.stderr
    );
    s
}

/// [`provisioned`], then `labels` removed from the item: a partial set.
fn partial_without(labels: &'static [&'static str]) -> Scenario {
    provisioned().world(move |w| {
        for item in w["op"]["items"].as_array_mut().expect("items") {
            if item["id"] == WEB_PROD_ITEM {
                item["fields"]
                    .as_array_mut()
                    .expect("fields")
                    .retain(|f| !labels.iter().any(|l| f["label"] == *l));
            }
        }
    })
}

/// The partial set the docs walk through: one issued site key and one generated secret lost.
fn partial() -> Scenario {
    partial_without(&["PLATFORM_SITE_KEY", "USER_HASH_KEY"])
}

/// [`provisioned`], then the gateway key changed under the bundle: an inconsistent set.
fn inconsistent() -> Scenario {
    provisioned().world(|w| {
        for item in w["op"]["items"].as_array_mut().expect("items") {
            if item["id"] == WEB_PROD_ITEM {
                for f in item["fields"].as_array_mut().expect("fields") {
                    if f["label"] == "SITES_GATEWAY_KEY" {
                        f["value"] = json!("test-marker-e2e-site-gateway-edited-by-hand");
                    }
                }
            }
        }
    })
}

/// The set's state as `ready prod --json` reports it.
fn ready_state(s: &Scenario) -> Value {
    let doc = document(&s.opv(&args(&["ready", "prod", "--json"])));
    doc["sets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| e["set"] == "sites")
        .map(|e| e["state"].clone())
        .unwrap_or(Value::Null)
}

// --- 71: the matched set ------------------------------------------------------------------

/// 71: one run writes all nine members in one checked write: one item edit, one version
/// step, verified at the version it made.
#[test]
fn the_set_is_written_in_one_checked_write() {
    let s = sites();
    let doc = document(&at_a_terminal(&s, &provision(&["--json"])));
    let item = &doc["item"];
    assert_eq!(
        (
            doc["result"].clone(),
            doc["members"].as_array().map(Vec::len),
            item_edits(&s),
            item["version_after"].as_u64() == item["version_before"].as_u64().map(|v| v + 1),
            item["verified_at"] == item["version_after"],
        ),
        (json!("written"), Some(9), 1, true, true),
        "{doc}"
    );
}

/// 71: after the run, every member holds a value.
#[test]
fn every_member_is_stored() {
    let s = provisioned();
    let missing: Vec<&str> = members()
        .into_iter()
        .filter(|k| stored(&s, k).is_none())
        .collect();
    assert_eq!(missing, Vec::<&str>::new());
}

/// 71: the bundle's leaves equal the consumers' own fields and the issuer's site IDs.
#[test]
fn the_bundle_leaves_equal_the_consumer_fields() {
    let s = provisioned();
    let f = |k: &str| stored(&s, k).expect(k);
    let iss = issuer(&s);
    let gateway = f("SITES_GATEWAY_KEY");
    let want = json!({"version": 1, "sites": [
        {"siteId": iss["sites"]["platform"]["id"], "identitySecret": f("PLATFORM_IDENTITY_SECRET"),
         "gatewaySecret": gateway},
        {"siteId": iss["sites"]["agency"]["id"], "identitySecret": f("AGENCY_IDENTITY_SECRET"),
         "gatewaySecret": gateway},
        {"siteId": iss["sites"]["owner"]["id"], "identitySecret": f("OWNER_IDENTITY_SECRET"),
         "gatewaySecret": gateway},
    ]});
    let got: Value = serde_json::from_str(&f(BUNDLE)).expect("the bundle is JSON");
    assert!(got == want, "the bundle does not match the stored members");
}

/// 71: the site keys stored are the ones the issuer made.
#[test]
fn the_site_keys_are_the_issuers() {
    let s = provisioned();
    let iss = issuer(&s);
    let differ: Vec<&str> = SITE_KEYS
        .iter()
        .zip(SITES)
        .filter(|(k, site)| stored(&s, k).as_deref() != iss["sites"][*site]["key"].as_str())
        .map(|(k, _)| *k)
        .collect();
    assert_eq!(differ, Vec::<&str>::new());
}

/// 71: `ready` reads the provisioned set as `complete`.
#[test]
fn ready_reads_the_set_as_complete() {
    assert_eq!(ready_state(&provisioned()), json!("complete"));
}

/// 71: a second run is `unchanged`: no question, no producer, no item edit.
#[test]
fn a_second_run_is_unchanged() {
    let s = provisioned();
    let (edits, created) = (item_edits(&s), issuer(&s)["created"].clone());
    let run = at_a_terminal_unasked(&s, &provision(&["--json"]));
    assert_eq!(
        (
            document(&run)["result"].clone(),
            item_edits(&s) - edits,
            issuer(&s)["created"].clone()
        ),
        (json!("unchanged"), 0, created),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

/// §4.7: `ready` reads a set with two members lost as `partial`.
#[test]
fn ready_reads_a_partial_set_as_partial() {
    assert_eq!(ready_state(&partial()), json!("partial"));
}

/// §4.7: without `--fill-missing` a partial set is refused, and nothing is written.
#[test]
fn a_partial_set_without_fill_missing_is_refused() {
    let s = partial();
    let edits = item_edits(&s);
    let run = at_a_terminal_unasked(&s, &provision(&["--json"]));
    assert_eq!(
        (document(&run)["ok"].clone(), item_edits(&s) - edits),
        (json!(false), 0),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

/// 71, §4.7: `--fill-missing` completes a partial set in one write and keeps every present
/// value; the issuer is asked again and returns its site (a get, not a create), so the lost
/// site key comes back as it was.
#[test]
fn fill_missing_completes_a_partial_set_keeping_the_present_values() {
    let s = provisioned();
    let before = stored_members(&s);
    let s = s.world(|w| {
        for item in w["op"]["items"].as_array_mut().expect("items") {
            if item["id"] == WEB_PROD_ITEM {
                item["fields"]
                    .as_array_mut()
                    .expect("fields")
                    .retain(|f| f["label"] != "PLATFORM_SITE_KEY" && f["label"] != "USER_HASH_KEY");
            }
        }
    });
    let edits = item_edits(&s);
    let run = at_a_terminal(&s, &provision(&["--fill-missing", "--json"]));
    let after = stored_members(&s);
    let kept: Vec<bool> = members()
        .iter()
        .zip(before.iter().zip(&after))
        .filter(|(k, _)| **k != "USER_HASH_KEY")
        .map(|(_, (b, a))| b == a)
        .collect();
    let hash_key = members()
        .iter()
        .position(|k| *k == "USER_HASH_KEY")
        .expect("member");
    assert_eq!(
        (
            document(&run)["result"].clone(),
            item_edits(&s) - edits,
            kept.iter().all(|k| *k),
            after[hash_key].is_some(),
            issuer(&s)["created"].clone(),
        ),
        (json!("written"), 1, true, true, json!(3)),
        "{}{}",
        run.stdout,
        run.stderr
    );
}

/// 71: after `--fill-missing`, `ready` reads the set as `complete` again.
#[test]
fn ready_reads_a_filled_set_as_complete() {
    let s = partial();
    at_a_terminal(&s, &provision(&["--fill-missing", "--json"]));
    assert_eq!(ready_state(&s), json!("complete"));
}

/// §4.5: `ready` reads a set whose bundle disagrees with a member as `inconsistent`.
#[test]
fn ready_reads_a_disagreeing_bundle_as_inconsistent() {
    assert_eq!(ready_state(&inconsistent()), json!("inconsistent"));
}

// --- custody canaries -----------------------------------------------------------------------

/// Every regular file under the scenario root that holds `needle`, except the vault (where
/// the values belong) and the issuer's own state (where the site keys came from).
fn files_holding(s: &Scenario, needle: &str) -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let t = e.file_type().expect("file type");
            if t.is_dir() {
                walk(&e.path(), out);
            } else if t.is_file() {
                out.push(e.path());
            }
        }
    }
    let root = s.path("world").parent().expect("root").to_path_buf();
    let mut files = Vec::new();
    walk(&root, &mut files);
    files
        .into_iter()
        .filter(|p| *p != s.path("world/world.json") && *p != s.path(ISSUER))
        .filter(|p| {
            std::fs::read(p)
                .map(|b| String::from_utf8_lossy(&b).contains(needle))
                .unwrap_or(false)
        })
        .map(|p| p.display().to_string())
        .collect()
}

/// Write, re-run, lose two members and fill them, in text and `--json`: every output and
/// receipt, with the values the vault ends up holding.
fn custody_runs() -> (Scenario, String) {
    let s = sites();
    let mut all = String::new();
    let mut take = |r: Run| all.push_str(&format!("{}{}", r.stdout, r.stderr));
    take(at_a_terminal(&s, &provision(&[])));
    take(at_a_terminal_unasked(&s, &provision(&[])));
    take(at_a_terminal_unasked(&s, &provision(&["--json"])));
    let s = s.world(|w| {
        for item in w["op"]["items"].as_array_mut().expect("items") {
            if item["id"] == WEB_PROD_ITEM {
                item["fields"]
                    .as_array_mut()
                    .expect("fields")
                    .retain(|f| f["label"] != "AGENCY_SITE_KEY");
            }
        }
    });
    let mut take = |r: Run| all.push_str(&format!("{}{}", r.stdout, r.stderr));
    take(at_a_terminal(&s, &provision(&["--fill-missing", "--json"])));
    take(s.opv(&args(&["ready", "prod"])));
    take(s.opv(&args(&["ready", "prod", "--json"])));
    take(s.opv(&provision(&["--dry-run", "--json"])));
    (s, all)
}

/// The issuer's marker values, and every member value the vault holds, reach no output or
/// receipt of any run.
#[test]
fn no_issued_or_made_value_reaches_an_output_or_receipt() {
    let (s, all) = custody_runs();
    let values: Vec<String> = stored_members(&s).into_iter().flatten().collect();
    let leaked: Vec<&String> = values.iter().filter(|v| all.contains(v.as_str())).collect();
    assert!(
        values.len() == 9 && leaked.is_empty() && !all.contains(SITE_MARKER),
        "{} values held; leaked {}, marker on output: {}",
        values.len(),
        leaked.len(),
        all.contains(SITE_MARKER)
    );
}

/// No file but the vault and the issuer's own state holds an issued value.
#[test]
fn no_file_but_the_vault_holds_an_issued_value() {
    let (s, _) = custody_runs();
    assert_eq!(files_holding(&s, SITE_MARKER), Vec::<String>::new());
}

/// The committed snapshot holds no issued value.
#[test]
fn the_snapshot_holds_no_issued_value() {
    let snap = std::fs::read_to_string(scenario_snapshots().join("provision_sets.snap"))
        .expect("provision_sets snapshot");
    assert!(
        !snap.contains(SITE_MARKER),
        "provision_sets.snap holds an issued value"
    );
}

// --- the snapshot ---------------------------------------------------------------------------

fn section(snap: &mut String, label: &str, run: &Run) {
    snap.push_str(&format!(
        "\n## {label} exit: {}\n## {label} stdout\n{}\n## {label} stderr\n{}",
        run.code.map_or("killed".into(), |c| c.to_string()),
        steady(&run.stdout),
        steady(&run.stderr),
    ));
}

/// A case: its label, its world, how it runs (`true`: at a terminal answering `prod`),
/// and its arguments.
type Case = (&'static str, fn() -> Scenario, Runner, Vec<String>);
type Runner = fn(&Scenario, &[String]) -> Run;

fn plain(s: &Scenario, a: &[String]) -> Run {
    s.opv(a)
}

/// Each case's telling runs, text and `--json`, each on a fresh world.
fn transcript() -> String {
    let mut snap = String::from("# provision_sets: a matched set through the real binary\n");
    let cases: Vec<Case> = vec![
        ("dry run", sites, plain, provision(&["--dry-run"])),
        ("written", sites, at_a_terminal, provision(&[])),
        (
            "second run",
            provisioned,
            at_a_terminal_unasked,
            provision(&[]),
        ),
        ("partial ready", partial, plain, args(&["ready", "prod"])),
        (
            "partial refused",
            partial,
            at_a_terminal_unasked,
            provision(&[]),
        ),
        (
            "partial dry run",
            partial,
            plain,
            provision(&["--fill-missing", "--dry-run"]),
        ),
        (
            "fill missing",
            partial,
            at_a_terminal,
            provision(&["--fill-missing"]),
        ),
        (
            "inconsistent ready",
            inconsistent,
            plain,
            args(&["ready", "prod"]),
        ),
        (
            "inconsistent refused",
            inconsistent,
            at_a_terminal_unasked,
            provision(&[]),
        ),
    ];
    for (label, scenario, runner, a) in cases {
        section(
            &mut snap,
            &format!("{label} text"),
            &runner(&scenario(), &a),
        );
        let mut j = a.clone();
        j.push("--json".into());
        section(
            &mut snap,
            &format!("{label} --json"),
            &runner(&scenario(), &j),
        );
    }
    snap
}

#[test]
fn the_provision_sets_scenarios_match_their_snapshot() {
    let got = transcript();
    let path = scenario_snapshots().join(format!("{}.snap", SNAPSHOTS[0]));
    if updating() {
        std::fs::write(&path, &got).expect("write snapshot");
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        got,
        want,
        "{} differs from its snapshot; review and rerun with UPDATE_SNAPSHOTS=1",
        path.display()
    );
}
