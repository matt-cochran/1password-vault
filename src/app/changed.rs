//! `opv changed <env>` (delivery-transports §2.2): has a source item changed since the
//! last sync? Read-only, value-free and exact.
//!
//! A sync records, in each placement's delivery item, one `v1|<item_id>|<version>` line per
//! source item it read (C2, `src/app/delivery.rs`). This command reads those lines back
//! through `op read` of **that one field** — never `op item get`, which would also expose
//! the delivery item's evidence key — and compares each recorded version with the item's
//! current `version` from `op item list --vault <vault> --format json`, listed once per
//! vault however many items are watched (FM-12).
//!
//! Per placement (product and target):
//!
//! | state | meaning |
//! |---|---|
//! | `unchanged` | every recorded version is still current |
//! | `changed` | a version differs (or the source item is gone) |
//! | `no_record` | no delivery item is recorded, or the `source versions` field is absent |
//!
//! `changed` exits **10** (`Cause::SourceChanged`, `source_changed`): a result, not a
//! failure (`ok: true` in `--json`), whose next step is the sync. A call that failed for any
//! other reason keeps its own exit code, never 0.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use serde::Serialize;
use serde_json::json;

use super::write_err;
use crate::adapters::onepassword::{OP, op_spawn_error, unanswered, unreadable_reply};
use crate::adapters::onepassword_diagnose::Facts;
use crate::adapters::onepassword_diagnose_items::diagnose_item_call;
use crate::cause::{
    Cause, DiagnoseContext, EnvName, Invocation, ResourceKind, ResourceName, ResourceRef, System,
    Unanswered, Upstream,
};
use crate::domain::Fleet;
use crate::error::Error;
use crate::runner::{Call, CommandRunner, Outcome, Output};

/// The one field a sync writes and this command reads back (never `op item get`).
const SOURCE_VERSIONS_FIELD: &str = "source versions";

/// Every non-zero exit status: a failed read is diagnosed at once, never retried blindly
/// (P16, as in `src/adapters/onepassword.rs`). A rate-limit reply is classified below.
const ANY_FAILURE: [i32; 255] = {
    let mut codes = [0; 255];
    let mut i = 0;
    while i < 255 {
        codes[i] = i as i32 + 1;
        i += 1;
    }
    codes
};

/// One placement to check: a product and the target that delivers it.
struct Placement<'a> {
    product: String,
    target: &'a str,
    state_vault: &'a str,
    delivery_item: Option<&'a str>,
}

/// One source item that moved since the last sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ItemChange {
    #[serde(rename = "item_id")]
    item: String,
    #[serde(rename = "recorded")]
    was: u64,
    /// The current version; absent when no listed vault holds the item any more.
    #[serde(rename = "current", skip_serializing_if = "Option::is_none")]
    now: Option<u64>,
}

/// One placement's answer, as `opv changed --json` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PlacementReport {
    product: String,
    target: String,
    state: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    items: Vec<ItemChange>,
}

/// One `v1|<item_id>|<version>` line the delivery item recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Recorded {
    item: String,
    version: u64,
}

/// One row of `op item list --vault <vault> --format json`.
#[derive(Debug, serde::Deserialize)]
struct ListRow {
    id: String,
    #[serde(default)]
    version: u64,
}

/// `opv changed <env> [--product p] [--target t] [--json]`: read-only. Every placement of
/// the product (each target of `env` that delivers it), or only those on `targets`; each
/// judged on its own. Returns the process exit code (0 unchanged, 10 changed or
/// `no_record`).
#[allow(clippy::too_many_arguments)]
pub fn run(
    fleet: &Fleet,
    env_name: &str,
    only: Option<&str>,
    targets: &[String],
    r: &dyn CommandRunner,
    json: bool,
    out: &mut dyn Write,
) -> Result<i32, Error> {
    // A misspelt product would otherwise match nothing and pass (exit 0) having checked
    // nothing.
    super::check_product(fleet, only, Some(env_name))?;
    let names = super::resolve_targets(fleet, env_name, targets, "changed")?;
    let placements = placements(fleet, env_name, &names, only)?;
    if placements.is_empty() {
        return Err(Cause::NothingInScope {
            env: EnvName::new(env_name),
            what: crate::cause::Scope::NoTargets {
                products: match only {
                    Some(p) => vec![crate::cause::ProductName::new(p)],
                    None => fleet
                        .products
                        .keys()
                        .map(crate::cause::ProductName::new)
                        .collect(),
                },
            },
        }
        .into());
    }

    let host = || crate::host::Host::detect();
    let facts = Facts::from_process_env();
    let versions = current_versions(fleet, env_name, r, &host, &facts)?;

    let mut reports = Vec::with_capacity(placements.len());
    for p in &placements {
        reports.push(check_placement(env_name, p, &versions, r, &host, &facts)?);
    }
    let changed = reports.iter().any(|p| p.state != "unchanged");
    let missing_item = placements.iter().any(|p| p.delivery_item.is_none());
    let confirm_env = fleet.environment(env_name)?.confirm_env;

    report(
        out,
        env_name,
        &reports,
        changed,
        missing_item,
        confirm_env,
        json,
    )?;
    Ok(if changed { 10 } else { 0 })
}

/// The placements to check: every product each target in `names` delivers with at least one
/// secret binding (the same set a sync records), or only `only`'s.
fn placements<'a>(
    fleet: &'a Fleet,
    env_name: &str,
    names: &'a [String],
    only: Option<&str>,
) -> Result<Vec<Placement<'a>>, Error> {
    let e = fleet.environment(env_name)?;
    let mut out = Vec::new();
    for target in names {
        let Some(t) = e.targets.get(target) else {
            continue;
        };
        for product in fleet.products.keys() {
            if only.is_some_and(|o| o != product) {
                continue;
            }
            if !fleet.delivers(env_name, target, product) {
                continue;
            }
            if super::delivery::bindings(fleet, env_name, target, product)?.is_empty() {
                continue;
            }
            out.push(Placement {
                product: product.clone(),
                target,
                state_vault: &t.state_vault_id,
                delivery_item: t.delivery_items.get(product).map(String::as_str),
            });
        }
    }
    Ok(out)
}

/// Every vault holding a source item the environment watches, once each (FM-12), plus the
/// manifest vault when the configuration itself lives in 1Password.
fn source_vaults(fleet: &Fleet, env_name: &str) -> Result<Vec<String>, Error> {
    let e = fleet.environment(env_name)?;
    let mut vaults = BTreeSet::new();
    for b in e.boundaries.values() {
        vaults.insert(b.vault_id.clone());
    }
    if let crate::cause::ConfigSource::Manifest { vault, .. } = &fleet.read_from.0 {
        vaults.insert(vault.as_str().to_string());
    }
    Ok(vaults.into_iter().collect())
}

/// Item id → current `version`, from one `op item list --vault <vault> --format json` per
/// source vault.
fn current_versions(
    fleet: &Fleet,
    env_name: &str,
    r: &dyn CommandRunner,
    host: &dyn Fn() -> crate::host::Host,
    facts: &Facts,
) -> Result<BTreeMap<String, u64>, Error> {
    let mut versions = BTreeMap::new();
    for vault in source_vaults(fleet, env_name)? {
        let args = [
            "item",
            "list",
            "--vault",
            vault.as_str(),
            "--format",
            "json",
        ];
        let ctx = vault_context(env_name, fleet, &vault);
        let out = read_op(r, host, &args, &ctx, facts)?;
        if out.stdout.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let rows: Vec<ListRow> =
            serde_json::from_slice(&out.stdout).map_err(|e| unreadable_reply(&args, &e))?;
        for row in rows {
            versions.insert(row.id, row.version);
        }
    }
    Ok(versions)
}

/// Judge one placement: no delivery item, a missing field, or the recorded versions against
/// the current ones.
fn check_placement(
    env_name: &str,
    p: &Placement,
    versions: &BTreeMap<String, u64>,
    r: &dyn CommandRunner,
    host: &dyn Fn() -> crate::host::Host,
    facts: &Facts,
) -> Result<PlacementReport, Error> {
    let state = |state, items| PlacementReport {
        product: p.product.clone(),
        target: p.target.to_string(),
        state,
        items,
    };
    let Some(item) = p.delivery_item else {
        return Ok(state("no_record", Vec::new()));
    };
    let reference = format!("op://{}/{}/{SOURCE_VERSIONS_FIELD}", p.state_vault, item);
    let args = ["read", reference.as_str()];
    let ctx = delivery_item_context(env_name, p, item);
    let out = match read_op_raw(r, host, &args, &ctx, facts) {
        Ok(out) => out,
        // A field or item that is not there is `no_record` (an older opv synced it), never a
        // failure: the step is the sync, not a fix.
        Err(ReadFailure::NoRecord) => return Ok(state("no_record", Vec::new())),
        Err(ReadFailure::Error(e)) => return Err(e),
    };
    if out.stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(state("no_record", Vec::new()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let recorded = parse_recorded(&text).ok_or_else(|| unreadable_field(&args))?;
    let changes: Vec<ItemChange> = recorded
        .into_iter()
        .filter_map(|rec| match versions.get(&rec.item) {
            Some(now) if *now == rec.version => None,
            Some(now) => Some(ItemChange {
                item: rec.item,
                was: rec.version,
                now: Some(*now),
            }),
            None => Some(ItemChange {
                item: rec.item,
                was: rec.version,
                now: None,
            }),
        })
        .collect();
    if changes.is_empty() {
        Ok(state("unchanged", Vec::new()))
    } else {
        Ok(state("changed", changes))
    }
}

/// The recorded lines, or `None` when the field holds something opv cannot read (an empty
/// field is [`check_placement`]'s `no_record` before this is called).
fn parse_recorded(text: &str) -> Option<Vec<Recorded>> {
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.trim().split('|');
        let recorded = match (parts.next(), parts.next(), parts.next()) {
            (Some("v1"), Some(item), Some(v)) => v.parse().ok().map(|version| Recorded {
                item: item.to_string(),
                version,
            }),
            _ => None,
        };
        out.push(recorded?);
    }
    Some(out)
}

/// A read that failed: the field or item is missing (`NoRecord`), or the call failed for
/// another reason and keeps its own cause.
enum ReadFailure {
    NoRecord,
    Error(Error),
}

/// Read `args` and, on a failure, decide `no_record` versus the call's own cause. An `op`
/// read is diagnosed at once on failure (never retried blindly); a rate-limit reply is
/// `Unavailable{RateLimited}` (exit 9), with the retry time when the reply gives one.
fn read_op_raw(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> crate::host::Host,
    args: &[&str],
    ctx: &DiagnoseContext,
    facts: &Facts,
) -> Result<Output, ReadFailure> {
    let call = Call::new(OP, args);
    let outcome = match r.read(&call, &ANY_FAILURE) {
        Ok(o) => o,
        Err(e) => return Err(ReadFailure::Error(op_spawn_error(r, &e, host))),
    };
    match outcome {
        Outcome::Done(o) => Ok(o),
        Outcome::Unknown { .. } => Err(ReadFailure::Error(unanswered(&call))),
        Outcome::Refused(_) => {
            let Some(failure) = crate::runner::take_failure() else {
                return Err(ReadFailure::Error(
                    Cause::Bug {
                        site: "changed: a refused op read left no failure",
                    }
                    .into(),
                ));
            };
            if let Some(retry_after_seconds) = rate_limited(failure.stderr()) {
                return Err(ReadFailure::Error(failed_with_evidence(
                    Cause::Unavailable {
                        system: System::OnePassword,
                        why: Unanswered::RateLimited {
                            retry_after_seconds,
                        },
                        attempts: failure.seen.attempts(),
                        seen: failure.seen.clone(),
                    },
                    &failure,
                )));
            }
            if missing_field_reply(failure.stderr()) {
                return Err(ReadFailure::NoRecord);
            }
            let cause = diagnose_item_call(failure.seen.clone(), failure.stderr(), ctx, facts);
            Err(ReadFailure::Error(failed_with_evidence(cause, &failure)))
        }
    }
}

/// One `op` read for a caller that has no `no_record` outcome (an `op item list`).
fn read_op(
    r: &dyn CommandRunner,
    host: &dyn Fn() -> crate::host::Host,
    args: &[&str],
    ctx: &DiagnoseContext,
    facts: &Facts,
) -> Result<Output, Error> {
    read_op_raw(r, host, args, ctx, facts).map_err(|f| match f {
        ReadFailure::NoRecord => unreadable_field(args),
        ReadFailure::Error(e) => e,
    })
}

/// `cause` with the failed call's scrubbed reply as its evidence box.
fn failed_with_evidence(cause: Cause, failure: &crate::runner::Failure) -> Error {
    let (said, truncated) = crate::scrub::Excerpt::parts(failure.excerpt.clone());
    if said.is_empty() {
        return cause.into();
    }
    Error::with_evidence(
        cause,
        Upstream {
            source: System::OnePassword,
            tool: "1Password CLI".to_string(),
            version: None,
            exit: failure.seen.exit(),
            said,
            removed_advice: false,
            truncated,
            untrusted: true,
        },
    )
}

/// The retry time a rate-limit reply gives, if one; `None` when the reply is not a rate
/// limit.
fn rate_limited(stderr: &str) -> Option<Option<u64>> {
    let low = stderr.to_ascii_lowercase();
    // 429 alone is not enough (some tools print it in unrelated failures); it is a rate
    // limit only together with op's "too many requests" wording.
    let limited = low.contains("rate limit")
        || low.contains("ratelimit")
        || (low.contains("429") && low.contains("too many requests"));
    if !limited {
        return None;
    }
    Some(retry_after_seconds(&low))
}

/// The seconds in "retry after <n>", "retry-after: <n>" or "try again in <n> seconds".
fn retry_after_seconds(low: &str) -> Option<u64> {
    for marker in ["retry-after", "retry after", "try again in"] {
        if let Some(i) = low.find(marker) {
            let digits: String = low[i + marker.len()..]
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(char::is_ascii_digit)
                .collect();
            if let Ok(n) = digits.parse() {
                return Some(n);
            }
        }
    }
    None
}

/// A `op read` failure whose reply says the field is not there (op 2.40 wording).
fn missing_field_reply(stderr: &str) -> bool {
    let low = stderr.to_ascii_lowercase();
    low.contains("isn't a field")
        || low.contains("is not a field")
        || low.contains("not a field")
        || low.contains("field not found")
        || low.contains("no field")
}

/// A `op read` reply opv cannot read, with the call's observation when the runner kept one.
fn unreadable_field(args: &[&str]) -> Error {
    let call = Call::new(OP, args);
    match crate::runner::take_unusable_reply(&call) {
        Some(seen) => Cause::UnexpectedOutput {
            system: System::OnePassword,
            at: None,
            problem: crate::cause::OutputProblem::Unparseable,
            during: crate::cause::During::Read,
            seen,
        }
        .into(),
        None => Cause::Bug {
            site: "changed: an unreadable source versions field left no observation",
        }
        .into(),
    }
}

/// The diagnosis context of a failed `op item list --vault <vault>`.
fn vault_context(env_name: &str, fleet: &Fleet, vault: &str) -> DiagnoseContext {
    let account = fleet
        .environment(env_name)
        .ok()
        .and_then(|e| e.account.as_deref())
        .map(crate::cause::AccountId::new);
    DiagnoseContext {
        env: Some(EnvName::new(env_name)),
        target: None,
        resource: Some(ResourceRef {
            kind: ResourceKind::Vault,
            name: ResourceName::new(vault),
            scope: None,
        }),
        named_by: None,
        create: None,
        write: false,
        account,
        account_from: None,
    }
}

/// The diagnosis context of a failed `op read` of one placement's delivery item.
fn delivery_item_context(env_name: &str, p: &Placement, item: &str) -> DiagnoseContext {
    DiagnoseContext {
        env: Some(EnvName::new(env_name)),
        target: Some(crate::cause::TargetName::new(p.target)),
        resource: Some(ResourceRef {
            kind: ResourceKind::Item,
            name: ResourceName::new(item),
            scope: Some(p.state_vault.to_string()),
        }),
        named_by: None,
        create: None,
        write: false,
        account: None,
        account_from: None,
    }
}

/// The report: one document for `--json`, lines otherwise, and the result's step.
fn report(
    out: &mut dyn Write,
    env_name: &str,
    placements: &[PlacementReport],
    changed: bool,
    missing_item: bool,
    confirm_env: bool,
    json: bool,
) -> Result<(), Error> {
    let (next, action) = result_step(env_name, changed, missing_item, confirm_env);
    if json {
        let doc = json!({
            "schema_version": crate::json::SCHEMA_VERSION,
            "environment": env_name,
            "changed": changed,
            "placements": placements,
            "next": next,
            "do": action,
        });
        return writeln!(out, "{doc}").map_err(write_err);
    }
    for p in placements {
        match p.state {
            "unchanged" => writeln!(
                out,
                "{} {}: unchanged",
                super::placement(env_name, &p.target),
                p.product
            )
            .map_err(write_err)?,
            "no_record" => writeln!(
                out,
                "{} {}: no source versions recorded",
                super::placement(env_name, &p.target),
                p.product
            )
            .map_err(write_err)?,
            _ => {
                writeln!(
                    out,
                    "{} {}: changed",
                    super::placement(env_name, &p.target),
                    p.product
                )
                .map_err(write_err)?;
                for it in &p.items {
                    match it.now {
                        Some(now) => {
                            writeln!(out, "  item {} {} -> {}", it.item, it.was, now)
                        }
                        None => writeln!(out, "  item {} {} -> gone", it.item, it.was),
                    }
                    .map_err(write_err)?;
                }
            }
        }
    }
    if let Some(next) = &next {
        writeln!(out, "Next: {next}").map_err(write_err)?;
    }
    Ok(())
}

/// The result's `next` and `do` (delivery-transports §2.2/§2.6), rendered from
/// [`Cause::SourceChanged`] so the document and the cause agree: `opv bootstrap` when no
/// delivery item is recorded, otherwise the sync — or `opv plan <env>` first on a guarded
/// environment (`confirm_env`, NR-20), whose sync refuses without `--confirm`. Neither when
/// unchanged.
fn result_step(
    env_name: &str,
    changed: bool,
    missing_item: bool,
    confirm_env: bool,
) -> (Option<String>, Option<String>) {
    if !changed {
        return (None, None);
    }
    let cause = Cause::SourceChanged {
        env: EnvName::new(env_name),
        no_record: missing_item,
    };
    let inv = Invocation::default();
    let next = if confirm_env && !missing_item {
        Some(format!("opv plan {env_name}"))
    } else {
        crate::cause::render::next_text(&cause.step(&inv).1, &inv)
    };
    (next, cause.do_text(&inv))
}

#[cfg(test)]
#[path = "changed_tests.rs"]
mod tests;
