//! Characterization tests (P0, §8 item 27): every Fly scenario's flyctl argv, stdin
//! digest, stdout and result, compared with a golden file. `UPDATE_GOLDEN=1` rewrites them;
//! after Task 1 they change only where an NR task changes Fly behaviour on purpose
//! (R2: the two preflight reads before the first write, NR-24; UX1: the output contract,
//! the run summary, `Next:` steps and `product/KEY (NAME)` names).

use sha2::{Digest, Sha256};

use super::status;
use super::sync::{self, SyncOpts};
use super::testutil::*;
use crate::config;
use crate::error::Error;
use crate::runner::Output;
use crate::runner::fake::FakeRunner;

fn transcript(r: &FakeRunner, out: &[u8], res: &Result<(), Error>) -> String {
    let mut s = String::new();
    for c in r.calls.borrow().iter() {
        s.push_str(&format!("$ {} {}\n", c.program, c.args.join(" ")));
        if let Some(i) = &c.stdin {
            s.push_str(&format!(
                "<stdin {} bytes sha256={:x}>\n",
                i.len(),
                Sha256::digest(i)
            ));
        }
    }
    s.push_str("--- stdout\n");
    s.push_str(&text_of(out));
    s.push_str("--- result\n");
    s.push_str(&format!("{res:?}\n"));
    s
}

/// Queue the delivery recording of a sync that mints no revision (FR-58: prod's
/// mode-skipped `STRIPE_SECRET_KEY` is never confirmed), then `after` (prune, deploy).
fn unrecorded_then<const N: usize>(r: &FakeRunner, after: [Output; N]) {
    let mut q = r.responses.borrow_mut();
    q.extend(delivery_not_recorded(complete_item()).map(Ok));
    q.extend(after.map(Ok));
}

fn golden(name: &str, actual: &str) {
    let path = format!("tests/fixtures/characterization/{name}.txt");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all("tests/fixtures/characterization").unwrap();
        std::fs::write(&path, actual).unwrap();
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(expected, actual, "golden {path} differs");
}

#[test]
fn sync_new_secrets_without_deploy() {
    let r = FakeRunner::new([
        complete_item(),
        fly_empty(),
        fly_app_ok(),
        fly_releases("complete"),
        ok(),
        fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2")]),
    ]);
    unrecorded_then(&r, []);
    let mut out = Vec::new();
    let res = sync::run(&fleet(), "prod", &r, &mut out, &SyncOpts::default());
    golden(
        "sync_new_secrets_without_deploy",
        &transcript(&r, &out, &res),
    );
}

#[test]
fn sync_unchanged_with_deploy() {
    let a = || fly(&[(OPENAI_FLY, "dA"), (ENC_FLY, "dB")]);
    let r = FakeRunner::new([
        complete_item(),
        a(),
        fly_app_ok(),
        fly_releases("complete"),
        ok(),
        a(),
    ]);
    unrecorded_then(&r, [ok()]);
    let opts = SyncOpts {
        deploy: true,
        ..SyncOpts::default()
    };
    let mut out = Vec::new();
    let res = sync::run(&fleet(), "prod", &r, &mut out, &opts);
    golden("sync_unchanged_with_deploy", &transcript(&r, &out, &res));
}

#[test]
fn sync_changed_with_deploy() {
    let r = FakeRunner::new([
        complete_item(),
        fly(&[(OPENAI_FLY, "dA"), (ENC_FLY, "dB")]),
        fly_app_ok(),
        fly_releases("complete"),
        ok(),
        fly(&[(OPENAI_FLY, "dA2"), (ENC_FLY, "dB")]),
    ]);
    unrecorded_then(&r, [ok()]);
    let opts = SyncOpts {
        deploy: true,
        ..SyncOpts::default()
    };
    let mut out = Vec::new();
    let res = sync::run(&fleet(), "prod", &r, &mut out, &opts);
    golden("sync_changed_with_deploy", &transcript(&r, &out, &res));
}

#[test]
fn sync_pending_from_earlier_run() {
    let a = || fly_st(&[(OPENAI_FLY, "d1", "Staged"), (ENC_FLY, "d2", "Deployed")]);
    let r = FakeRunner::new([
        complete_item(),
        a(),
        fly_app_ok(),
        fly_releases("complete"),
        ok(),
        a(),
    ]);
    unrecorded_then(&r, [ok()]);
    let opts = SyncOpts {
        deploy: true,
        ..SyncOpts::default()
    };
    let mut out = Vec::new();
    let res = sync::run(&fleet(), "prod", &r, &mut out, &opts);
    golden("sync_pending_from_earlier_run", &transcript(&r, &out, &res));
}

#[test]
fn sync_prune_with_deploy() {
    let a = || fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2"), (STRIPE_FLY, "d3")]);
    let r = FakeRunner::new([
        complete_item(),
        a(),
        fly_app_ok(),
        fly_releases("complete"),
        ok(),
        a(),
    ]);
    unrecorded_then(&r, [ok(), ok()]);
    let opts = SyncOpts {
        deploy: true,
        prune: true,
        ..SyncOpts::default()
    };
    let mut out = Vec::new();
    let res = sync::run(&fleet(), "prod", &r, &mut out, &opts);
    golden("sync_prune_with_deploy", &transcript(&r, &out, &res));
}

#[test]
fn sync_prune_without_flag() {
    let a = || fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2"), (STRIPE_FLY, "d3")]);
    let r = FakeRunner::new([
        complete_item(),
        a(),
        fly_app_ok(),
        fly_releases("complete"),
        ok(),
        a(),
    ]);
    unrecorded_then(&r, []);
    let mut out = Vec::new();
    let res = sync::run(&fleet(), "prod", &r, &mut out, &SyncOpts::default());
    golden("sync_prune_without_flag", &transcript(&r, &out, &res));
}

#[test]
fn sync_rotate_immutable() {
    let r = FakeRunner::new([
        complete_item(),
        fly(&[(ENC_FLY, "d-enc")]),
        fly_app_ok(),
        fly_releases("complete"),
        ok(),
        // List B shows every staged name (NR-30 polls until it does).
        fly(&[(ENC_FLY, "d-enc2"), (OPENAI_FLY, "d-openai")]),
    ]);
    unrecorded_then(&r, []);
    let opts = SyncOpts {
        rotate: vec!["allumata/INTEGRATION_ENC_KEY".into()],
        ..SyncOpts::default()
    };
    let mut out = Vec::new();
    let res = sync::run(&fleet(), "prod", &r, &mut out, &opts);
    golden("sync_rotate_immutable", &transcript(&r, &out, &res));
}

#[test]
fn sync_prune_immutable() {
    const OLD_FLY: &str = "FLEET__ALLUMATA__OLD_ENC";
    let fl = fleet_with(
        "[products.allumata.keys.OLD_ENC]\nkind = \"secret\"\n\
         environments = [\"staging\"]\nimmutable = true\n",
    );
    let a = || fly(&[(OPENAI_FLY, "d1"), (ENC_FLY, "d2"), (OLD_FLY, "d3")]);
    let r = FakeRunner::new([
        complete_item(),
        a(),
        fly_app_ok(),
        fly_releases("complete"),
        ok(),
        a(),
    ]);
    unrecorded_then(&r, [ok()]);
    let opts = SyncOpts {
        prune: true,
        prune_immutable: vec!["allumata/OLD_ENC".into()],
        ..SyncOpts::default()
    };
    let mut out = Vec::new();
    let res = sync::run(&fl, "prod", &r, &mut out, &opts);
    golden("sync_prune_immutable", &transcript(&r, &out, &res));
}

#[test]
fn sync_refused_missing_key() {
    let r = FakeRunner::new([item_without("allumata", "OPENAI_API_KEY"), fly_empty()]);
    let mut out = Vec::new();
    let res = sync::run(&fleet(), "prod", &r, &mut out, &SyncOpts::default());
    golden("sync_refused_missing_key", &transcript(&r, &out, &res));
}

#[test]
fn plan_text() {
    let r = FakeRunner::new([complete_item(), fly(&[(OPENAI_FLY, "d1")])]);
    let mut out = Vec::new();
    let res = sync::plan_with(&fleet(), "prod", &r, &mut out, false);
    golden("plan_text", &transcript(&r, &out, &res));
}

#[test]
fn plan_json() {
    let r = FakeRunner::new([complete_item(), fly(&[(OPENAI_FLY, "d1")])]);
    let mut out = Vec::new();
    let res = sync::plan_with(&fleet(), "prod", &r, &mut out, true);
    golden("plan_json", &transcript(&r, &out, &res));
}

#[test]
fn status_clean() {
    let r = FakeRunner::new([complete_item(), fly_empty()]);
    let mut out = Vec::new();
    let res = status::run_with(&fleet(), "prod", &r, &mut out, false);
    golden("status_clean", &transcript(&r, &out, &res));
}

#[test]
fn status_env_without_target() {
    let fl = fleet_with("[environments.dev]\n");
    let r = FakeRunner::new([]);
    let mut out = Vec::new();
    let res = status::run_with(&fl, "dev", &r, &mut out, false);
    golden("status_env_without_target", &transcript(&r, &out, &res));
}

/// One app with bare names (formerly the simple profile, FR-20): the one product `app`,
/// whose target's template is `{KEY}`.
const SINGLE_APP: &str = r#"
[environments.staging]
boundaries.app = { vault_id = "vstg", item_id = "istg" }
modes.app.payments = "test"

[environments.staging.targets.app]
fly.app = "myapp-staging"
fly.secret_name = "{KEY}"
state_vault_id = "sstaging"

[environments.prod]
boundaries.app = { vault_id = "vprd", item_id = "iprd" }
modes.app.payments = "off"

[environments.prod.targets.app]
fly.app = "myapp-production"
fly.secret_name = "{KEY}"
state_vault_id = "sprod"

[products.app.keys.DATABASE_URL]
kind = "secret"
environments = ["staging", "prod"]
rules = { prefix = "postgres://" }
guidance = "Fly Postgres / connection string"

[products.app.keys.JWT_KEY]
kind = "secret"
environments = ["staging", "prod"]
immutable = true
rules = { base64_bytes = 32 }
guidance = "32 random bytes, base64"

[products.app.keys.STRIPE_SECRET_KEY]
kind = "secret"
environments = ["staging", "prod"]
rules = { prefix_by_mode = { mode = "payments", values = { test = "sk_test_", live = "sk_live_" }, skip = ["off"] } }

[products.app.keys.STAGING_DEBUG_TOKEN]
kind = "secret"
environments = ["staging"]

[products.app.keys.LOG_LEVEL]
kind = "config"
environments = ["staging", "prod"]
rules = { enum = ["debug", "info", "warn"] }
"#;

#[test]
fn simple_sync_deploy() {
    fn simple_item() -> Output {
        item(&[
            secret(
                "app",
                "DATABASE_URL",
                "postgres://FIXTUREVALUE@db.internal/app",
            ),
            secret("app", "JWT_KEY", &enc()),
            text("app", "LOG_LEVEL", "info"),
        ])
    }
    let fl = config::parse(SINGLE_APP).unwrap();
    let r = FakeRunner::new([
        simple_item(),
        fly(&[("DATABASE_URL", "d1"), ("JWT_KEY", "d2")]),
        fly_app_ok(),
        fly_releases("complete"),
        ok(),
        fly(&[("DATABASE_URL", "d1b"), ("JWT_KEY", "d2")]),
    ]);
    {
        let mut q = r.responses.borrow_mut();
        q.extend(delivery_not_recorded(simple_item()).map(Ok));
        q.push_back(Ok(ok()));
    }
    let opts = SyncOpts {
        deploy: true,
        ..SyncOpts::default()
    };
    let mut out = Vec::new();
    let res = sync::run(&fl, "prod", &r, &mut out, &opts);
    golden("simple_sync_deploy", &transcript(&r, &out, &res));
}
