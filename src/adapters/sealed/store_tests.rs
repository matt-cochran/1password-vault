//! The sealed store (design `sealed-target` §5.2 to §5.6, §8.3; FMECA T3, T8, T10, R7): a
//! verified, value-free listing, whole-bundle staleness, the revision rule and the atomic
//! whole-set write. One behavioural assertion each. Keys are the stock-tool fixtures of
//! `tests/fixtures/sealed/kat/` (the fake runner signs with the fixture signer) or fixed test
//! seeds; values are obvious test markers.

use std::path::{Path, PathBuf};

use ssh_key::LineEnding;
use ssh_key::PrivateKey;
use ssh_key::private::Ed25519Keypair;

use super::*;
use crate::bundle::crypto::{Expect, parse_identity, parse_signing_key};
use crate::bundle::format::parse_envelope;
use crate::domain::Fleet;
use crate::provider::{PreflightMode, TargetConfig};
use crate::runner::fake::FakeRunner;

/// A recipient other than the fixture's (a test key from `whole_set_tests.rs`).
const OTHER_RECIPIENT: &str = "age13ts5aywwye8k4qr653hu89n89lt2eexd7szjadl9u3m47fzneggstxdxvs";
const PLAN: &str = "plan_sealedstore01";
const TOKEN: &str = "test-marker-token-value";

fn kat(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sealed/kat")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn recipient_line() -> String {
    kat("age-recipient.txt")
        .lines()
        .find(|l| l.starts_with("age1"))
        .expect("fixture recipient")
        .to_string()
}

/// prod's sealed target `box` delivering api (TOKEN, DB_URL, and TLS_KEY as a file) to
/// `recipients`, signed by the fixture signer.
fn fleet_with(recipients: &[String]) -> Fleet {
    let list = recipients
        .iter()
        .map(|r| format!("\"{r}\""))
        .collect::<Vec<_>>()
        .join(", ");
    crate::config::parse(&format!(
        r#"
[environments.prod]
boundaries.api = {{ vault_id = "vapi", item_id = "iapi" }}

[environments.prod.targets.box]
state_vault_id = "sprod"
deploy_credentials = "op://Ops Prod/opv-sealed-prod-signer"
sealed.out = "sealed/prod/{{product}}.opv-sealed"
sealed.env_name = "{{KEY}}"
sealed.recipients = [{list}]
sealed.signer = "{}"

[products.api.local]
secrets_dir_env = "APP_SECRETS_DIR"

[products.api.keys.TOKEN]
kind = "secret"

[products.api.keys.DB_URL]
kind = "secret"

[products.api.keys.TLS_KEY]
kind = "secret"
file = "tls/key"
"#,
        kat("signer_ed25519.pub").trim()
    ))
    .expect("the sealed fixture configuration loads")
}

/// The target of [`fleet_with`], rooted at `root` as `--sealed-root` roots it.
fn target_with(root: &Path, recipients: &[String]) -> SealedTarget {
    let fleet = fleet_with(recipients);
    let mut t = fleet.environments["prod"].targets["box"].config.clone();
    t.set_out_root(root);
    t.as_any()
        .downcast_ref::<SealedTarget>()
        .expect("a sealed target")
        .clone()
}

fn target(root: &Path) -> SealedTarget {
    target_with(root, &[recipient_line()])
}

fn store<'a>(t: &'a SealedTarget, r: &'a FakeRunner) -> SealedStore<'a> {
    SealedStore::new(t, "prod", r).with_clock(|| 1_000)
}

fn v(s: &str) -> SecretValue {
    SecretValue::new(s.to_string())
}

/// Write `names` (each with a test-marker value) as the whole set of the run.
fn write(s: &SealedStore<'_>, names: &[&str]) -> Result<(), Error> {
    let values: Vec<SecretValue> = names.iter().map(|n| v(&format!("{TOKEN}-{n}"))).collect();
    let batch: Vec<(String, &SecretValue)> = names
        .iter()
        .zip(&values)
        .map(|(n, v)| (n.to_string(), v))
        .collect();
    let run = WriteRun {
        plan_id: PLAN,
        product: None,
    };
    s.write_run(&batch, &run)
}

fn bundle(t: &SealedTarget) -> PathBuf {
    t.written_path("api")
}

fn header(t: &SealedTarget) -> Header {
    parse_envelope(&std::fs::read(bundle(t)).unwrap())
        .unwrap()
        .header
}

fn versions(s: &SealedStore<'_>) -> Vec<String> {
    s.list()
        .unwrap()
        .into_iter()
        .map(|e| e.version.unwrap_or_default())
        .collect()
}

fn code(e: &Error) -> &'static str {
    e.code_str()
}

/// A bundle for `t` signed by a key other than `sealed.signer`, at `revision`.
fn plant_foreign(t: &SealedTarget, revision: u64) {
    let pem = PrivateKey::from(Ed25519Keypair::from_seed(&[9u8; 32]))
        .to_openssh(LineEnding::LF)
        .unwrap();
    let key = parse_signing_key(&pem).unwrap();
    let recipient = crypto::parse_recipient(&recipient_line()).unwrap();
    let names = vec![Name {
        name: "TOKEN".into(),
        destination: "env:TOKEN".into(),
    }];
    let header = Header {
        format: FORMAT.into(),
        project: "x".into(),
        environment: "prod".into(),
        product: "api".into(),
        target: "box".into(),
        revision,
        created_at: "2026-11-04T12:00:00Z".into(),
        opv_version: "0.0.0".into(),
        plan_id: "plan_planted".into(),
        contract_digest: "sha256:00".into(),
        recipients: vec![crypto::recipient_fingerprint(&recipient)],
        signer: key.fingerprint(),
        names,
        secrets_dir_env: None,
    };
    let entries: [(&str, &[u8]); 1] = [("TOKEN", b"test-marker-planted")];
    let bytes = crypto::seal(&header, &entries, &[recipient], &key).unwrap();
    std::fs::create_dir_all(bundle(t).parent().unwrap()).unwrap();
    std::fs::write(bundle(t), bytes).unwrap();
}

// --- list --------------------------------------------------------------------------------

#[test]
fn an_absent_bundle_lists_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    assert!(store(&t, &r).list().unwrap().is_empty());
}

#[test]
fn a_verified_bundle_lists_every_name_at_its_revision_and_file_digest() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    let s = store(&t, &r);
    write(&s, &["DB_URL", "TOKEN"]).unwrap();
    let digest = file_digest(&std::fs::read(bundle(&t)).unwrap());
    let want = format!("r1000.{digest}");
    assert_eq!(versions(&s), vec![want.clone(), want]);
}

#[test]
fn a_bundle_signed_by_another_key_is_drift() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    plant_foreign(&t, 7);
    assert!(
        versions(&store(&t, &r))
            .iter()
            .all(|v| v.starts_with("foreign."))
    );
}

#[test]
fn a_tampered_bundle_refuses_the_listing() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    let s = store(&t, &r);
    write(&s, &["TOKEN"]).unwrap();
    let mut bytes = std::fs::read(bundle(&t)).unwrap();
    // One character of the age block's armor, which the signature covers.
    let at = bytes
        .windows(format::AGE_BEGIN.len())
        .position(|w| w == format::AGE_BEGIN)
        .unwrap()
        + format::AGE_BEGIN.len()
        + 4;
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    std::fs::write(bundle(&t), bytes).unwrap();
    assert_eq!(code(&s.list().unwrap_err()), "input_invalid");
}

#[test]
fn a_carriage_return_in_the_bundle_refuses_the_listing() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    let s = store(&t, &r);
    write(&s, &["TOKEN"]).unwrap();
    let crlf = String::from_utf8(std::fs::read(bundle(&t)).unwrap())
        .unwrap()
        .replace('\n', "\r\n");
    std::fs::write(bundle(&t), crlf).unwrap();
    assert_eq!(code(&s.list().unwrap_err()), "input_invalid");
}

#[test]
fn a_recipient_change_marks_every_name_stale() {
    let dir = tempfile::tempdir().unwrap();
    let r = FakeRunner::new([]);
    let before = target(dir.path());
    write(&store(&before, &r), &["DB_URL", "TOKEN"]).unwrap();
    let after = target_with(dir.path(), &[recipient_line(), OTHER_RECIPIENT.to_string()]);
    assert!(
        versions(&store(&after, &r))
            .iter()
            .all(|v| v.ends_with(".stale"))
    );
}

#[test]
fn a_recipient_change_prints_one_preflight_line_with_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let r = FakeRunner::new([]);
    let before = target(dir.path());
    write(&store(&before, &r), &["DB_URL", "TOKEN"]).unwrap();
    let after = target_with(dir.path(), &[recipient_line(), OTHER_RECIPIENT.to_string()]);
    let lines: Vec<String> = after
        .preflight(&r, PreflightMode::Read)
        .unwrap()
        .checks
        .into_iter()
        .map(|c| c.outcome.unwrap().line(&c.name))
        .collect();
    assert_eq!(
        lines,
        vec![
            "warn  sealed bundle sealed/prod/api.opv-sealed: stale as a whole (recipients changed): every name is sealed again"
                .to_string()
        ]
    );
}

#[test]
fn an_unchanged_configuration_prints_no_preflight_line() {
    let dir = tempfile::tempdir().unwrap();
    let r = FakeRunner::new([]);
    let t = target(dir.path());
    write(&store(&t, &r), &["DB_URL", "TOKEN"]).unwrap();
    assert!(
        t.preflight(&r, PreflightMode::Read)
            .unwrap()
            .checks
            .is_empty()
    );
}

#[test]
fn listing_makes_no_call() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    let s = store(&t, &r);
    write(&s, &["TOKEN"]).unwrap();
    r.calls.borrow_mut().clear();
    s.list().unwrap();
    assert!(r.calls.borrow().is_empty());
}

// --- write -------------------------------------------------------------------------------

#[test]
fn the_revision_increases_across_two_writes_in_one_second() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    let s = store(&t, &r);
    write(&s, &["TOKEN"]).unwrap();
    write(&s, &["TOKEN"]).unwrap();
    assert_eq!(header(&t).revision, 1_001);
}

#[test]
fn the_revision_is_the_clock_when_it_is_ahead() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    write(&store(&t, &r), &["TOKEN"]).unwrap();
    write(
        &SealedStore::new(&t, "prod", &r).with_clock(|| 5_000),
        &["TOKEN"],
    )
    .unwrap();
    assert_eq!(header(&t).revision, 5_000);
}

#[test]
fn a_foreign_bundle_never_sets_the_revision() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    plant_foreign(&t, u64::MAX);
    write(&store(&t, &r), &["TOKEN"]).unwrap();
    assert_eq!(header(&t).revision, 1_000);
}

#[test]
fn the_header_names_the_placement_the_plan_and_the_destinations() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    write(&store(&t, &r), &["TOKEN", "TLS_KEY"]).unwrap();
    let h = header(&t);
    let got = (
        h.environment,
        h.product,
        h.target,
        h.plan_id,
        h.names
            .iter()
            .map(|n| n.destination.clone())
            .collect::<Vec<_>>(),
        h.secrets_dir_env,
    );
    assert_eq!(
        got,
        (
            "prod".to_string(),
            "api".to_string(),
            "box".to_string(),
            PLAN.to_string(),
            vec!["file:tls/key".to_string(), "env:TOKEN".to_string()],
            Some("APP_SECRETS_DIR".to_string()),
        )
    );
}

#[test]
fn the_written_bundle_opens_with_the_fixture_identity_to_the_exact_values() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    write(&store(&t, &r), &["TOKEN"]).unwrap();
    let identity = parse_identity(
        kat("age-identity.txt")
            .lines()
            .find(|l| l.starts_with("AGE-SECRET-KEY-1"))
            .unwrap(),
    )
    .unwrap();
    let signers = AllowedSigners::parse(kat("allowed_signers").as_bytes()).unwrap();
    let expect = Expect {
        environment: "prod",
        product: "api",
        min_revision: Some(1_000),
    };
    let opened = crypto::open(
        &std::fs::read(bundle(&t)).unwrap(),
        &identity,
        &signers,
        &expect,
    )
    .unwrap();
    assert_eq!(
        opened.values[0].1.as_slice(),
        format!("{TOKEN}-TOKEN").as_bytes()
    );
}

#[test]
fn a_retired_last_name_leaves_an_empty_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    let s = store(&t, &r);
    write(&s, &["TOKEN"]).unwrap();
    write(&s, &[]).unwrap();
    assert!(header(&t).names.is_empty());
}

#[test]
fn an_empty_set_with_no_bundle_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    write(&store(&t, &r), &[]).unwrap();
    assert!(!bundle(&t).exists());
}

#[test]
fn the_bundle_is_written_under_the_sealed_root() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    write(&store(&t, &r), &["TOKEN"]).unwrap();
    assert!(dir.path().join("sealed/prod/api.opv-sealed").is_file());
}

#[test]
fn a_failed_write_leaves_no_temporary_file() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    // A non-empty directory where the bundle goes: the rename onto it fails.
    std::fs::create_dir_all(bundle(&t).join("occupied")).unwrap();
    let _ = write(&store(&t, &r), &["TOKEN"]);
    let left: Vec<String> = std::fs::read_dir(bundle(&t).parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, vec!["api.opv-sealed".to_string()]);
}

#[test]
fn a_failed_write_is_a_local_write_failure() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    std::fs::create_dir_all(bundle(&t).join("occupied")).unwrap();
    assert_eq!(
        code(&write(&store(&t, &r), &["TOKEN"]).unwrap_err()),
        "local_io_failed"
    );
}

#[test]
fn a_seal_already_in_progress_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    std::fs::create_dir_all(bundle(&t).parent().unwrap()).unwrap();
    let _held = Lock::take(&bundle(&t)).unwrap();
    assert_eq!(
        code(&write(&store(&t, &r), &["TOKEN"]).unwrap_err()),
        "local_io_failed"
    );
}

/// A held seal lock names the other run and the bundle, never "full" or a time budget.
#[test]
fn a_held_lock_says_another_run_is_sealing_the_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    std::fs::create_dir_all(bundle(&t).parent().unwrap()).unwrap();
    let _held = Lock::take(&bundle(&t)).unwrap();
    let e = write(&store(&t, &r), &["TOKEN"]).unwrap_err();
    assert_eq!(
        e.cause().map(|(c, _)| c.message()),
        Some(format!(
            "another opv run is sealing {}; retry when it finishes",
            bundle(&t).display()
        ))
    );
}

/// A tampered bundle refuses the store's local check, which `sync` runs before any read.
#[test]
fn the_local_check_refuses_a_tampered_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    write(&store(&t, &r), &["TOKEN"]).unwrap();
    let mut bytes = std::fs::read(bundle(&t)).unwrap();
    let at = bytes
        .windows(format::AGE_BEGIN.len())
        .position(|w| w == format::AGE_BEGIN)
        .unwrap()
        + format::AGE_BEGIN.len()
        + 4;
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    std::fs::write(bundle(&t), bytes).unwrap();
    assert_eq!(
        code(&store(&t, &r).check_local().unwrap_err()),
        "input_invalid"
    );
}

/// A lock file left by a run that was killed has no holder, so it does not block.
#[test]
fn a_leftover_lock_file_without_a_holder_does_not_block_a_seal() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    std::fs::create_dir_all(bundle(&t).parent().unwrap()).unwrap();
    std::fs::write(dir.path().join("sealed/prod/api.opv-sealed.lock"), b"").unwrap();
    assert!(write(&store(&t, &r), &["TOKEN"]).is_ok());
}

#[test]
fn a_write_leaves_no_lock_behind() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    write(&store(&t, &r), &["TOKEN"]).unwrap();
    assert!(!dir.path().join("sealed/prod/api.opv-sealed.lock").exists());
}

#[test]
fn a_write_makes_exactly_one_seal_call_and_no_other() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    write(&store(&t, &r), &["DB_URL", "TOKEN"]).unwrap();
    let programs: Vec<String> = r.calls.borrow().iter().map(|c| c.program.clone()).collect();
    assert_eq!(programs, vec![crate::runner::seal::PROGRAM.to_string()]);
}

#[test]
fn a_name_of_no_delivered_product_is_a_bug() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    assert_eq!(
        code(&write(&store(&t, &r), &["UNDECLARED"]).unwrap_err()),
        "internal_error"
    );
}

// --- the port ----------------------------------------------------------------------------

#[test]
fn remove_on_the_whole_set_store_is_a_bug() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    assert_eq!(
        code(&store(&t, &r).remove(&["TOKEN".to_string()]).unwrap_err()),
        "internal_error"
    );
}

#[test]
fn a_write_without_the_run_is_a_bug() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    let value = v(TOKEN);
    assert_eq!(
        code(
            &store(&t, &r)
                .write(&[("TOKEN".to_string(), &value)])
                .unwrap_err()
        ),
        "internal_error"
    );
}

#[test]
fn the_store_is_whole_set() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    assert!(store(&t, &r).whole_set());
}

#[test]
fn the_runtime_is_live() {
    assert!(SealedRuntime.live());
}

#[test]
fn an_empty_value_is_not_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    assert_eq!(store(&t, &r).refusal("TOKEN", &v("")), None);
}

#[test]
fn a_value_over_one_mebibyte_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    let big = v(&"x".repeat(MAX_VALUE + 1));
    assert_eq!(
        store(&t, &r).refusal("TOKEN", &big).map(|(rule, _)| rule),
        Some(VALUE_TOO_LARGE)
    );
}

#[test]
fn open_returns_the_whole_set_store() {
    let dir = tempfile::tempdir().unwrap();
    let (t, r) = (target(dir.path()), FakeRunner::new([]));
    let ports = t
        .open(
            "prod",
            Default::default(),
            &Default::default(),
            &Default::default(),
            &r,
        )
        .unwrap();
    assert!(matches!(ports, crate::ports::Ports::Staged { store, .. } if store.whole_set()));
}

// --- one 1Password read per scope (acceptance 2) ---------------------------------------------

/// 1Password through [`FakeOp`]; the seal effect records how many `op` calls preceded it.
struct World {
    op: crate::adapters::fake_op::FakeOp,
    values_id: String,
    /// The number of `op` calls made before each seal.
    seals: std::cell::RefCell<Vec<usize>>,
}

impl World {
    /// `op item get` calls of the values item among the first `upto` `op` calls.
    fn values_reads(&self, upto: usize) -> usize {
        self.op
            .calls
            .borrow()
            .iter()
            .take(upto)
            .filter(|c| c.program == "op" && c.args.contains(&self.values_id))
            .filter(|c| c.args.iter().any(|a| a == "get"))
            .count()
    }
}

impl CommandRunner for World {
    fn read(
        &self,
        call: &crate::runner::Call<'_>,
        refused: &[i32],
    ) -> std::io::Result<crate::runner::Outcome> {
        self.op.read(call, refused)
    }
    fn write(&self, call: &crate::runner::Call<'_>) -> std::io::Result<crate::runner::Outcome> {
        self.op.write(call)
    }
    fn probe(
        &self,
        call: &crate::runner::Call<'_>,
        limit: std::time::Duration,
    ) -> std::io::Result<crate::runner::Output> {
        self.op.probe(call, limit)
    }
    fn pause(&self, _: std::time::Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> std::io::Result<i32> {
        unreachable!("sync never runs a child")
    }
    fn seal_bundle(&self, call: &SealCall) -> Result<Vec<u8>, SealFailure> {
        self.seals.borrow_mut().push(self.op.calls.borrow().len());
        crate::runner::seal::run(call, None)
    }
}

/// dev's sealed target `box` delivering api's A_KEY and B_KEY, with its signing item (the
/// fixture key) and delivery item in the shared vault.
fn counting_world() -> (World, Fleet) {
    use serde_json::json;
    const VALUES: &str = "vdev0000000000000000000001";
    const SHARED: &str = "vshr0000000000000000000002";
    let op = crate::adapters::fake_op::FakeOp::default();
    let field = |id: &str, label: &str, value: &str| json!({"id": id, "section": {"id": "api", "label": "api"}, "type": "CONCEALED", "label": label, "value": value});
    let values_id = op.insert(
        VALUES,
        json!({
            "title": "t", "category": "SECURE_NOTE",
            "sections": [{"id": "api", "label": "api"}],
            "fields": [
                field("f1", "A_KEY", "tok-FIXTUREVALUE-a"),
                field("f2", "B_KEY", "tok-FIXTUREVALUE-b"),
            ]
        }),
    );
    let signer = op.insert(
        SHARED,
        json!({
            "title": "opv-sealed-dev-signer", "category": "SSH_KEY",
            "fields": [
                {"id": "private_key", "type": "SSHKEY", "label": "private key",
                 "value": kat("signer_ed25519.pkcs8.pem"),
                 "ssh_formats": {"openssh": {"value": kat("signer_ed25519")}}},
                {"id": "public_key", "type": "STRING", "label": "public key", "value": kat("signer_ed25519.pub")},
            ]
        }),
    );
    let state = op.insert(
        SHARED,
        json!({"title": "opv · delivery · api · box", "category": "SECURE_NOTE", "fields": []}),
    );
    let fleet = crate::config::parse(&format!(
        r#"
[environments.dev]
boundaries.api = {{ vault_id = "{VALUES}", item_id = "{values_id}" }}

[environments.dev.targets.box]
state_vault_id = "{SHARED}"
delivery_items = {{ api = "{state}" }}
deploy_credentials = "op://{SHARED}/{signer}"
sealed.out = "sealed/{{product}}.opv-sealed"
sealed.env_name = "{{KEY}}"
sealed.recipients = ["{}"]
sealed.signer = "{}"

[products.api.keys.A_KEY]
kind = "secret"

[products.api.keys.B_KEY]
kind = "secret"
"#,
        recipient_line(),
        kat("signer_ed25519.pub").trim()
    ))
    .expect("the counting configuration loads");
    let world = World {
        op,
        values_id,
        seals: Default::default(),
    };
    (world, fleet)
}

/// `opv sync` on `fleet`'s dev, signed in with the target's deploy credentials as `opv sync`
/// is, writing under `root`.
fn sync_dev(w: &World, fleet: &Fleet, root: &Path) {
    let opts = crate::app::sync::SyncOpts {
        sealed_root: Some(root.to_path_buf()),
        ..Default::default()
    };
    let linux =
        || crate::host::Host::from_env(&crate::host::FakeEnv::new("linux").shell("/bin/bash"));
    let signed_in =
        crate::app::signin::open_on(fleet, "dev", w, crate::app::signin::Reach::Target, &linux)
            .unwrap();
    crate::app::sync::run(fleet, "dev", &signed_in, &mut Vec::new(), &opts).unwrap();
}

#[test]
fn sealing_one_product_reads_its_boundary_item_once_before_the_seal() {
    let dir = tempfile::tempdir().unwrap();
    let (w, fleet) = counting_world();
    sync_dev(&w, &fleet, dir.path());
    let before_seal = w.seals.borrow().first().copied().unwrap_or(0);
    assert_eq!(
        (w.seals.borrow().len(), w.values_reads(before_seal)),
        (1, 1)
    );
}

#[test]
fn a_second_sync_with_nothing_changed_seals_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (w, fleet) = counting_world();
    sync_dev(&w, &fleet, dir.path());
    sync_dev(&w, &fleet, dir.path());
    assert_eq!(w.seals.borrow().len(), 1);
}
