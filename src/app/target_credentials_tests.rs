//! `opv target credentials --create`: the token only ever reaches `op item create` on
//! stdin, and the item's reference is the only thing recorded locally. One behavioural
//! scenario per test.

use std::cell::RefCell;
use std::io;
use std::time::Duration;

use super::*;
use crate::adapters::fake_op::FakeOp;
use crate::error::Code;
use crate::runner::{Call, Outcome, Output};

const TOKEN: &str = "fo1_FAKEDEPLOYTOKENMARKER0123456789";
const CREDENTIAL: &str = "opv-shop-staging-web";
const RECORDED_REFERENCE: &str = "op://vstate/item0000000000000000000001";

/// A staging environment with one Fly target and its state vault; `deploy` adds the
/// `deploy_credentials` line an earlier mint would have recorded.
fn fleet_text(deploy: Option<&str>) -> String {
    let line = deploy
        .map(|r| format!("deploy_credentials = {r:?}\n"))
        .unwrap_or_default();
    format!(
        "# keep this comment\n\
         [environments.staging]\n\
         boundaries.web = {{ vault_id = \"vweb\", item_id = \"iweb\" }}\n\
         \n\
         [environments.staging.targets.web]\n\
         fly.app = \"shop-staging\"\n\
         fly.secret_name = \"{{KEY}}\"\n\
         {line}state_vault_id = \"vstate\"\n\
         \n\
         [products.web.keys.WEB_KEY]\n\
         kind = \"secret\"\n\
         environments = [\"staging\"]\n"
    )
}

fn fleet(deploy: Option<&str>) -> Fleet {
    crate::config::parse(&fleet_text(deploy)).unwrap()
}

/// A GitHub target's provider mints no deploy credential (`mint_*` default to `None`).
fn github_fleet() -> Fleet {
    crate::config::parse(
        "[environments.staging]\n\
         boundaries.web = { vault_id = \"vweb\", item_id = \"iweb\" }\n\
         [environments.staging.targets.web]\n\
         github.repo = \"acme/shop\"\n\
         state_vault_id = \"vstate\"\n\
         [products.web.keys.WEB_KEY]\n\
         kind = \"secret\"\n\
         environments = [\"staging\"]\n",
    )
    .unwrap()
}

type Recorded = (String, Vec<String>, Option<Vec<u8>>);

/// The fake `op` (state vault present, readable) plus a scripted `flyctl` that mints
/// [`TOKEN`], recording every call with its stdin.
struct World {
    op: FakeOp,
    fly_signed_in: bool,
    minted: Option<String>,
    calls: RefCell<Vec<Recorded>>,
}

impl World {
    fn new() -> Self {
        let op = FakeOp::default();
        op.vaults.borrow_mut().push(("vweb".into(), "web".into()));
        op.vaults
            .borrow_mut()
            .push(("vstate".into(), "state".into()));
        World {
            op,
            fly_signed_in: true,
            minted: Some(TOKEN.to_string()),
            calls: RefCell::new(Vec::new()),
        }
    }
    fn record(&self, call: &Call) {
        self.calls.borrow_mut().push((
            call.program.to_string(),
            call.args.iter().map(|a| a.to_string()).collect(),
            call.stdin.map(<[u8]>::to_vec),
        ));
    }
    fn ran(&self, program: &str, first: &[&str]) -> bool {
        self.calls.borrow().iter().any(|(p, a, _)| {
            p == program
                && a.iter()
                    .map(String::as_str)
                    .take(first.len())
                    .eq(first.iter().copied())
        })
    }
    /// The stdin of the first `op item create`, as text.
    fn item_stdin(&self) -> String {
        let bytes = self
            .calls
            .borrow()
            .iter()
            .find(|(p, a, _)| p == "op" && a.first().map(String::as_str) == Some("item"))
            .and_then(|(_, _, s)| s.clone())
            .expect("op item create ran");
        String::from_utf8(bytes).unwrap()
    }
}

impl CommandRunner for World {
    fn read(&self, call: &Call, refused: &[i32]) -> io::Result<Outcome> {
        self.record(call);
        self.op.read(call, refused)
    }
    fn probe(&self, call: &Call, limit: Duration) -> io::Result<Output> {
        self.record(call);
        if call.program == "flyctl" && call.args == ["auth", "whoami"] {
            if self.fly_signed_in {
                return Ok(Output::success("me@example.com\n"));
            }
            // flyctl's recorded signed-out reply, through the runner so the failure is
            // observed and diagnosed (design §5).
            let fake = crate::runner::fake::FakeRunner::default();
            fake.push_with_stderr(
                Output::failure(1),
                include_str!("../../tests/fixtures/fly/failures/01-signed-out-whoami.stderr"),
            );
            return fake.probe(call, limit);
        }
        self.op.probe(call, limit)
    }
    fn write(&self, call: &Call) -> io::Result<Outcome> {
        self.record(call);
        if call.program == "flyctl" && call.args.first().copied() == Some("tokens") {
            return Ok(match &self.minted {
                Some(t) => Outcome::Done(Output::success(format!("{t}\n"))),
                None => Outcome::Refused(Output::failure(1)),
            });
        }
        self.op.write(call)
    }
    fn pause(&self, _: Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> io::Result<i32> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}

struct Answer(bool, RefCell<Vec<String>>);

impl Interaction for Answer {
    fn show(&mut self, message: &str) -> Result<(), Error> {
        self.1.borrow_mut().push(message.to_string());
        Ok(())
    }
    fn confirm(&mut self, _: &str) -> Result<bool, Error> {
        Ok(self.0)
    }
    fn secret(&mut self, _: &str) -> Result<SecretValue, Error> {
        unreachable!("never asks for a secret")
    }
}

fn file(text: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.toml");
    std::fs::write(&path, text).unwrap();
    (dir, path)
}

fn create(
    w: &World,
    fleet: &Fleet,
    path: &Path,
    yes: bool,
) -> (Result<(), Error>, String, Vec<String>) {
    let mut ui = Answer(yes, RefCell::new(Vec::new()));
    let mut out = Vec::new();
    let res = run(fleet, path, "staging", "web", "shop", w, &mut ui, &mut out);
    (res, String::from_utf8(out).unwrap(), ui.1.borrow().clone())
}

// ── The token never leaves stdin ───────────────────────────────────────────────

#[test]
fn the_token_reaches_onepassword_on_stdin() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let _ = create(&w, &fleet(None), &path, true);
    assert!(w.item_stdin().contains(TOKEN));
}

#[test]
fn the_token_is_never_a_program_argument() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let _ = create(&w, &fleet(None), &path, true);
    assert!(
        !w.calls
            .borrow()
            .iter()
            .any(|(_, a, _)| a.iter().any(|x| x.contains("FAKEDEPLOYTOKENMARKER")))
    );
}

#[test]
fn the_token_is_never_written_to_the_configuration_file() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let _ = create(&w, &fleet(None), &path, true);
    assert!(!std::fs::read_to_string(&path).unwrap().contains(TOKEN));
}

#[test]
fn the_token_is_never_shown_in_output_or_the_confirmation() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let (res, out, shown) = create(&w, &fleet(None), &path, true);
    let all = format!("{res:?}{out}{}", shown.join("\n"));
    assert!(!all.contains("FAKEDEPLOYTOKENMARKER"), "{all}");
}

#[test]
fn a_store_failure_never_puts_the_token_in_the_error() {
    let w = World::new();
    w.op.vaults.borrow_mut().retain(|(id, _)| id != "vstate");
    let (_d, path) = file(&fleet_text(None));
    let (res, _, _) = create(&w, &fleet(None), &path, true);
    assert!(!format!("{:?}", res.unwrap_err()).contains("FAKEDEPLOYTOKENMARKER"));
}

// ── Recording the reference ────────────────────────────────────────────────────

#[test]
fn the_item_reference_is_recorded_on_the_target() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let _ = create(&w, &fleet(None), &path, true);
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains(&format!("deploy_credentials = {RECORDED_REFERENCE:?}"))
    );
}

#[test]
fn recording_the_reference_preserves_the_files_comments() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let _ = create(&w, &fleet(None), &path, true);
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("# keep this comment")
    );
}

// ── Refusals happen before anything is created ─────────────────────────────────

#[test]
fn a_target_that_already_records_deploy_credentials_is_refused() {
    let w = World::new();
    let deploy = Some("op://vstate/already0000000000000000001");
    let (_d, path) = file(&fleet_text(deploy));
    let (res, _, _) = create(&w, &fleet(deploy), &path, true);
    assert_eq!(res.unwrap_err().code_str(), "already_declared");
}

#[test]
fn a_target_that_already_records_deploy_credentials_calls_no_provider() {
    let w = World::new();
    let deploy = Some("op://vstate/already0000000000000000001");
    let (_d, path) = file(&fleet_text(deploy));
    let _ = create(&w, &fleet(deploy), &path, true);
    assert!(!w.ran("flyctl", &["tokens"]));
}

#[test]
fn a_target_that_already_records_deploy_credentials_creates_no_item() {
    let w = World::new();
    let deploy = Some("op://vstate/already0000000000000000001");
    let (_d, path) = file(&fleet_text(deploy));
    let _ = create(&w, &fleet(deploy), &path, true);
    assert!(!w.ran("op", &["item"]));
}

#[test]
fn a_provider_that_cannot_mint_is_refused() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let (res, _, _) = create(&w, &github_fleet(), &path, true);
    assert_eq!(res.unwrap_err().code_str(), "usage");
}

#[test]
fn a_provider_that_cannot_mint_asks_nothing() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let (_, _, shown) = create(&w, &github_fleet(), &path, true);
    assert!(shown.is_empty());
}

#[test]
fn declining_creates_no_provider_token() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let _ = create(&w, &fleet(None), &path, false);
    assert!(!w.ran("flyctl", &["tokens"]));
}

#[test]
fn declining_creates_no_onepassword_item() {
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let _ = create(&w, &fleet(None), &path, false);
    assert!(!w.ran("op", &["item"]));
}

#[test]
fn a_missing_provider_sign_in_is_reported_as_auth_required() {
    let mut w = World::new();
    w.fly_signed_in = false;
    let (_d, path) = file(&fleet_text(None));
    let (res, _, _) = create(&w, &fleet(None), &path, true);
    assert_eq!(res.unwrap_err().code(), Code::AuthRequired);
}

#[test]
fn a_missing_provider_sign_in_creates_no_token() {
    let mut w = World::new();
    w.fly_signed_in = false;
    let (_d, path) = file(&fleet_text(None));
    let _ = create(&w, &fleet(None), &path, true);
    assert!(!w.ran("flyctl", &["tokens"]));
}

// ── A failed store names what was created and how to revoke it ─────────────────

#[test]
fn a_failed_store_names_the_minted_credential() {
    let w = World::new();
    w.op.vaults.borrow_mut().retain(|(id, _)| id != "vstate");
    let (_d, path) = file(&fleet_text(None));
    let (res, _, _) = create(&w, &fleet(None), &path, true);
    assert!(message(&res.unwrap_err()).contains(CREDENTIAL));
}

#[test]
fn a_failed_store_gives_the_providers_revoke_hint() {
    let w = World::new();
    w.op.vaults.borrow_mut().retain(|(id, _)| id != "vstate");
    let (_d, path) = file(&fleet_text(None));
    let (res, _, _) = create(&w, &fleet(None), &path, true);
    // C21: the revoke is the cause's Do (SecretNotStored), never free text.
    assert_eq!(res.unwrap_err().code_str(), "secret_not_stored");
}

#[test]
fn a_failed_store_never_leads_to_the_mint_again() {
    // C21 (X5): a token that was minted but not stored steps to a read, never a re-run of
    // `--create`, which would mint a second token.
    let w = World::new();
    w.op.vaults.borrow_mut().retain(|(id, _)| id != "vstate");
    let (_d, path) = file(&fleet_text(None));
    let (res, _, _) = create(&w, &fleet(None), &path, true);
    let next = res.unwrap_err().next_text().unwrap_or_default();
    assert!(!next.contains("--create"), "{next}");
}

#[test]
fn a_failed_store_records_nothing() {
    let w = World::new();
    w.op.vaults.borrow_mut().retain(|(id, _)| id != "vstate");
    let (_d, path) = file(&fleet_text(None));
    let _ = create(&w, &fleet(None), &path, true);
    assert!(
        !std::fs::read_to_string(&path)
            .unwrap()
            .contains("deploy_credentials")
    );
}

// ── The read-only form prints the state ────────────────────────────────────────

#[test]
fn show_reports_the_recorded_reference() {
    let w = World::new();
    let deploy = Some(RECORDED_REFERENCE);
    let mut out = Vec::new();
    show(&fleet(deploy), "staging", "web", &w, &mut out).unwrap();
    assert!(String::from_utf8(out).unwrap().contains(RECORDED_REFERENCE));
}

#[test]
fn show_names_the_next_command() {
    let w = World::new();
    let mut out = Vec::new();
    show(&fleet(None), "staging", "web", &w, &mut out).unwrap();
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains("Next: opv target credentials staging --target web --create")
    );
}

fn shown(fleet: &Fleet, w: &World) -> String {
    let mut out = Vec::new();
    show(fleet, "staging", "web", w, &mut out).unwrap();
    String::from_utf8(out).unwrap()
}

#[test]
fn show_never_suggests_create_when_credentials_are_recorded() {
    let w = World::new();
    assert!(!shown(&fleet(Some(RECORDED_REFERENCE)), &w).contains("--create"));
}

#[test]
fn show_names_the_provider_sign_in_before_create() {
    let mut w = World::new();
    w.fly_signed_in = false;
    assert!(shown(&fleet(None), &w).contains("Do: sign in to Fly: flyctl auth login"));
}

#[test]
fn show_never_suggests_create_where_the_provider_cannot_mint() {
    let w = World::new();
    let mut out = Vec::new();
    show(&github_fleet(), "staging", "web", &w, &mut out).unwrap();
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains("Next: opv config edit")
    );
}

#[test]
fn a_recorded_credential_refusal_points_to_config_edit() {
    let w = World::new();
    let deploy = Some(RECORDED_REFERENCE);
    let (_d, path) = file(&fleet_text(deploy));
    let (res, _, _) = create(&w, &fleet(deploy), &path, true);
    assert_eq!(
        res.unwrap_err().next_text().unwrap_or_default(),
        "opv config edit"
    );
}

// ── Regressions of the audit findings (06-targets.md) ──────────────────────────

/// A catalog error's message, or a legacy error's text.
fn message(e: &Error) -> String {
    match e.cause() {
        Some((c, _)) => c.message(),
        None => e.text().to_string(),
    }
}

#[test]
fn show_names_the_preflight_cause_not_a_sign_in() {
    // 06.06: the summary line repeats the cause the preflight found.
    let mut w = World::new();
    w.fly_signed_in = false;
    assert!(shown(&fleet(None), &w).contains("Fly can mint one once this is fixed: "));
}

#[test]
fn show_leads_to_create_once_the_preflight_cause_is_fixed() {
    // The step follows the target's state: after signing in, the --create runs.
    let mut w = World::new();
    w.fly_signed_in = false;
    assert!(
        shown(&fleet(None), &w)
            .contains("Next: opv target credentials staging --target web --create")
    );
}

#[test]
fn a_preflight_failure_keeps_its_do_unchanged() {
    // 06.07: nothing is appended to the line that becomes Do.
    let mut w = World::new();
    w.fly_signed_in = false;
    let (_d, path) = file(&fleet_text(None));
    let (res, _, _) = create(&w, &fleet(None), &path, true);
    let action = res.unwrap_err().do_text();
    assert!(!action.unwrap_or_default().contains("nothing was created"));
}

#[test]
fn a_generated_configuration_is_refused_before_a_token_is_minted() {
    // 06.08: a configuration that cannot take the reference is refused before the mint.
    let w = World::new();
    let (_d, path) = file(&format!("# generated by make\n{}", fleet_text(None)));
    let _ = create(&w, &fleet(None), &path, true);
    assert!(!w.ran("flyctl", &["tokens"]));
}

#[test]
fn a_reference_that_cannot_be_recorded_names_the_stored_item() {
    // 06.08: the failure says what exists, so nothing is minted twice.
    let (_d, path) = file(&fleet_text(None));
    let done = vec!["1Password item i1 in vault vstate, to record as op://vstate/i1".into()];
    let e = not_recorded(
        Error::Config("could not edit".to_string().into()),
        &path,
        "staging",
        "web",
        done,
    );
    assert!(message(&e).contains("op://vstate/i1"));
}

#[test]
fn a_reference_that_cannot_be_recorded_never_leads_to_the_mint_again() {
    // 06.08, X5: Next is a read, never the --create.
    let (_d, path) = file(&fleet_text(None));
    let e = not_recorded(
        Error::Config("could not edit".to_string().into()),
        &path,
        "staging",
        "web",
        vec!["Fly deploy token t".into()],
    );
    assert!(!e.next_text().unwrap_or_default().contains("--create"));
}

#[test]
fn a_failed_store_fills_in_the_app_to_list_tokens() {
    // 06.09: the revoke hint names the app, never `<app>`.
    let w = World::new();
    w.op.vaults.borrow_mut().retain(|(id, _)| id != "vstate");
    let (_d, path) = file(&fleet_text(None));
    let (res, _, _) = create(&w, &fleet(None), &path, true);
    // C21: Fly's own listing is the step that finds the token (Provider::mint_refind).
    let next = res.unwrap_err().next_text().unwrap_or_default();
    assert_eq!(next, "flyctl tokens list --app shop-staging");
}

#[test]
fn declining_is_the_declined_cause() {
    // 06.45: a decline is its own cause, never "fix the cause above".
    let w = World::new();
    let (_d, path) = file(&fleet_text(None));
    let (res, _, _) = create(&w, &fleet(None), &path, false);
    assert_eq!(res.unwrap_err().code_str(), "declined");
}

#[test]
fn a_misspelt_target_is_an_unknown_target() {
    let w = World::new();
    let mut out = Vec::new();
    let e = show(&fleet(None), "staging", "wbe", &w, &mut out).unwrap_err();
    assert_eq!(e.code_str(), "unknown_target");
}
