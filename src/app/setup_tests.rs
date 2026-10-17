use super::*;
use std::cell::RefCell;
use std::collections::VecDeque;

type RecordedCalls = Vec<(Vec<String>, Option<Vec<u8>>)>;
struct Fake {
    replies: RefCell<VecDeque<Output>>,
    calls: RefCell<RecordedCalls>,
    logins: Vec<bool>,
}
impl Fake {
    fn new(replies: Vec<Output>) -> Self {
        Self {
            replies: RefCell::new(replies.into()),
            calls: RefCell::new(Vec::new()),
            logins: Vec::new(),
        }
    }
}
impl Backend for Fake {
    fn native(&self) -> Result<(), Error> {
        Ok(())
    }
    fn call(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, Error> {
        self.calls.borrow_mut().push((
            args.iter().map(|s| s.to_string()).collect(),
            stdin.map(<[u8]>::to_vec),
        ));
        Ok(self
            .replies
            .borrow_mut()
            .pop_front()
            .expect("unexpected call"))
    }
    fn sign_in(&mut self, _: Option<&str>, add: bool) -> Result<(), Error> {
        self.logins.push(add);
        Ok(())
    }
}
struct Ui {
    confirms: VecDeque<bool>,
    values: VecDeque<SecretValue>,
    messages: Vec<String>,
}
impl Ui {
    fn new(confirms: Vec<bool>, values: &[&str]) -> Self {
        Self {
            confirms: confirms.into(),
            values: values
                .iter()
                .map(|s| SecretValue::new((*s).into()))
                .collect(),
            messages: Vec::new(),
        }
    }
}
impl Interaction for Ui {
    fn show(&mut self, s: &str) -> Result<(), Error> {
        self.messages.push(s.into());
        Ok(())
    }
    fn confirm(&mut self, s: &str) -> Result<bool, Error> {
        self.messages.push(s.into());
        Ok(self.confirms.pop_front().expect("unexpected confirmation"))
    }
    fn secret(&mut self, _: &str) -> Result<SecretValue, Error> {
        Ok(self.values.pop_front().expect("unexpected value prompt"))
    }
}
fn ok(value: &str) -> Output {
    Output::success(value.as_bytes().to_vec())
}
fn recipe(dir: &Path) -> PathBuf {
    let path = dir.join("opv.setup.toml");
    fs::write(&path, "title='Local example'\nenvironment='dev'\nvault='Development'\nitem='api'\n[[fields]]\nkey='API_KEY'\nproduct='api'\ntitle='Provider login'\ndescription='Lets this API call its provider.'\nsource='Your provider dashboard.'\n").unwrap();
    path
}
fn metadata() -> Vec<Output> {
    vec![
        ok("2.40.0"),
        ok(r#"[{"id":"vault-id","name":"Development"}]"#),
    ]
}

#[test]
fn missing_item_is_created_with_hidden_input_and_metadata_only_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.extend([
        ok("[]"),
        ok(r#"{"id":"item-id","fields":[{"value":"synthetic-private"}]}"#),
    ]);
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![true], &["synthetic-private"]);
    assert_eq!(
        run(&path, None, None, None, &mut backend, &mut ui).unwrap(),
        0
    );
    let output = fs::read_to_string(dir.path().join("secrets.toml")).unwrap();
    assert!(!output.contains("synthetic-private"));
    assert!(!ui.messages.join("\n").contains("synthetic-private"));
    let calls = backend.calls.borrow();
    assert!(
        !format!("{:?}", calls.iter().map(|c| &c.0).collect::<Vec<_>>())
            .contains("synthetic-private")
    );
    let body: Value = serde_json::from_slice(calls.last().unwrap().1.as_ref().unwrap()).unwrap();
    assert_eq!(body["fields"][0]["value"], "synthetic-private");
    assert_eq!(calls.last().unwrap().0[1], "create");
}

#[test]
fn skipping_a_value_saves_resumable_progress_and_exits_findings() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.extend([ok("[]"), ok(r#"{"id":"item-id"}"#)]);
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![true], &[""]);
    assert_eq!(
        run(&path, None, None, None, &mut backend, &mut ui).unwrap(),
        8
    );
    assert!(ui.messages.join("\n").contains("Provider login"));
    assert!(ui.messages.join("\n").contains("Saved progress"));
    assert!(dir.path().join("secrets.toml").exists());
}

#[test]
fn repeated_setup_keeps_existing_value_and_makes_no_write_or_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.extend([ok(r#"[{"id":"item-id","title":"api"}]"#),ok(r#"{"category":"SECURE_NOTE","sections":[{"id":"api","label":"api"}],"fields":[{"id":"key","section":{"id":"api","label":"api"},"label":"API_KEY","type":"CONCEALED","value":"synthetic-existing"}]}"#)]);
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![], &[]);
    assert_eq!(
        run(&path, None, None, None, &mut backend, &mut ui).unwrap(),
        0
    );
    assert!(
        !backend
            .calls
            .borrow()
            .iter()
            .any(|c| c.0.get(1).is_some_and(|s| s == "edit" || s == "create"))
    );
    assert!(!ui.messages.join("\n").contains("synthetic-existing"));
}

#[test]
fn cancel_before_create_does_not_write_item_or_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.push(ok("[]"));
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![false], &[""]);
    assert_eq!(
        run(&path, None, None, None, &mut backend, &mut ui).unwrap(),
        6
    );
    assert!(!dir.path().join("secrets.toml").exists());
    assert_eq!(backend.calls.borrow().len(), 3);
}

#[test]
fn failed_authentication_is_repaired_then_vault_access_is_verified() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut backend = Fake::new(vec![
        ok("2.40.0"),
        Output::failure(1),
        ok("[]"),
        ok(r#"[{"id":"vault-id","name":"Development"}]"#),
        ok("[]"),
        ok(r#"{"id":"item-id"}"#),
    ]);
    let mut ui = Ui::new(vec![true], &[""]);
    assert_eq!(
        run(&path, None, None, None, &mut backend, &mut ui).unwrap(),
        8
    );
    assert_eq!(backend.logins, vec![true, false]);
}

/// [`Backend`] over the runner's fake, which observes every failed call as the real runner
/// does, so a failure is diagnosed from op's reply (#159).
struct Observed {
    r: crate::runner::fake::FakeRunner,
}
impl Backend for Observed {
    fn native(&self) -> Result<(), Error> {
        Ok(())
    }
    fn call(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, Error> {
        use crate::runner::{Call, CommandRunner, Outcome};
        match self
            .r
            .read(&Call::new("op", args).with_stdin(stdin), &[])
            .unwrap()
        {
            Outcome::Done(o) | Outcome::Refused(o) => Ok(o),
            Outcome::Unknown { .. } => unreachable!("no unknown outcome is queued"),
        }
    }
    fn sign_in(&mut self, _: Option<&str>, _: bool) -> Result<(), Error> {
        Ok(())
    }
}

/// op's reply to a call made without a session (recorded case 06).
const SIGNED_OUT: &str = "[ERROR] 2026/10/16 10:00:00 You are not currently signed in. Please run `op signin --help` for instructions";

/// Setup whose vault list still fails after the sign-in (#157), op saying no one is
/// signed in.
fn vaults_unlisted_after_sign_in() -> Error {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let r = crate::runner::fake::FakeRunner::new([ok("2.40.0")]);
    r.push_with_stderr(Output::failure(1), SIGNED_OUT);
    r.responses
        .borrow_mut()
        .push_back(Ok(ok(r#"[{"url":"my.1password.com"}]"#)));
    r.push_with_stderr(Output::failure(1), SIGNED_OUT);
    let mut backend = Observed { r };
    let mut ui = Ui::new(vec![], &[]);
    run(&path, None, None, None, &mut backend, &mut ui).unwrap_err()
}

// 05.08, #159: the cause is op's own reply, never one chosen by setup.
#[test]
fn vaults_unlisted_after_sign_in_are_diagnosed_from_ops_reply() {
    assert_eq!(
        vaults_unlisted_after_sign_in().code_str(),
        "op_not_signed_in"
    );
}

// 05.08: never "rerun setup", which `opv login` shares.
#[test]
fn vaults_unlisted_after_sign_in_never_name_setup() {
    assert!(
        !vaults_unlisted_after_sign_in()
            .to_string()
            .contains("setup")
    );
}

// #159: `op whoami --account <id>` answers, then `op vault list` says no one is signed in:
// the account's own sign-in, from op's reply (no longer a Legacy source_error).
#[test]
fn a_signed_out_vault_list_under_a_live_session_is_op_not_signed_in() {
    let r = crate::runner::fake::FakeRunner::new([ok("2.40.0"), ok(WHOAMI_A)]);
    r.push_with_stderr(Output::failure(1), SIGNED_OUT);
    let mut backend = Observed { r };
    let e = prepare(
        Some("ACCOUNT0000000000000000001"),
        &mut backend,
        &mut Ui::new(vec![], &[]),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "op_not_signed_in");
}

// 05.26: a failing item step is diagnosed from op's reply, naming no generic "this step".
#[test]
fn a_failing_item_list_is_diagnosed_from_ops_reply() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let r = crate::runner::fake::FakeRunner::new(metadata());
    r.push_with_stderr(Output::failure(1), SIGNED_OUT);
    let mut backend = Observed { r };
    let e = run(
        &path,
        None,
        None,
        None,
        &mut backend,
        &mut Ui::new(vec![], &[]),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "op_not_signed_in");
}

#[test]
fn a_missing_vault_names_the_account_it_was_looked_for_in() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut backend = Fake::new(vec![
        ok("2.40.0"),
        ok(WHOAMI_A),
        ok(r#"[{"id":"x","name":"Other"}]"#),
    ]);
    let mut ui = Ui::new(vec![], &[]);
    let error = run(
        &path,
        None,
        Some("ACCOUNT0000000000000000001"),
        None,
        &mut backend,
        &mut ui,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("looked for in 1Password account ACCOUNT0000000000000000001"),
        "{error}"
    );
}

#[test]
fn wrong_kind_has_specific_repair_and_preserves_existing_item() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.extend([ok(r#"[{"id":"item-id","title":"api"}]"#),ok(r#"{"category":"SECURE_NOTE","sections":[{"id":"api","label":"api"}],"fields":[{"section":{"id":"api","label":"api"},"label":"API_KEY","type":"STRING","value":"synthetic-private"}]}"#)]);
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![], &[]);
    let error = run(&path, None, None, None, &mut backend, &mut ui).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("stored as plain text, not concealed")
    );
    assert!(!error.to_string().contains("synthetic-private"));
    assert_eq!(backend.calls.borrow().len(), 4);
}

#[test]
fn an_item_read_of_another_shape_is_unexpected_output() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.extend([
        ok(r#"[{"id":"item-id","title":"api"}]"#),
        ok(r#"{"category":"SECURE_NOTE","fields":[{"section":{"id":"api","label":"api"},"label":"API_KEY","type":5}]}"#),
    ]);
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![], &[]);
    let error = run(&path, None, None, None, &mut backend, &mut ui).unwrap_err();
    assert_eq!(error.code_str(), "unexpected_output");
}

#[test]
fn conflicting_configuration_is_refused_before_any_vendor_call() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let recipe = Recipe::parse(&fs::read_to_string(&path).unwrap()).unwrap();
    fs::write(
        dir.path().join("secrets.toml"),
        recipe
            .manifest("other-vault", "other-item")
            .unwrap()
            .replace("API_KEY", "OTHER_KEY"),
    )
    .unwrap();
    let mut backend = Fake::new(vec![]);
    let mut ui = Ui::new(vec![], &[]);
    assert!(run(&path, None, None, None, &mut backend, &mut ui).is_err());
    assert!(backend.calls.borrow().is_empty());
}

#[test]
fn duplicate_vault_is_refused_without_guessing_or_writing() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut backend = Fake::new(vec![
        ok("2.40.0"),
        ok(r#"[{"id":"a","name":"Development"},{"id":"b","name":"Development"}]"#),
    ]);
    let mut ui = Ui::new(vec![], &[]);
    let error = run(&path, None, None, None, &mut backend, &mut ui).unwrap_err();
    // F4: a duplicate title is the catalog's ItemUnusable (its Do renames the duplicate).
    assert_eq!(error.code_str(), "item_unusable");
    assert_eq!(backend.calls.borrow().len(), 2);
}

#[test]
fn shared_keys_have_unique_ids_and_keep_product_sections() {
    let recipe = Recipe::parse("title='Products'\nenvironment='dev'\nvault='Development'\nitem='api'\n[[fields]]\nkey='API_KEY'\nproduct='one'\ntitle='One login'\ndescription='For one.'\nsource='Dashboard.'\n[[fields]]\nkey='API_KEY'\nproduct='two'\ntitle='Two login'\ndescription='For two.'\nsource='Dashboard.'\n").unwrap();
    let mut doc = json!({"category":"SECURE_NOTE","fields":[],"sections":[]});
    let indices = field_indices(&mut doc, &recipe.fields, &recipe).unwrap();
    assert_ne!(
        doc["fields"][indices[0]]["id"],
        doc["fields"][indices[1]]["id"]
    );
    assert_eq!(doc["fields"][indices[1]]["section"]["label"], "two");
    assert_eq!(
        field_indices(&mut doc, &recipe.fields, &recipe).unwrap(),
        indices
    );
}

#[test]
fn product_setup_prompts_only_selected_product_but_declares_all_managed_names() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("opv.setup.toml");
    fs::write(&path, "title='Products'\nenvironment='dev'\nvault='Development'\nitem='api'\n[[fields]]\nkey='ONE_KEY'\nproduct='one'\ntitle='One login'\ndescription='For one.'\nsource='Dashboard.'\n[[fields]]\nkey='TWO_KEY'\nproduct='two'\ntitle='Two login'\ndescription='For two.'\nsource='Dashboard.'\n").unwrap();
    let mut replies = metadata();
    replies.extend([ok("[]"), ok(r#"{"id":"item-id"}"#)]);
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![true], &["synthetic-one"]);
    assert_eq!(
        run(&path, None, None, Some("one"), &mut backend, &mut ui).unwrap(),
        0
    );
    let config = fs::read_to_string(dir.path().join("secrets.toml")).unwrap();
    assert!(config.contains("ONE_KEY") && config.contains("TWO_KEY"));
    assert!(!ui.messages.join("\n").contains("Two login"));
    let calls = backend.calls.borrow();
    let body: Value = serde_json::from_slice(calls.last().unwrap().1.as_ref().unwrap()).unwrap();
    assert_eq!(body["fields"].as_array().unwrap().len(), 1);
}

// --- #160: the session is checked for the account asked for, never by a bare whoami -------

/// Recorded case 10: `op whoami --account A --format json` while A is signed in.
const WHOAMI_A: &str = include_str!("../../tests/fixtures/op/failures/10-whoami-a.stdout");
/// Account B, asked for (the recordings' `<ACCOUNT_1>`).
const ACCOUNT_B: &str = "BACCOUNT000000000000000001";

/// Setup for account B, whose `op whoami --account B` fails as in recorded case 11 (only A
/// holds a session); B is signed in at the prompt.
fn setup_for_b_with_a_live() -> Fake {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut backend = Fake::new(vec![
        ok("2.40.0"),
        Output::failure(1),
        ok(r#"[{"url":"my.1password.com"}]"#),
        ok(WHOAMI_A.replace("<ACCOUNT_2>", ACCOUNT_B).as_str()),
        ok(r#"[{"id":"x","name":"Other"}]"#),
    ]);
    let _ = run(
        &path,
        None,
        Some(ACCOUNT_B),
        None,
        &mut backend,
        &mut Ui::new(vec![], &[]),
    );
    backend
}

#[test]
fn setup_checks_the_session_of_the_account_by_id() {
    let backend = setup_for_b_with_a_live();
    assert_eq!(
        backend.calls.borrow()[1].0,
        ["whoami", "--account", ACCOUNT_B, "--format", "json"]
    );
}

#[test]
fn a_live_session_for_another_account_is_never_taken_for_the_account() {
    assert_eq!(setup_for_b_with_a_live().logins, [false]);
}

#[test]
fn setup_without_an_account_never_runs_a_bare_whoami() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut backend = Fake::new(vec![
        ok("2.40.0"),
        Output::failure(1),
        ok(r#"[{"url":"my.1password.com"}]"#),
        Output::failure(1),
    ]);
    let _ = run(
        &path,
        None,
        None,
        None,
        &mut backend,
        &mut Ui::new(vec![], &[]),
    );
    assert!(!backend.calls.borrow().iter().any(|c| c.0[0] == "whoami"));
}

// --- #153: the child `op signin` for B, with a session for A in opv's environment ---------

/// Recorded case 13: `op signin --account B` with `OP_SESSION_<A>` set and `OP_ACCOUNT`
/// unset succeeded (op 2.40.0). opv runs it so: the account in `--account` only.
fn signin_for_b() -> std::process::Command {
    signin_command(
        Some(ACCOUNT_B),
        false,
        [
            std::ffi::OsString::from("OP_SESSION_ACCOUNTA0000000000000000001"),
            std::ffi::OsString::from("PATH"),
        ],
    )
}

fn removed(command: &std::process::Command) -> Vec<String> {
    command
        .get_envs()
        .filter(|(_, v)| v.is_none())
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn signing_in_to_b_unsets_op_account_for_op() {
    assert!(removed(&signin_for_b()).contains(&"OP_ACCOUNT".to_string()));
}

#[test]
fn signing_in_to_b_unsets_the_other_accounts_session() {
    assert!(
        removed(&signin_for_b()).contains(&"OP_SESSION_ACCOUNTA0000000000000000001".to_string())
    );
}

#[test]
fn signing_in_to_b_keeps_the_rest_of_the_environment() {
    assert!(!removed(&signin_for_b()).contains(&"PATH".to_string()));
}

#[test]
fn signing_in_to_b_names_b_with_the_account_flag() {
    let args: Vec<_> = signin_for_b()
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert_eq!(args, ["signin", "--force", "--account", ACCOUNT_B]);
}

// --- the save after a long interactive window: fresh re-read, re-plan, verified write ---

mod stateful {
    use super::*;
    use crate::adapters::fake_op::FakeOp;
    use crate::adapters::onepassword::NO_CACHE;
    use crate::runner::{Call, CommandRunner, Outcome};
    use std::rc::Rc;

    const VAULT: &str = "vdev0000000000000000000001";

    /// [`Backend`] over the stateful fake `op`; `drop_values` makes every edit lose its
    /// values on the way, as a faulty write would.
    struct Op {
        op: Rc<FakeOp>,
        drop_values: bool,
    }
    impl Backend for Op {
        fn native(&self) -> Result<(), Error> {
            Ok(())
        }
        fn call(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, Error> {
            if args == ["--version"] {
                return Ok(ok("2.40.0"));
            }
            let stripped = stdin.filter(|_| self.drop_values).map(|s| {
                let mut v: Value = serde_json::from_slice(s).unwrap();
                for f in v["fields"].as_array_mut().into_iter().flatten() {
                    f["value"] = json!("");
                }
                serde_json::to_vec(&v).unwrap()
            });
            let call = Call::new("op", args).with_stdin(stripped.as_deref().or(stdin));
            match self.op.read(&call, &[]).unwrap() {
                Outcome::Done(o) | Outcome::Refused(o) => Ok(o),
                Outcome::Unknown { .. } => unreachable!(),
            }
        }
        fn sign_in(&mut self, _: Option<&str>, _: bool) -> Result<(), Error> {
            Ok(())
        }
    }

    type Hook = Box<dyn FnMut()>;
    /// [`Ui`] that runs `on_secret` during the value prompt and `on_confirm[n]` during the
    /// n-th confirmation: someone else editing the item while setup waits for the owner.
    struct Racing {
        ui: Ui,
        on_secret: Option<Hook>,
        on_confirm: BTreeMap<usize, Hook>,
        confirms: usize,
    }
    impl Interaction for Racing {
        fn show(&mut self, s: &str) -> Result<(), Error> {
            self.ui.show(s)
        }
        fn confirm(&mut self, s: &str) -> Result<bool, Error> {
            self.confirms += 1;
            if let Some(h) = self.on_confirm.get_mut(&self.confirms) {
                h();
            }
            self.ui.confirm(s)
        }
        fn secret(&mut self, s: &str) -> Result<SecretValue, Error> {
            if let Some(h) = self.on_secret.as_mut() {
                h();
            }
            self.ui.secret(s)
        }
    }

    /// The setup item `api` with `API_KEY` empty and an unrelated field `NOTE`.
    fn op_with_item() -> (Rc<FakeOp>, String) {
        let op = Rc::new(FakeOp::default());
        let id = op.insert(
            VAULT,
            json!({"title": "api", "category": "SECURE_NOTE", "sections": [{"id": "api", "label": "api"}], "fields": [
                {"id": "key", "section": {"id": "api", "label": "api"}, "label": "API_KEY", "type": "CONCEALED", "value": ""},
                {"id": "note", "label": "NOTE", "type": "STRING", "value": "first"},
            ]}),
        );
        (op, id)
    }

    fn recipe_in(dir: &Path) -> PathBuf {
        let path = dir.join("opv.setup.toml");
        fs::write(&path, "title='Local example'\nenvironment='dev'\nvault='myapp-dev'\nitem='api'\n[[fields]]\nkey='API_KEY'\nproduct='api'\ntitle='Provider login'\ndescription='Lets this API call its provider.'\nsource='Your provider dashboard.'\n").unwrap();
        path
    }

    /// Someone else sets `label` to `value` in the 1Password app: a new version.
    fn edit_elsewhere(op: &FakeOp, id: &str, label: &str, value: &str) {
        for i in op.items.borrow_mut().iter_mut() {
            if i["id"] == id {
                for f in i["fields"].as_array_mut().into_iter().flatten() {
                    if f["label"] == label {
                        f["value"] = json!(value);
                    }
                }
                i["version"] = json!(i["version"].as_u64().unwrap() + 1);
            }
        }
    }

    fn hook(op: &Rc<FakeOp>, id: &str, label: &'static str, value: &'static str) -> Hook {
        let (op, id) = (Rc::clone(op), id.to_string());
        Box::new(move || edit_elsewhere(&op, &id, label, value))
    }

    fn field(op: &FakeOp, id: &str, label: &str) -> Value {
        op.item(id)["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["label"] == label)
            .map(|f| f["value"].clone())
            .unwrap_or(Value::Null)
    }

    fn racing(confirms: Vec<bool>, values: &[&str]) -> Racing {
        Racing {
            ui: Ui::new(confirms, values),
            on_secret: None,
            on_confirm: BTreeMap::new(),
            confirms: 0,
        }
    }

    fn setup(op: &Rc<FakeOp>, ui: &mut Racing, drop_values: bool) -> Result<i32, Error> {
        let dir = tempfile::tempdir().unwrap();
        let path = recipe_in(dir.path());
        let mut backend = Op {
            op: Rc::clone(op),
            drop_values,
        };
        run(&path, None, None, None, &mut backend, ui)
    }

    /// The args of the call right before the first `item edit`.
    fn call_before_edit(op: &FakeOp) -> Vec<String> {
        let calls = op.calls.borrow();
        let at = calls
            .iter()
            .position(|c| c.args.get(1).is_some_and(|a| a == "edit"))
            .unwrap();
        calls[at - 1].args.clone()
    }

    #[test]
    fn save_rereads_the_item_fresh_right_before_writing() {
        let (op, _) = op_with_item();
        let mut ui = racing(vec![true], &["synthetic-typed"]);
        setup(&op, &mut ui, false).unwrap();
        let before = call_before_edit(&op);
        assert!(before[..2] == ["item", "get"] && before.contains(&NO_CACHE.to_string()));
    }

    #[test]
    fn an_unchanged_item_is_saved_with_the_typed_value() {
        let (op, id) = op_with_item();
        let mut ui = racing(vec![true], &["synthetic-typed"]);
        setup(&op, &mut ui, false).unwrap();
        assert_eq!(field(&op, &id, "API_KEY"), "synthetic-typed");
    }

    #[test]
    fn an_edit_made_while_setup_waited_is_kept() {
        let (op, id) = op_with_item();
        let mut ui = racing(vec![true, true], &["synthetic-typed"]);
        ui.on_secret = Some(hook(&op, &id, "NOTE", "theirs"));
        setup(&op, &mut ui, false).unwrap();
        assert_eq!(field(&op, &id, "NOTE"), "theirs");
    }

    #[test]
    fn a_value_typed_before_a_concurrent_edit_is_saved_without_asking_again() {
        let (op, id) = op_with_item();
        // One value only: a second prompt would panic.
        let mut ui = racing(vec![true, true], &["synthetic-typed"]);
        ui.on_secret = Some(hook(&op, &id, "NOTE", "theirs"));
        setup(&op, &mut ui, false).unwrap();
        assert_eq!(field(&op, &id, "API_KEY"), "synthetic-typed");
    }

    #[test]
    fn the_owner_is_told_and_asked_once_more_after_a_concurrent_edit() {
        let (op, id) = op_with_item();
        let mut ui = racing(vec![true, true], &["synthetic-typed"]);
        ui.on_secret = Some(hook(&op, &id, "NOTE", "theirs"));
        setup(&op, &mut ui, false).unwrap();
        let text = ui.ui.messages.join("\n");
        assert!(
            text.contains("changed in 1Password while setup was open") && ui.confirms == 2,
            "{text}"
        );
    }

    #[test]
    fn a_field_filled_elsewhere_keeps_its_1password_value() {
        let (op, id) = op_with_item();
        let mut ui = racing(vec![true, true], &["synthetic-typed"]);
        ui.on_secret = Some(hook(&op, &id, "API_KEY", "synthetic-theirs"));
        setup(&op, &mut ui, false).unwrap();
        assert_eq!(field(&op, &id, "API_KEY"), "synthetic-theirs");
    }

    #[test]
    fn declining_after_a_concurrent_edit_writes_nothing() {
        let (op, id) = op_with_item();
        let mut ui = racing(vec![true, false], &["synthetic-typed"]);
        ui.on_secret = Some(hook(&op, &id, "NOTE", "theirs"));
        assert_eq!(setup(&op, &mut ui, false).unwrap(), 6);
        assert_eq!(op.count(&["op", "item", "edit"]), 0);
    }

    #[test]
    fn a_second_edit_while_saving_is_item_changed_with_nothing_written() {
        let (op, id) = op_with_item();
        let mut ui = racing(vec![true, true], &["synthetic-typed"]);
        ui.on_secret = Some(hook(&op, &id, "NOTE", "theirs"));
        ui.on_confirm.insert(2, hook(&op, &id, "NOTE", "again"));
        let e = setup(&op, &mut ui, false).unwrap_err();
        assert_eq!(
            (e.code_str(), op.count(&["op", "item", "edit"])),
            ("item_changed", 0)
        );
    }

    #[test]
    fn an_edit_landing_with_setups_is_concurrent_edit() {
        let (op, _) = op_with_item();
        op.racing_edit.set(Some(1));
        let mut ui = racing(vec![true], &["synthetic-typed"]);
        let e = setup(&op, &mut ui, false).unwrap_err();
        assert_eq!(e.code_str(), "concurrent_edit");
    }

    // C1: a failure after the save says exactly what the save put in 1Password.
    #[test]
    fn an_edit_landing_with_setups_says_what_was_saved() {
        let (op, _) = op_with_item();
        op.racing_edit.set(Some(1));
        let mut ui = racing(vec![true], &["synthetic-typed"]);
        let _ = setup(&op, &mut ui, false);
        assert!(
            ui.ui
                .messages
                .iter()
                .any(|m| m
                    == "Saved in 1Password: item api in vault myapp-dev, with Provider login."),
            "{:?}",
            ui.ui.messages
        );
    }

    #[test]
    fn a_write_that_lost_a_value_is_read_back_missing() {
        let (op, _) = op_with_item();
        let mut ui = racing(vec![true], &["synthetic-typed"]);
        let e = setup(&op, &mut ui, true).unwrap_err();
        assert_eq!(e.code_str(), "tidy_unverified");
    }

    #[test]
    fn item_changed_never_shows_a_value() {
        let (op, _) = op_with_item();
        op.racing_edit.set(Some(1));
        let mut ui = racing(vec![true], &["synthetic-typed"]);
        let e = setup(&op, &mut ui, false).unwrap_err();
        let shown = format!("{e}{}", ui.ui.messages.join("\n"));
        assert!(!shown.contains("synthetic-typed"), "{shown}");
    }

    /// FR-43: a person's setup tidies the existing item instead of refusing its layout.
    #[test]
    fn setup_conceals_a_secret_stored_as_text_and_saves_it() {
        let op = Rc::new(FakeOp::default());
        let id = op.insert(
            VAULT,
            json!({"title": "api", "category": "SECURE_NOTE", "sections": [], "fields": [
                {"id": "k", "label": "api key", "type": "STRING", "value": "synthetic-private"},
            ]}),
        );
        let mut ui = racing(vec![true], &[]);
        let _on = super::super::super::tidy::activate();
        setup(&op, &mut ui, false).unwrap();
        let item = op.item(&id);
        assert!(
            item["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["label"] == "API_KEY" && f["type"] == "CONCEALED"),
            "{item}"
        );
    }
}

// ---- catalog causes and steps (05.09, 05.21, 05.28, 05.29, 05.32, C1, C8) ----

/// [`Ui`] whose value prompt is stopped by the person (Ctrl-D): the declined guard.
struct Stopping {
    messages: Vec<String>,
}
impl Interaction for Stopping {
    fn show(&mut self, s: &str) -> Result<(), Error> {
        self.messages.push(s.into());
        Ok(())
    }
    fn confirm(&mut self, _: &str) -> Result<bool, Error> {
        Ok(true)
    }
    fn secret(&mut self, _: &str) -> Result<SecretValue, Error> {
        Err(crate::cause::Cause::Guard {
            guard: crate::cause::Guard::Declined,
        }
        .into())
    }
}

/// A recipe of two settings, `SAVED_KEY` (filled in 1Password by an earlier setup) and
/// `NEW_KEY` (empty), and the replies of the item that holds them.
fn two_settings(dir: &Path) -> (PathBuf, Vec<Output>) {
    let path = dir.join("opv.setup.toml");
    fs::write(&path, "title='Two'\nenvironment='dev'\nvault='Development'\nitem='api'\n[[fields]]\nkey='SAVED_KEY'\nproduct='api'\ntitle='Saved login'\ndescription='Saved before.'\nsource='Dashboard.'\n[[fields]]\nkey='NEW_KEY'\nproduct='api'\ntitle='New login'\ndescription='Not yet.'\nsource='Dashboard.'\n").unwrap();
    let mut replies = metadata();
    replies.extend([
        ok(r#"[{"id":"item-id","title":"api"}]"#),
        ok(r#"{"category":"SECURE_NOTE","sections":[{"id":"api","label":"api"}],"fields":[{"id":"s","section":{"id":"api","label":"api"},"label":"SAVED_KEY","type":"CONCEALED","value":"synthetic-saved"}]}"#),
    ]);
    (path, replies)
}

// C1 (X26): stopping at a prompt says exactly what 1Password holds: the fields an earlier
// setup saved are named, and nothing from this run.
#[test]
fn stopping_at_a_prompt_names_the_fields_saved_before() {
    let dir = tempfile::tempdir().unwrap();
    let (path, replies) = two_settings(dir.path());
    let mut ui = Stopping { messages: vec![] };
    let _ = run(&path, None, None, None, &mut Fake::new(replies), &mut ui);
    assert_eq!(
        ui.messages.last().map(String::as_str),
        Some(
            "Stopped before saving: nothing from this run was saved in 1Password. Saved there \
             by an earlier setup: Saved login."
        )
    );
}

#[test]
fn stopping_at_a_prompt_is_declined() {
    let dir = tempfile::tempdir().unwrap();
    let (path, replies) = two_settings(dir.path());
    let mut ui = Stopping { messages: vec![] };
    let e = run(&path, None, None, None, &mut Fake::new(replies), &mut ui).unwrap_err();
    assert_eq!(e.code_str(), "declined");
}

// 05.32: a setup the owner stops ends with the setup command to run again.
#[test]
fn a_stopped_setup_ends_with_its_own_command() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.push(ok("[]"));
    let mut ui = Ui::new(vec![false], &[""]);
    run(&path, None, None, None, &mut Fake::new(replies), &mut ui).unwrap();
    assert_eq!(
        ui.messages.last().cloned(),
        Some(format!(
            "Next: opv setup --recipe {} --product api",
            crate::error::shell_word(&path.display().to_string())
        ))
    );
}

// 05.32: progress saved with fields still empty (exit 8) ends with the setup command too.
#[test]
fn saved_progress_ends_with_its_own_command() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.extend([ok("[]"), ok(r#"{"id":"item-id"}"#)]);
    let mut ui = Ui::new(vec![true], &[""]);
    run(&path, None, None, None, &mut Fake::new(replies), &mut ui).unwrap();
    assert!(
        ui.messages
            .last()
            .is_some_and(|m| m.starts_with("Next: opv setup --recipe ")),
        "{:?}",
        ui.messages
    );
}

/// `opv setup --product apii` on the one-product recipe.
fn unknown_product() -> Error {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    run(
        &path,
        None,
        None,
        Some("apii"),
        &mut Fake::new(vec![]),
        &mut Ui::new(vec![], &[]),
    )
    .unwrap_err()
}

// 05.21: a product the recipe does not declare is a usage error, before any call.
#[test]
fn an_unknown_product_is_a_usage_error() {
    assert_eq!(unknown_product().code_str(), "usage");
}

// 05.21: the one product is substituted into the same command, never the failing one.
#[test]
fn an_unknown_product_steps_to_the_declared_one() {
    // The cause's own command, not its rendering: whether `opv setup` may be the Next depends
    // on the terminal the test runs under (A10, `Situation::refuses`).
    let next = match unknown_product().cause() {
        Some((
            Cause::Usage {
                problem: crate::cause::UsageProblem::UseInstead { command },
            },
            _,
        )) => crate::cause::render::cmd_text(command),
        _ => String::new(),
    };
    assert!(
        next.starts_with("opv setup --recipe ") && next.ends_with(" --product api"),
        "{next}"
    );
}

// 05.28: an output configuration without a boundary is the cataloged boundary_missing, its
// step the cause's own (no "; next:" inside the text).
#[test]
fn an_output_without_a_boundary_is_boundary_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    fs::write(dir.path().join("secrets.toml"), "[environments.dev]\n").unwrap();
    let e = run(
        &path,
        None,
        None,
        None,
        &mut Fake::new(vec![]),
        &mut Ui::new(vec![], &[]),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "boundary_missing");
}

// 05.29: an op whose version cannot be read is tool_unusable, on every platform.
#[test]
fn an_unreadable_op_version_is_tool_unusable() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let e = run(
        &path,
        None,
        None,
        None,
        &mut Fake::new(vec![ok("not a version")]),
        &mut Ui::new(vec![], &[]),
    )
    .unwrap_err();
    assert_eq!(e.code_str(), "tool_unusable");
}

// C8: an invalid recipe is named by its own path.
#[test]
fn an_invalid_recipe_names_its_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("team.setup.toml");
    fs::write(&path, "title=''\n").unwrap();
    let e = run(
        &path,
        None,
        None,
        None,
        &mut Fake::new(vec![]),
        &mut Ui::new(vec![], &[]),
    )
    .unwrap_err();
    assert!(e.to_string().contains("team.setup.toml"), "{e}");
}

// 05.09: a dotenv file that is not there is named, never "the existing settings file".
#[test]
fn a_missing_dotenv_file_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let e = read_legacy(&dir.path().join("typo.env")).unwrap_err();
    assert!(e.to_string().contains("typo.env"), "{e}");
}

// 05.09: a dotenv file others can read is file_too_open, whose Do is the chmod.
#[cfg(unix)]
#[test]
fn an_open_dotenv_file_is_file_too_open() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.env");
    fs::write(&path, "A=1\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(read_legacy(&path).unwrap_err().code_str(), "file_too_open");
}

#[test]
fn a_dotenv_file_that_cannot_be_read_is_input_unreadable() {
    // F4: a missing file is an unreadable input, not one whose content is invalid.
    let dir = tempfile::tempdir().unwrap();
    let e = read_legacy(&dir.path().join("missing.env")).unwrap_err();
    assert_eq!(e.code_str(), "input_unreadable");
}
