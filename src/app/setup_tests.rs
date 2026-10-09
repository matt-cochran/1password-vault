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
    fs::write(&path, "title='Local example'\nenvironment='dev'\nvault='Development'\nitem='api'\n[[fields]]\nkey='API_KEY'\ntitle='Provider login'\ndescription='Lets this API call its provider.'\nsource='Your provider dashboard.'\n").unwrap();
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
    replies.extend([ok(r#"[{"id":"item-id","title":"api"}]"#),ok(r#"{"category":"SECURE_NOTE","sections":[],"fields":[{"id":"key","label":"API_KEY","type":"CONCEALED","value":"synthetic-existing"}]}"#)]);
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

#[test]
fn wrong_kind_has_specific_repair_and_preserves_existing_item() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(dir.path());
    let mut replies = metadata();
    replies.extend([ok(r#"[{"id":"item-id","title":"api"}]"#),ok(r#"{"category":"SECURE_NOTE","fields":[{"label":"API_KEY","type":"STRING","value":"synthetic-private"}]}"#)]);
    let mut backend = Fake::new(replies);
    let mut ui = Ui::new(vec![], &[]);
    let error = run(&path, None, None, None, &mut backend, &mut ui).unwrap_err();
    assert!(error.to_string().contains("Password / concealed"));
    assert!(!error.to_string().contains("synthetic-private"));
    assert_eq!(backend.calls.borrow().len(), 4);
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
    assert!(error.to_string().contains("Rename the duplicate"));
    assert_eq!(backend.calls.borrow().len(), 2);
}

#[test]
fn shared_keys_have_unique_ids_and_keep_product_sections() {
    let recipe = Recipe::parse("title='Products'\nenvironment='dev'\nvault='Development'\nitem='api'\n[[fields]]\nkey='API_KEY'\nproduct='one'\ntitle='One login'\ndescription='For one.'\nsource='Dashboard.'\n[[fields]]\nkey='API_KEY'\nproduct='two'\ntitle='Two login'\ndescription='For two.'\nsource='Dashboard.'\n").unwrap();
    let mut doc = json!({"category":"SECURE_NOTE","fields":[],"sections":[]});
    let indices = field_indices(&mut doc, &recipe.fields).unwrap();
    assert_ne!(
        doc["fields"][indices[0]]["id"],
        doc["fields"][indices[1]]["id"]
    );
    assert_eq!(doc["fields"][indices[1]]["section"]["label"], "two");
    assert_eq!(field_indices(&mut doc, &recipe.fields).unwrap(), indices);
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
            json!({"title": "api", "category": "SECURE_NOTE", "sections": [], "fields": [
                {"id": "key", "label": "API_KEY", "type": "CONCEALED", "value": ""},
                {"id": "note", "label": "NOTE", "type": "STRING", "value": "first"},
            ]}),
        );
        (op, id)
    }

    fn recipe_in(dir: &Path) -> PathBuf {
        let path = dir.join("opv.setup.toml");
        fs::write(&path, "title='Local example'\nenvironment='dev'\nvault='myapp-dev'\nitem='api'\n[[fields]]\nkey='API_KEY'\ntitle='Provider login'\ndescription='Lets this API call its provider.'\nsource='Your provider dashboard.'\n").unwrap();
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
            (e.code(), op.count(&["op", "item", "edit"])),
            (crate::error::Code::ItemChanged, 0)
        );
    }

    #[test]
    fn an_edit_landing_with_setups_is_item_changed() {
        let (op, _) = op_with_item();
        op.racing_edit.set(Some(1));
        let mut ui = racing(vec![true], &["synthetic-typed"]);
        let e = setup(&op, &mut ui, false).unwrap_err();
        assert_eq!(e.code(), crate::error::Code::ItemChanged);
    }

    #[test]
    fn a_write_that_lost_a_value_is_item_changed() {
        let (op, _) = op_with_item();
        let mut ui = racing(vec![true], &["synthetic-typed"]);
        let e = setup(&op, &mut ui, true).unwrap_err();
        assert_eq!(e.code(), crate::error::Code::ItemChanged);
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
