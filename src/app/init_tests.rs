//! Tests for `opv init` (FR-23) in the one configuration form (FR-56, FR-57, FR-60). Every
//! fake item value contains [`MARKER`]; no marker may reach the written file, stdout, an
//! error or argv (SR-1, SR-3, SR-4).

use std::path::Path;

use serde_json::json;

use super::*;
use crate::app::testutil::{
    Field, MARKER, assert_no_values, assert_no_values_in_argv, fly_empty, item, ok, secret, text,
    text_of,
};
use crate::app::{config_export, run as run_cmd, status, sync};
use crate::runner::Output;
use crate::runner::fake::{FakeRunner, failed_read};

const VAULT_ID: &str = "vaultid01";
const ITEM_ID: &str = "itemid01";

fn vaults() -> Output {
    let v = json!([
        {"id": VAULT_ID, "name": "myapp-staging"},
        {"id": "othervault", "name": "Private"},
    ]);
    Output::success(serde_json::to_vec(&v).unwrap())
}

fn items() -> Output {
    let v = json!([
        {"id": ITEM_ID, "title": "myapp", "category": "SECURE_NOTE"},
        {"id": "otheritem", "title": "unrelated", "category": "LOGIN"},
    ]);
    Output::success(serde_json::to_vec(&v).unwrap())
}

/// `opv init staging --vault myapp-staging --item myapp`: no product, no target.
fn args() -> InitArgs {
    InitArgs {
        env: "staging".into(),
        vault: "myapp-staging".into(),
        item: "myapp".into(),
        ..Default::default()
    }
}

/// [`args`] with `--product api`.
fn api_args() -> InitArgs {
    InitArgs {
        product: Some("api".into()),
        ..args()
    }
}

fn v(s: &str) -> String {
    format!("{s}-{MARKER}")
}

/// Fields outside any section: the keys of the product `--product` names.
fn unsectioned_fields() -> Vec<Field> {
    vec![
        secret("", "DATABASE_URL", &v("postgres://u:p@h/db")),
        secret("", "JWT_KEY", &v("jwt")),
        text("", "LOG_LEVEL", &v("info")),
    ]
}

/// One section, one product.
fn api_fields() -> Vec<Field> {
    vec![
        secret("api", "OPENAI_API_KEY", &v("sk-proj")),
        text("api", "SIGNUP_POLICY", &v("open")),
    ]
}

/// Two sections, two products sharing the item.
fn two_products() -> Vec<Field> {
    let mut f = api_fields();
    f.push(secret("web-app", "SESSION_KEY", &v("sess")));
    f
}

struct Run {
    res: Result<(), Error>,
    out: String,
    r: FakeRunner,
    file: Option<String>,
}

impl Run {
    fn err(&self) -> &Error {
        self.res.as_ref().unwrap_err()
    }
    fn file(&self) -> &str {
        self.file.as_deref().expect("no file written")
    }
    /// No value anywhere: file, stdout, error text, argv.
    fn assert_value_free(&self) {
        if let Some(f) = &self.file {
            assert_no_values(f);
        }
        assert_no_values(&self.out);
        if let Err(e) = &self.res {
            assert_no_values(&e.to_string());
            assert_no_values(&format!("{e:?}"));
        }
        assert_no_values_in_argv(&self.r);
    }
}

fn run_in(dir: &Path, a: &InitArgs, responses: Vec<Output>) -> Run {
    let r = FakeRunner::new(responses);
    let mut out = Vec::new();
    let res = run(a, dir, &r, &mut out);
    let file = fs::read_to_string(dir.join(FILE_NAME)).ok();
    let run = Run {
        res,
        out: text_of(&out),
        r,
        file,
    };
    run.assert_value_free();
    run
}

fn init_with(fields: &[Field], a: &InitArgs) -> (tempfile::TempDir, Run) {
    let dir = tempfile::tempdir().unwrap();
    let run = run_in(dir.path(), a, vec![vaults(), items(), item(fields)]);
    (dir, run)
}

fn argvs(r: &FakeRunner) -> Vec<String> {
    crate::app::testutil::argvs(r)
}

fn dir_entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// The written configuration, loaded with the normal loader.
fn loaded(dir: &Path) -> Fleet {
    config::load(dir.join(FILE_NAME)).unwrap()
}

/// The written environment's recorded boundary names.
fn boundaries(dir: &Path) -> Vec<String> {
    loaded(dir).environments["staging"]
        .boundaries
        .keys()
        .cloned()
        .collect()
}

// ---- One item, one boundary (FR-57) ----

#[test]
fn a_one_section_item_records_its_products_boundary() {
    let (dir, _run) = init_with(&api_fields(), &args());
    assert_eq!(boundaries(dir.path()), ["api"]);
}

#[test]
fn the_boundary_records_the_items_ids() {
    let (dir, _run) = init_with(&api_fields(), &args());
    let fleet = loaded(dir.path());
    let b = &fleet.environments["staging"].boundaries["api"];
    assert_eq!(
        (b.vault_id.as_str(), b.item_id.as_str()),
        (VAULT_ID, ITEM_ID)
    );
}

#[test]
fn a_several_section_item_records_the_core_boundary() {
    let (dir, _run) = init_with(&two_products(), &args());
    assert_eq!(boundaries(dir.path()), ["core"]);
}

#[test]
fn a_several_section_item_puts_each_product_in_core() {
    let (dir, _run) = init_with(&two_products(), &args());
    let fleet = loaded(dir.path());
    assert_eq!(
        [fleet.boundary_of("api"), fleet.boundary_of("web-app")],
        ["core", "core"]
    );
}

#[test]
fn each_section_is_declared_as_its_product() {
    let (dir, _run) = init_with(&two_products(), &args());
    let products: Vec<String> = loaded(dir.path()).products.keys().cloned().collect();
    assert_eq!(products, ["api", "web-app"]);
}

#[test]
fn unsectioned_fields_become_the_products_keys() {
    let (dir, _run) = init_with(&unsectioned_fields(), &api_args());
    let keys: Vec<String> = loaded(dir.path()).products["api"]
        .keys
        .keys()
        .cloned()
        .collect();
    assert_eq!(keys, ["DATABASE_URL", "JWT_KEY", "LOG_LEVEL"]);
}

#[test]
fn unsectioned_fields_record_the_products_boundary() {
    let (dir, _run) = init_with(&unsectioned_fields(), &api_args());
    assert_eq!(boundaries(dir.path()), ["api"]);
}

#[test]
fn a_concealed_field_is_declared_secret() {
    let (dir, _run) = init_with(&api_fields(), &args());
    assert_eq!(
        loaded(dir.path()).products["api"].keys["OPENAI_API_KEY"].kind,
        Kind::Secret
    );
}

#[test]
fn a_text_field_is_declared_config() {
    let (dir, _run) = init_with(&api_fields(), &args());
    assert_eq!(
        loaded(dir.path()).products["api"].keys["SIGNUP_POLICY"].kind,
        Kind::Config
    );
}

#[test]
fn a_key_is_declared_for_the_environment() {
    let (dir, _run) = init_with(&api_fields(), &args());
    assert_eq!(
        loaded(dir.path()).products["api"].keys["OPENAI_API_KEY"].environments,
        ["staging"]
    );
}

#[test]
fn built_in_fields_are_not_keys() {
    let (_dir, run) = init_with(&api_fields(), &args());
    assert!(!run.file().contains("notesPlain"), "{}", run.file());
}

#[test]
fn unsectioned_fields_without_product_are_refused_naming_the_flag() {
    let (_dir, run) = init_with(&unsectioned_fields(), &args());
    assert!(
        run.err().to_string().contains("pass --product <name>"),
        "{}",
        run.err()
    );
}

#[test]
fn unsectioned_fields_without_product_write_nothing() {
    let (dir, _run) = init_with(&unsectioned_fields(), &args());
    assert!(dir_entries(dir.path()).is_empty());
}

#[test]
fn an_invalid_product_is_refused_before_any_call() {
    let mut a = api_args();
    a.product = Some("My App".into());
    let (_dir, run) = init_with(&unsectioned_fields(), &a);
    assert!(run.r.calls.borrow().is_empty());
}

#[test]
fn a_mixed_item_is_refused_naming_both_shapes() {
    let mut fields = unsectioned_fields();
    fields.extend(two_products());
    let (_dir, run) = init_with(&fields, &api_args());
    assert!(
        run.err()
            .to_string()
            .contains("with 3 unsectioned fields and 3 sectioned fields"),
        "{}",
        run.err()
    );
}

#[test]
fn a_mixed_item_writes_nothing() {
    let mut fields = unsectioned_fields();
    fields.extend(two_products());
    let (dir, _run) = init_with(&fields, &api_args());
    assert!(dir_entries(dir.path()).is_empty());
}

// ---- Output ----

#[test]
fn init_makes_two_lookups_and_one_item_read() {
    let (_dir, run) = init_with(&api_fields(), &args());
    assert_eq!(
        argvs(&run.r),
        vec![
            "op vault list --format json".to_string(),
            format!("op item list --vault {VAULT_ID} --format json"),
            format!("op item get {ITEM_ID} --vault {VAULT_ID} --format json"),
        ]
    );
}

#[test]
fn init_reports_the_vault_and_item_ids() {
    let (_dir, run) = init_with(&api_fields(), &args());
    assert!(
        run.out.contains(&format!(
            "vault \"myapp-staging\" is {VAULT_ID}, item \"myapp\" is {ITEM_ID}"
        )),
        "{}",
        run.out
    );
}

#[test]
fn init_reports_the_product_and_counts() {
    let (dir, run) = init_with(&api_fields(), &args());
    assert!(
        run.out.contains(&format!(
            "wrote {} (product api): 1 secret, 1 config, skipped 0",
            dir.path().join(FILE_NAME).display()
        )),
        "{}",
        run.out
    );
}

#[test]
fn init_reports_the_shared_boundary() {
    let (_dir, run) = init_with(&two_products(), &args());
    assert!(
        run.out
            .contains("(products api, web-app (boundary core)): 2 secret, 1 config"),
        "{}",
        run.out
    );
}

#[test]
fn init_ends_with_next_bootstrap() {
    let (_dir, run) = init_with(&api_fields(), &args());
    assert!(run.out.ends_with("Next: opv bootstrap\n"), "{}", run.out);
}

/// Review #16, #17: found live, a docs pointer on every init that asked nothing of the
/// person.
#[test]
fn init_with_keys_prints_no_docs_pointer() {
    let (_dir, run) = init_with(&two_products(), &args());
    assert!(!run.out.contains("https://"), "{}", run.out);
}

/// An empty item's one useful pointer: how to declare a key in the product.
#[test]
fn init_of_an_empty_item_says_how_to_add_a_key() {
    let (_dir, run) = init_with(&[], &api_args());
    assert!(
        run.out
            .contains("add a key: opv add api/<KEY> --kind secret --env staging"),
        "{}",
        run.out
    );
}

#[test]
fn init_of_an_empty_item_writes_a_configuration_that_loads() {
    let (dir, _run) = init_with(&[], &api_args());
    assert!(config::load(dir.path().join(FILE_NAME)).is_ok());
}

// ---- Lookups and refusals ----

#[test]
fn no_matching_vault_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = args();
    a.vault = "myapp-prod".into();
    let run = run_in(dir.path(), &a, vec![vaults()]);
    assert_eq!(run.err().exit_code(), 2);
}

#[test]
fn no_matching_vault_lists_the_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = args();
    a.vault = "myapp-prod".into();
    let run = run_in(dir.path(), &a, vec![vaults()]);
    assert!(
        run.err().to_string().contains(&format!(
            "\"Private\" (othervault), \"myapp-staging\" ({VAULT_ID})"
        )),
        "{}",
        run.err()
    );
}

#[test]
fn no_matching_vault_reads_nothing_more() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = args();
    a.vault = "myapp-prod".into();
    let run = run_in(dir.path(), &a, vec![vaults()]);
    assert_eq!(argvs(&run.r).len(), 1);
}

/// Found live: when opv may not create a missing vault, the person is told to create it
/// (the bare step re-ran a command that could not succeed).
#[test]
fn a_vault_opv_may_not_create_asks_the_person_to_create_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = args();
    a.vault = "myapp-prod".into();
    let run = run_in(dir.path(), &a, vec![vaults()]);
    assert_eq!(
        run.err().do_text().as_deref(),
        Some(
            "create the vault \"myapp-prod\" in 1Password (opv creates it only for a person \
             signed in with their own account), or give the exact title of one that exists"
        )
    );
}

/// FR-43: in a person's own session, a missing item is created (one `op item create`).
#[test]
fn init_creates_a_missing_item_for_a_person() {
    let dir = tempfile::tempdir().unwrap();
    let op = crate::adapters::fake_op::FakeOp::default();
    let _person = crate::app::tidy::activate();
    let a = InitArgs {
        vault: "myapp-dev".into(),
        ..api_args()
    };
    let _ = run(&a, dir.path(), &op, &mut Vec::new());
    assert_eq!(op.count(&["op", "item", "create"]), 1);
}

#[test]
fn several_matching_items_list_them() {
    let dir = tempfile::tempdir().unwrap();
    let dup = Output::success(
        serde_json::to_vec(&json!([
            {"id": "item_a", "title": "myapp"},
            {"id": "item_b", "title": "myapp"},
        ]))
        .unwrap(),
    );
    let run = run_in(dir.path(), &args(), vec![vaults(), dup]);
    assert!(
        run.err()
            .to_string()
            .contains("\"myapp\" (item_a), \"myapp\" (item_b)"),
        "{}",
        run.err()
    );
}

#[test]
fn an_existing_file_without_force_is_refused_before_any_call() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(FILE_NAME), "# hand-written\n").unwrap();
    let run = run_in(dir.path(), &args(), vec![]);
    assert!(run.r.calls.borrow().is_empty() && run.res.is_err());
}

#[test]
fn an_existing_file_without_force_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(FILE_NAME), "# hand-written\n").unwrap();
    let run = run_in(dir.path(), &args(), vec![]);
    assert_eq!(run.file(), "# hand-written\n");
}

#[test]
fn an_existing_file_refusal_names_add_env() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(FILE_NAME), "# hand-written\n").unwrap();
    let run = run_in(dir.path(), &api_args(), vec![]);
    assert_eq!(
        next_of(run.err(), &["opv", "init", "staging", "--product", "api"]).as_deref(),
        Some("opv init staging --vault myapp-staging --item myapp --product api --add-env")
    );
}

#[test]
fn force_overwrites_and_leaves_no_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(FILE_NAME), "# hand-written\n").unwrap();
    let mut a = args();
    a.force = true;
    let _run = run_in(dir.path(), &a, vec![vaults(), items(), item(&api_fields())]);
    assert_eq!(dir_entries(dir.path()), vec![FILE_NAME.to_string()]);
}

#[test]
fn force_replaces_the_files_text() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(FILE_NAME), "# hand-written\n").unwrap();
    let mut a = args();
    a.force = true;
    let run = run_in(dir.path(), &a, vec![vaults(), items(), item(&api_fields())]);
    assert!(!run.file().contains("hand-written"), "{}", run.file());
}

#[test]
fn a_refused_item_leaves_an_existing_file_untouched_even_with_force() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(FILE_NAME), "# hand-written\n").unwrap();
    let mut a = args();
    a.force = true;
    let run = run_in(
        dir.path(),
        &a,
        vec![vaults(), items(), item(&unsectioned_fields())],
    );
    assert_eq!(run.file(), "# hand-written\n");
}

#[test]
fn op_failure_goes_through_diagnosis() {
    let dir = tempfile::tempdir().unwrap();
    // vault list fails; op whoami fails; account list has one account → not signed in.
    let run = run_in(
        dir.path(),
        &args(),
        failed_read(1)
            .chain([Output::failure(1), Output::success(b"[{}]".to_vec())])
            .collect(),
    );
    assert!(
        run.err().to_string().contains("not signed in to 1Password"),
        "{}",
        run.err()
    );
}

#[test]
fn init_never_writes_to_1password() {
    let (_dir, run) = init_with(&two_products(), &args());
    let writes: Vec<String> = run
        .r
        .calls
        .borrow()
        .iter()
        .filter(|c| {
            c.stdin.is_some() || !matches!(c.args.get(1).map(String::as_str), Some("list" | "get"))
        })
        .map(|c| c.args.join(" "))
        .collect();
    assert!(writes.is_empty(), "{writes:?}");
}

// ---- Skipped fields ----

#[test]
fn invalid_key_names_are_never_declared() {
    let mut fields = unsectioned_fields();
    fields.push(secret("", "db-password", &v("pw")));
    fields.push(text("", "Api_Url", &v("u")));
    let (_dir, run) = init_with(&fields, &api_args());
    let f = run.file();
    assert!(
        ["db-password", "DB_PASSWORD", "Api_Url", "API_URL"]
            .iter()
            .all(|bad| !f.contains(bad)),
        "{f}"
    );
}

#[test]
fn an_invalid_key_name_is_noted_by_name() {
    let mut fields = unsectioned_fields();
    fields.push(secret("", "db-password", &v("pw")));
    let (_dir, run) = init_with(&fields, &api_args());
    assert!(
        run.out
            .contains("note: skipped \"db-password\": not a valid key name (^[A-Z][A-Z0-9_]*$)"),
        "{}",
        run.out
    );
}

#[test]
fn other_field_types_are_noted_as_rejected() {
    let mut fields = api_fields();
    fields.push(("api".into(), "HOMEPAGE".into(), "URL", Some(v("https://x"))));
    let (_dir, run) = init_with(&fields, &args());
    assert!(
        run.out.contains(&format!(
            "note: skipped \"api\"/\"HOMEPAGE\": field type \"URL\" is neither concealed \
             (secret) nor text (config); {REJECT}"
        )),
        "{}",
        run.out
    );
}

#[test]
fn an_unsectioned_field_of_another_type_is_noted() {
    let mut fields = unsectioned_fields();
    fields.push(("".into(), "HOMEPAGE".into(), "URL", Some(v("https://x"))));
    let (_dir, run) = init_with(&fields, &api_args());
    assert!(
        run.out
            .contains("note: skipped \"HOMEPAGE\": field type \"URL\" is neither"),
        "{}",
        run.out
    );
}

#[test]
fn invalid_section_names_are_skipped_by_name() {
    let mut fields = two_products();
    fields.push(secret("My App", "TOKEN", &v("t")));
    let (_dir, run) = init_with(&fields, &args());
    assert!(
        run.out
            .contains("note: skipped section \"My App\" (1 field): not a valid product name"),
        "{}",
        run.out
    );
}

#[test]
fn a_duplicate_field_is_declared_once() {
    // FR-43: a label given twice is read tolerantly, never an error.
    let mut fields = api_fields();
    fields.push(text("api", "SIGNUP_POLICY", &v("closed")));
    let (_dir, run) = init_with(&fields, &args());
    assert_eq!(
        run.file()
            .matches("[products.api.keys.SIGNUP_POLICY]")
            .count(),
        1
    );
}

const REJECT: &str = "status and sync will reject it until it is fixed in 1Password";

/// An `op item get` document from raw field objects (shapes `item_json` cannot build).
fn raw_item(fields: Vec<serde_json::Value>) -> Output {
    Output::success(serde_json::to_vec(&json!({"id": ITEM_ID, "fields": fields})).unwrap())
}

fn sf(section: serde_json::Value, ty: &str, label: &str) -> serde_json::Value {
    json!({"id": label.to_lowercase(), "section": section, "type": ty, "label": label,
           "value": v("x")})
}

fn init_raw(fields: Vec<serde_json::Value>, a: &InitArgs) -> (tempfile::TempDir, Run) {
    let dir = tempfile::tempdir().unwrap();
    let run = run_in(dir.path(), a, vec![vaults(), items(), raw_item(fields)]);
    (dir, run)
}

fn api() -> serde_json::Value {
    json!({"id": "api", "label": "api"})
}

/// A field in 1Password's unlabelled default section is unsectioned: a key of `--product`.
#[test]
fn an_unlabelled_section_field_is_a_key_of_the_product() {
    let fields = vec![sf(json!({"id": "nolabel"}), "STRING", "MODE")];
    let (_dir, run) = init_raw(fields, &api_args());
    assert!(
        run.file().contains("[products.api.keys.MODE]"),
        "{}",
        run.file()
    );
}

#[test]
fn an_empty_label_in_a_section_is_noted_as_rejected() {
    let fields = vec![sf(api(), "CONCEALED", "TOKEN"), sf(api(), "STRING", "")];
    let (_dir, run) = init_raw(fields, &args());
    assert!(
        run.out.contains(&format!(
            "note: skipped \"api\"/\"\": not a valid key name (^[A-Z][A-Z0-9_]*$); rename the \
             field in 1Password to manage it; it has no label; {REJECT}"
        )),
        "{}",
        run.out
    );
}

#[test]
fn a_wrong_type_in_a_skipped_section_is_noted_as_rejected() {
    let bad = json!({"id": "s", "label": "My App"});
    let fields = vec![
        sf(api(), "CONCEALED", "TOKEN"),
        sf(bad.clone(), "URL", "SITE"),
        sf(bad, "CONCEALED", "KEY"),
    ];
    let (_dir, run) = init_raw(fields, &args());
    assert!(
        run.out.contains(&format!(
            "note: skipped \"My App\"/\"SITE\": its section is skipped; field type \"URL\" is \
             neither concealed (secret) nor text (config); {REJECT}"
        )),
        "{}",
        run.out
    );
}

#[test]
fn a_valid_field_in_a_skipped_section_has_no_note_of_its_own() {
    let bad = json!({"id": "s", "label": "My App"});
    let fields = vec![
        sf(api(), "CONCEALED", "TOKEN"),
        sf(bad.clone(), "URL", "SITE"),
        sf(bad, "CONCEALED", "KEY"),
    ];
    let (_dir, run) = init_raw(fields, &args());
    assert!(!run.out.contains("\"My App\"/\"KEY\""), "{}", run.out);
}

/// FR-43: a label given twice is read tolerantly, whatever the field types.
#[test]
fn duplicates_never_fail_init() {
    let fields = vec![sf(api(), "CONCEALED", "TOKEN"), sf(api(), "URL", "TOKEN")];
    let (_dir, run) = init_raw(fields, &args());
    assert!(run.res.is_ok(), "{:?}", run.res);
}

#[test]
fn the_same_label_in_two_sections_declares_both() {
    let fields = vec![
        sf(api(), "CONCEALED", "TOKEN"),
        sf(json!({"id": "web", "label": "web"}), "CONCEALED", "TOKEN"),
    ];
    let (dir, _run) = init_raw(fields, &args());
    let fleet = loaded(dir.path());
    assert!(
        fleet.products["api"].keys.contains_key("TOKEN")
            && fleet.products["web"].keys.contains_key("TOKEN")
    );
}

// ---- Status and other commands ----

/// The written file with the Fly target `opv target add staging web --fly-app
/// myapp-staging` adds: the provider's section and the state vault it records.
fn with_fly_target(dir: &Path) -> Fleet {
    let fly = crate::adapters::registry::find("fly").unwrap();
    let section = fly
        .init_section(&BTreeMap::from([("app", "myapp-staging".to_string())]))
        .unwrap();
    let text = fs::read_to_string(dir.join(FILE_NAME)).unwrap()
        + "\n[environments.staging.targets.web]\nstate_vault_id = \"sstg\"\n"
        + &section;
    config::parse(&text).unwrap()
}

/// Once its target is added, `opv status` finds every key saved against the very item the
/// file was generated from.
#[test]
fn generated_file_passes_status_against_the_same_item() {
    let (dir, _run) = init_with(&two_products(), &args());
    let r = FakeRunner::new([item(&two_products()), fly_empty()]);
    let mut out = Vec::new();
    status::run(&with_fly_target(dir.path()), "staging", &r, &mut out).unwrap();
    assert!(text_of(&out).contains("3 saved"), "{}", text_of(&out));
}

fn is_title_lookup(c: &crate::runner::fake::Call) -> bool {
    c.program == "op"
        && matches!(
            (
                c.args.first().map(String::as_str),
                c.args.get(1).map(String::as_str)
            ),
            (Some("vault" | "item"), Some("list"))
        )
}

/// FR-13, acceptance 20: sync, plan, status, run and config export make no title lookup.
#[test]
fn other_commands_never_look_up_titles() {
    let cfg = crate::app::testutil::fleet();
    let responses = || {
        let mut v = vec![crate::app::testutil::complete_item(), fly_empty()];
        v.extend((0..10).map(|_| ok()));
        v
    };
    type Cmd<'a> = Box<dyn Fn(&FakeRunner) + 'a>;
    let cmds: Vec<(&str, Cmd)> = vec![
        (
            "status",
            Box::new(|r| {
                let _ = status::run(&cfg, "prod", r, &mut Vec::new());
            }),
        ),
        (
            "fly plan",
            Box::new(|r| {
                let _ = sync::plan_with(&cfg, "prod", r, &mut Vec::new(), true);
            }),
        ),
        (
            "fly sync",
            Box::new(|r| {
                let opts = sync::SyncOpts {
                    deploy: true,
                    prune: true,
                    ..Default::default()
                };
                let _ = sync::run(&cfg, "prod", r, &mut Vec::new(), &opts);
            }),
        ),
        (
            "config export",
            Box::new(|r| {
                let _ = config_export::run(&cfg, "prod", r, &mut Vec::new());
            }),
        ),
        (
            "run",
            Box::new(|r| {
                let _ = run_cmd::run_for(&cfg, "prod", Some("allumata"), None, &["true".into()], r);
            }),
        ),
    ];
    let lookups: Vec<String> = cmds
        .iter()
        .flat_map(|(name, cmd)| {
            let r = FakeRunner::new(responses());
            cmd(&r);
            let calls = r.calls.borrow();
            calls
                .iter()
                .filter(|c| is_title_lookup(c))
                .map(|c| format!("{name}: {}", c.args.join(" ")))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(lookups.is_empty(), "{lookups:?}");
}

// ---- Ancestor note ----

#[test]
fn an_ancestor_secrets_toml_is_noted_never_refused() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join(FILE_NAME), "# parent\n").unwrap();
    let nested = root.path().join("svc").join("api");
    fs::create_dir_all(&nested).unwrap();
    let run = run_in(
        &nested,
        &args(),
        vec![vaults(), items(), item(&api_fields())],
    );
    let want = format!(
        "note: {} also exists; the new secrets.toml takes precedence for commands run from {} \
         and below",
        root.path().join(FILE_NAME).display(),
        nested.display()
    );
    assert!(run.out.contains(&want), "{}", run.out);
}

#[test]
fn no_ancestor_note_without_an_ancestor_file() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("x");
    fs::create_dir_all(&nested).unwrap();
    // Only meaningful when nothing above the temp dir holds a secrets.toml.
    if config::discover(dir.path()).is_none() {
        assert_eq!(ancestor_note(&nested), None);
    }
}

// ---- Targets: init writes none (FR-56, FR-60) ----

#[test]
fn init_writes_no_target() {
    let (_dir, run) = init_with(&api_fields(), &args());
    assert!(!run.file().contains(".targets."), "{}", run.file());
}

#[test]
fn init_names_target_add_for_a_deploy_target() {
    let (_dir, run) = init_with(&api_fields(), &args());
    assert!(
        run.out
            .contains("add a deploy target: opv target add staging <name>"),
        "{}",
        run.out
    );
}

#[test]
fn a_bad_environment_name_is_refused_before_any_call() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = args();
    a.env = "a.b".into();
    let run = run_in(dir.path(), &a, vec![]);
    assert!(run.r.calls.borrow().is_empty() && run.res.is_err());
}

// ---- H2: `init <env> --add-env` adds one environment in the one form ----

const EXISTING: &str = "# Fleet config; values live in 1Password.\n\
[environments.prod]   # live\nboundaries.api = { vault_id = \"vprd\", item_id = \"iprd\" }\n\n\
# api\n[products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\n\
[products.api.keys.LEGACY_TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]  # going away\n";

struct AddEnv {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    res: Result<(), Error>,
    out: String,
    r: FakeRunner,
}

impl AddEnv {
    fn text(&self) -> String {
        fs::read_to_string(&self.path).unwrap()
    }
    fn fleet(&self) -> Fleet {
        config::parse(&self.text()).unwrap()
    }
    fn boundaries(&self) -> Vec<String> {
        self.fleet().environments["staging"]
            .boundaries
            .keys()
            .cloned()
            .collect()
    }
}

fn add_env_with(file: &str, a: &InitArgs, fields: &[Field]) -> AddEnv {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(FILE_NAME);
    fs::write(&path, file).unwrap();
    let r = FakeRunner::new(vec![vaults(), items(), item(fields)]);
    let mut out = Vec::new();
    let store = crate::config_store::FileStore { path: path.clone() };
    let res = add_env(a, &store, &r, &mut out);
    let run = AddEnv {
        _dir: dir,
        path,
        res,
        out: text_of(&out),
        r,
    };
    assert_no_values(&run.text());
    assert_no_values(&run.out);
    assert_no_values_in_argv(&run.r);
    run
}

#[test]
fn add_env_keeps_every_comment() {
    let run = add_env_with(EXISTING, &args(), &two_products());
    let text = run.text();
    let comments: Vec<&str> = EXISTING.lines().filter(|l| l.contains('#')).collect();
    assert!(comments.iter().all(|c| text.contains(c)), "{text}");
}

#[test]
fn add_env_records_the_products_boundary() {
    let run = add_env_with(EXISTING, &args(), &two_products());
    assert_eq!(run.boundaries(), ["api"]);
}

#[test]
fn add_env_records_the_items_ids() {
    let run = add_env_with(EXISTING, &args(), &two_products());
    let fleet = run.fleet();
    let b = &fleet.environments["staging"].boundaries["api"];
    assert_eq!(
        (b.vault_id.as_str(), b.item_id.as_str()),
        (VAULT_ID, ITEM_ID)
    );
}

#[test]
fn add_env_includes_the_keys_the_item_has() {
    let run = add_env_with(EXISTING, &args(), &two_products());
    assert_eq!(
        run.fleet().products["api"].keys["OPENAI_API_KEY"].environments,
        vec!["prod", "staging"]
    );
}

#[test]
fn add_env_leaves_out_the_keys_the_item_lacks() {
    let run = add_env_with(EXISTING, &args(), &two_products());
    assert_eq!(
        run.fleet().products["api"].keys["LEGACY_TOKEN"].environments,
        vec!["prod"]
    );
}

// ---- FR-55: an item holding only personal keys is no environment boundary ----

/// A team key (`api`, which needs the `api` boundary) and a personal key (`mine`): the item
/// below holds only the personal one, so it is not the environment's shared item.
const PERSONAL_KEY: &str = "[environments.prod]\n\
boundaries.api = { vault_id = \"vprd\", item_id = \"iprd\" }\n\n\
[products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\n\
[products.mine.keys.MY_TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\npersonal = true\n";

fn personal_item_fields() -> Vec<Field> {
    vec![secret("mine", "MY_TOKEN", &v("tok"))]
}

#[test]
fn add_env_refuses_an_item_holding_only_personal_keys() {
    let run = add_env_with(PERSONAL_KEY, &args(), &personal_item_fields());
    assert!(matches!(
        run.res.as_ref().unwrap_err().cause(),
        Some((
            crate::cause::Cause::ConfigProposalInvalid {
                rule: crate::cause::FieldRule::Check {
                    check: crate::cause::ConfigCheck::PersonalItemBoundary { .. }
                },
                ..
            },
            _
        ))
    ));
}

#[test]
fn add_env_with_only_personal_keys_leaves_the_configuration_unchanged() {
    let run = add_env_with(PERSONAL_KEY, &args(), &personal_item_fields());
    assert_eq!(run.text(), PERSONAL_KEY);
}

#[test]
fn add_env_names_the_item_fields_not_declared() {
    let run = add_env_with(EXISTING, &args(), &two_products());
    assert!(
        run.out
            .contains("in the item but not declared: api/SIGNUP_POLICY, web-app/SESSION_KEY"),
        "{}",
        run.out
    );
}

#[test]
fn add_env_gives_unsectioned_fields_to_the_product() {
    let mut fields = unsectioned_fields();
    fields.push(secret("", "OPENAI_API_KEY", &v("sk")));
    let run = add_env_with(EXISTING, &api_args(), &fields);
    assert_eq!(
        run.fleet().products["api"].keys["OPENAI_API_KEY"].environments,
        vec!["prod", "staging"]
    );
}

#[test]
fn add_env_refuses_an_existing_environment_before_any_call() {
    let mut a = args();
    a.env = "prod".into();
    let run = add_env_with(EXISTING, &a, &two_products());
    assert!(run.r.calls.borrow().is_empty() && run.res.is_err());
}

#[test]
fn add_env_points_at_check() {
    let run = add_env_with(EXISTING, &args(), &two_products());
    assert!(
        run.out.ends_with("Next: opv check staging --product api\n"),
        "{}",
        run.out
    );
}

// ---- init --add-env on a manifest (FR-44): the same edit through ConfigStore ----

/// Manifest calls (`item get <manifest>`, `item edit`) and the identity probe (`whoami`) go
/// to the stateful fake; the item lookups `init` makes go to the scripted one.
struct Split<'a> {
    op: &'a crate::adapters::fake_op::FakeOp,
    rest: &'a FakeRunner,
    manifest: String,
}

impl Split<'_> {
    fn to_op(&self, call: &crate::runner::Call) -> bool {
        call.args.contains(&self.manifest.as_str())
            || call.args.starts_with(&["item", "edit"])
            || call.args.starts_with(&["whoami"])
    }
}

impl CommandRunner for Split<'_> {
    fn read(
        &self,
        call: &crate::runner::Call,
        refused: &[i32],
    ) -> std::io::Result<crate::runner::Outcome> {
        if self.to_op(call) {
            self.op.read(call, refused)
        } else {
            self.rest.read(call, refused)
        }
    }
    fn write(&self, call: &crate::runner::Call) -> std::io::Result<crate::runner::Outcome> {
        if self.to_op(call) {
            self.op.write(call)
        } else {
            self.rest.write(call)
        }
    }
    fn probe(
        &self,
        call: &crate::runner::Call,
        limit: std::time::Duration,
    ) -> std::io::Result<Output> {
        if self.to_op(call) {
            self.op.probe(call, limit)
        } else {
            self.rest.probe(call, limit)
        }
    }
    fn pause(&self, _: std::time::Duration, _: &str) {}
    fn note(&self, _: &str) {}
    fn run_inherited(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> std::io::Result<i32> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

/// `init --add-env` against a manifest holding `body`; returns the manifest's text after.
fn add_env_to_manifest(body: &str, a: &InitArgs) -> (Result<(), Error>, String) {
    use crate::adapters::onepassword_manifest::{Row, VaultRef, template};
    use crate::config_store::{Found, ManifestStore, Matched, manifest_title};
    let op = crate::adapters::fake_op::FakeOp::default();
    let id = op.insert(
        "myapp-dev",
        template(&manifest_title("myapp"), "myapp", &[], body),
    );
    let row = Row {
        id: id.clone(),
        title: manifest_title("myapp"),
        tags: Vec::new(),
        version: 1,
        vault: VaultRef {
            id: "vdev0000000000000000000001".into(),
            name: "myapp-dev".into(),
        },
    };
    let found = Found::Manifest(ManifestStore::from_row(&row, None, Matched::Given));
    let rest = FakeRunner::new(vec![vaults(), items(), item(&two_products())]);
    let r = Split {
        op: &op,
        rest: &rest,
        manifest: id,
    };
    let mut out = Vec::new();
    let res = add_env(a, found.store(), &r, &mut out);
    let text = found.store().read(&op).unwrap().text;
    assert_no_values(&text);
    assert_no_values(&text_of(&out));
    (res, text)
}

#[test]
fn add_env_on_a_manifest_saves_the_environment_in_it() {
    let (_res, text) = add_env_to_manifest(EXISTING, &args());
    assert!(
        config::parse(&text).is_ok_and(|f| f.environments.contains_key("staging")),
        "{text}"
    );
}

#[test]
fn add_env_on_a_manifest_keeps_its_comments() {
    let (_res, text) = add_env_to_manifest(EXISTING, &args());
    assert!(text.contains("# going away"), "{text}");
}

#[test]
fn add_env_on_a_manifest_refuses_an_existing_environment_naming_config_edit() {
    let mut a = args();
    a.env = "prod".into();
    let (res, _) = add_env_to_manifest(EXISTING, &a);
    assert_eq!(
        next_of(&res.unwrap_err(), &["opv", "init", "prod", "--add-env"]).as_deref(),
        Some("opv config edit")
    );
}

// ---- A5: `init --json` ----

fn init_json(fields: &[Field], a: &InitArgs) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let r = FakeRunner::new(vec![vaults(), items(), item(fields)]);
    let mut out = Vec::new();
    let res = run_as(a, dir.path(), &r, &mut out, true);
    let framed = crate::app::json_tests::framed(&out, &res, "opv init staging --json");
    // The temp directory differs per run and per platform.
    let framed = crate::app::json_tests::without_dir(&framed, dir.path());
    (dir, framed)
}

#[test]
fn init_json_success_golden() {
    let (_dir, out) = init_json(&two_products(), &args());
    crate::app::json_tests::golden("init_success", &out);
}

#[test]
fn init_json_refusal_golden() {
    let mut a = args();
    a.vault = "no-such-vault".into();
    let (_dir, out) = init_json(&two_products(), &a);
    crate::app::json_tests::golden("init_unknown_vault", &out);
}

// ---- M6: `--add-env` and shared keys (FR-45) ----

const SHARED: &str = "[environments.prod]\n\
boundaries.core = { vault_id = \"vprd\", item_id = \"iprd\" }\n\n\
[products.api]\nboundary = \"core\"\n\n\
[products.worker]\nboundary = \"core\"\n\n\
[products.api.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\n\
[products.api.keys.LEGACY_TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\n\n\
[products.worker.keys.OPENAI_API_KEY]\nkind = \"secret\"\nenvironments = [\"prod\"]\nfrom = \"api/OPENAI_API_KEY\"\n\n\
[products.worker.keys.LEGACY_TOKEN]\nkind = \"secret\"\nenvironments = [\"prod\"]\nfrom = \"api/LEGACY_TOKEN\"\n";

#[test]
fn add_env_adds_a_shared_key_with_its_source() {
    let run = add_env_with(SHARED, &args(), &two_products());
    assert_eq!(
        run.fleet().products["worker"].keys["OPENAI_API_KEY"].environments,
        vec!["prod", "staging"]
    );
}

#[test]
fn add_env_records_the_shared_boundary() {
    let run = add_env_with(SHARED, &args(), &two_products());
    assert_eq!(run.boundaries(), ["core"]);
}

#[test]
fn add_env_leaves_out_a_shared_key_whose_source_is_absent() {
    let run = add_env_with(SHARED, &args(), &two_products());
    assert_eq!(
        run.fleet().products["worker"].keys["LEGACY_TOKEN"].environments,
        vec!["prod"]
    );
}

#[test]
fn add_env_saves_despite_a_stray_field_for_a_shared_key() {
    let mut fields = two_products();
    fields.push(secret("worker", "LEGACY_TOKEN", &v("stray")));
    let run = add_env_with(SHARED, &args(), &fields);
    assert!(run.res.is_ok(), "{:?}", run.res);
}

#[test]
fn add_env_refuses_products_in_different_boundaries() {
    let separate = SHARED
        .replace("[products.api]\nboundary = \"core\"\n\n", "")
        .replace("[products.worker]\nboundary = \"core\"\n\n", "")
        .replace(
            "boundaries.core = { vault_id = \"vprd\", item_id = \"iprd\" }",
            "boundaries.api = { vault_id = \"vprd\", item_id = \"iprd\" }\n\
             boundaries.worker = { vault_id = \"vwrk\", item_id = \"iwrk\" }",
        );
    let run = add_env_with(&separate, &args(), &two_products());
    assert!(
        run.res
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("products.api.boundary must be \"core\""),
        "{:?}",
        run.res
    );
}

/// Found live: `demo-app` beside `opv · demo-app` gave no hint which note held the values.
#[test]
fn the_default_item_reads_apart_from_the_manifest() {
    assert_eq!(default_item("demo-app", "dev"), "demo-app · dev values");
}

#[test]
fn the_default_vault_is_the_project_and_environment() {
    assert_eq!(default_vault("demo-app", "dev"), "demo-app-dev");
}

// ---- catalog steps (05.01, 05.07) ----

/// The Next a catalog error renders for the command line `argv`.
fn next_of(e: &Error, argv: &[&str]) -> Option<String> {
    let inv =
        crate::cause::Invocation::from_cli(&argv.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    let (cause, _) = e.cause()?;
    crate::cause::render::next_text(&cause.step(&inv).1, &inv)
}

/// What `init` prepared for the API item, as `run_manifest` has it before it reports.
fn prepared_api() -> Prepared {
    let r = FakeRunner::new(vec![vaults(), items(), item(&api_fields())]);
    prepare(&args(), None, &r, &crate::host::Host::detect).unwrap()
}

// 05.01: a manifest project never gets `opv bootstrap`, which reads a secrets.toml only.
#[test]
fn a_manifest_init_never_steps_to_bootstrap() {
    let next = next_after(
        &args(),
        &prepared_api(),
        &Place::Manifest("opv · myapp".into()),
    );
    assert_ne!(next.command, ["bootstrap"]);
}

// 05.01: the manifest's step checks the one product init declared.
#[test]
fn a_manifest_init_steps_to_the_check_of_its_product() {
    let next = next_after(
        &args(),
        &prepared_api(),
        &Place::Manifest("opv · myapp".into()),
    );
    assert_eq!(
        crate::cause::render::cmd_text(&next),
        "opv check staging --product api"
    );
}

#[test]
fn a_file_init_steps_to_bootstrap() {
    let next = next_after(
        &args(),
        &prepared_api(),
        &Place::File("secrets.toml".into()),
    );
    assert_eq!(next.command, ["bootstrap"]);
}

// 05.07: the --product advice keeps the vault and item init read, so following it reaches
// the same item (X1).
#[test]
fn the_product_advice_keeps_the_vault_and_item() {
    let (_dir, run) = init_with(&unsectioned_fields(), &args());
    assert!(
        run.err()
            .to_string()
            .contains("together with --vault myapp-staging --item myapp"),
        "{}",
        run.err()
    );
}

// 05.07: the step is init's help, never a rebuilt `init --product` that moves the titles.
#[test]
fn the_product_advice_steps_to_init_help() {
    let (_dir, run) = init_with(&unsectioned_fields(), &args());
    assert_eq!(
        next_of(run.err(), &["opv", "init", "staging"]).as_deref(),
        Some("opv init --help")
    );
}

/// R2-4: a field the file does not hold came from opv's proposal.
#[test]
fn an_invalid_field_missing_from_the_file_is_marked_as_from_the_proposal() {
    let e = would_write(Some("[environments.dev]\n"))(
        config::parse("[environments.dev]\nbogus = 1\n").unwrap_err(),
    );
    assert!(matches!(
        e.cause(),
        Some((
            crate::cause::Cause::ConfigProposalInvalid {
                from_proposal: true,
                ..
            },
            _
        ))
    ));
}

/// R2-4: a field the file already holds is the file's own.
#[test]
fn an_invalid_field_already_in_the_file_is_not_from_the_proposal() {
    let file = "[environments.dev]\nbogus = 1\n";
    let e = would_write(Some(file))(config::parse(file).unwrap_err());
    assert!(matches!(
        e.cause(),
        Some((
            crate::cause::Cause::ConfigProposalInvalid {
                from_proposal: false,
                ..
            },
            _
        ))
    ));
}

#[test]
fn an_invalid_proposed_configuration_says_nothing_was_written() {
    // F2: text opv generated that fails validation is `ConfigProposalInvalid`.
    let e = would_write(None)(config::parse("[environments.dev]\nbogus = 1\n").unwrap_err());
    assert!(e.to_string().contains("nothing was written"), "{e}");
}
