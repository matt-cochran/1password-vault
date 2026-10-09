//! The convention planner (FR-43): tolerant resolution and the tidy plan. Pure.

use super::*;
use crate::config;

const DATE: &str = "2026-10-08";
const MARK: &str = "CONVMARKER";

fn fleet() -> Fleet {
    config::parse(
        r#"
[profile]
kind = "fleet"

[environments.dev]
vault_id = "vdev"
item_id = "idev"

[products.api.keys.OPENAI_API_KEY]
kind = "secret"
environments = ["dev"]
rules = { prefix = "sk-" }

[products.api.keys.LOG_LEVEL]
kind = "config"
environments = ["dev"]

[products.api.keys.STRIPE_KEY]
kind = "secret"
environments = ["dev"]
rules = { ensure_prefix = "sk_" }

[products.web.keys.SESSION_KEY]
kind = "secret"
environments = ["dev"]
"#,
    )
    .unwrap()
}

fn simple() -> Fleet {
    config::parse(
        "[profile]\nkind = \"simple\"\n[environments.dev]\nvault_id = \"vdev\"\nitem_id = \"idev\"\n\
         [keys.DB_URL]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
    )
    .unwrap()
}

/// (section label or "" for top level, label, type, value).
type F<'a> = (&'a str, &'a str, &'a str, &'a str);

fn layout(fields: &[F<'_>]) -> Layout {
    let mut l = Layout::default();
    for (i, (s, label, ty, v)) in fields.iter().enumerate() {
        let section = (!s.is_empty()).then(|| Section {
            id: format!("sec_{s}"),
            label: (*s).to_string(),
        });
        if let Some(sec) = &section
            && !l.sections.contains(sec)
        {
            l.sections.push(sec.clone());
        }
        l.fields.push(Found {
            id: format!("f{i}"),
            section,
            ty: (*ty).to_string(),
            label: (*label).to_string(),
            builtin: false,
            value: SecretValue::new((*v).to_string()),
        });
    }
    l
}

/// Every declared key of [`fleet`], laid out by the convention and rule-valid.
fn tidy_fields() -> Vec<F<'static>> {
    vec![
        ("api", "OPENAI_API_KEY", "CONCEALED", "sk-CONVMARKER"),
        ("api", "LOG_LEVEL", "STRING", "info"),
        ("api", "STRIPE_KEY", "CONCEALED", "sk_CONVMARKER"),
        ("web", "SESSION_KEY", "CONCEALED", "s-CONVMARKER"),
        ("opv", "convention", "STRING", "1"),
    ]
}

fn with(extra: &[F<'static>], without: &str) -> Layout {
    let mut fs: Vec<F<'static>> = tidy_fields()
        .into_iter()
        .filter(|f| f.1 != without)
        .collect();
    fs.extend_from_slice(extra);
    layout(&fs)
}

fn plan_of(l: &Layout) -> TidyPlan {
    plan(l, &fleet(), "dev", DATE)
}

fn chosen(l: &Layout, product: &str, key: &str) -> Option<usize> {
    resolve(l, &fleet())
        .chosen
        .get(&(product.to_string(), key.to_string()))
        .copied()
}

#[test]
fn norm_ignores_case_spaces_dashes_and_underscores() {
    assert_eq!(norm("Openai-API key"), norm("OPENAI_API_KEY"));
}

#[test]
fn a_label_spelled_differently_is_found() {
    let l = with(
        &[("api", "openai api-key", "CONCEALED", "sk-x")],
        "OPENAI_API_KEY",
    );
    assert_eq!(chosen(&l, "api", "OPENAI_API_KEY"), Some(4));
}

#[test]
fn a_top_level_field_is_found() {
    let l = with(
        &[("", "OPENAI_API_KEY", "CONCEALED", "sk-x")],
        "OPENAI_API_KEY",
    );
    assert_eq!(chosen(&l, "api", "OPENAI_API_KEY"), Some(4));
}

#[test]
fn a_human_named_section_is_searched() {
    let l = with(
        &[("My Secrets", "OPENAI_API_KEY", "CONCEALED", "sk-x")],
        "OPENAI_API_KEY",
    );
    assert_eq!(chosen(&l, "api", "OPENAI_API_KEY"), Some(4));
}

#[test]
fn a_product_shaped_section_is_never_raided() {
    let l = with(
        &[("billing", "OPENAI_API_KEY", "CONCEALED", "sk-x")],
        "OPENAI_API_KEY",
    );
    assert_eq!(chosen(&l, "api", "OPENAI_API_KEY"), None);
}

#[test]
fn a_field_two_products_could_claim_is_left_alone() {
    let f = config::parse(
        "[profile]\nkind = \"fleet\"\n[environments.dev]\nvault_id = \"v\"\nitem_id = \"i\"\n\
         [products.a.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"dev\"]\n\
         [products.b.keys.TOKEN]\nkind = \"secret\"\nenvironments = [\"dev\"]\n",
    )
    .unwrap();
    let l = layout(&[("", "TOKEN", "CONCEALED", "x")]);
    assert!(resolve(&l, &f).chosen.is_empty());
}

#[test]
fn a_filled_field_wins_over_an_empty_one_at_home() {
    let l = with(
        &[
            ("api", "OPENAI_API_KEY", "CONCEALED", ""),
            ("", "OPENAI_API_KEY", "CONCEALED", "sk-x"),
        ],
        "OPENAI_API_KEY",
    );
    assert_eq!(chosen(&l, "api", "OPENAI_API_KEY"), Some(5));
}

#[test]
fn among_filled_fields_the_one_at_home_wins() {
    let l = with(
        &[
            ("api", "OPENAI_API_KEY", "CONCEALED", "sk-a"),
            ("", "OPENAI_API_KEY", "CONCEALED", "sk-b"),
        ],
        "OPENAI_API_KEY",
    );
    assert_eq!(chosen(&l, "api", "OPENAI_API_KEY"), Some(4));
}

#[test]
fn among_equal_fields_the_later_one_wins() {
    let l = with(
        &[
            ("api", "OPENAI_API_KEY", "CONCEALED", "sk-a"),
            ("api", "openai_api_key", "CONCEALED", "sk-b"),
        ],
        "OPENAI_API_KEY",
    );
    assert_eq!(chosen(&l, "api", "OPENAI_API_KEY"), Some(5));
}

#[test]
fn a_conventional_item_needs_no_tidy() {
    assert!(plan_of(&layout(&tidy_fields())).is_empty());
}

#[test]
fn a_missing_field_is_created_empty() {
    let l = with(&[], "LOG_LEVEL");
    assert_eq!(
        plan_of(&l).changes,
        vec![Change::CreatedField("api/LOG_LEVEL".into())]
    );
}

#[test]
fn a_missing_section_is_created() {
    let l = layout(&[("opv", "convention", "STRING", "1")]);
    assert!(
        plan_of(&l)
            .changes
            .contains(&Change::CreatedSection("api".into()))
    );
}

#[test]
fn a_secret_stored_as_text_is_concealed() {
    let l = with(
        &[("api", "OPENAI_API_KEY", "STRING", "sk-x")],
        "OPENAI_API_KEY",
    );
    assert_eq!(
        plan_of(&l).changes,
        vec![Change::MadeConcealed("api/OPENAI_API_KEY".into())]
    );
}

#[test]
fn config_stored_as_concealed_is_accepted_unchanged() {
    let l = with(&[("api", "LOG_LEVEL", "CONCEALED", "info")], "LOG_LEVEL");
    assert!(plan_of(&l).is_empty());
}

#[test]
fn a_label_is_renamed_to_the_key() {
    let l = with(&[("api", "log level", "STRING", "info")], "LOG_LEVEL");
    assert!(plan_of(&l).changes.contains(&Change::Renamed {
        field: "api/LOG_LEVEL".into(),
        from: "log level".into(),
    }));
}

#[test]
fn a_renamed_label_leaves_a_breadcrumb_in_kept() {
    let l = with(&[("api", "log level", "STRING", "info")], "LOG_LEVEL");
    let p = plan_of(&l);
    assert!(p.ops.iter().any(|op| matches!(op,
        Op::Add { section: Some(s), label, .. }
            if s == KEPT_SECTION && label == "log level (renamed to api/LOG_LEVEL, 2026-10-08)")));
}

#[test]
fn a_field_in_the_wrong_section_is_moved_home() {
    let l = with(&[("Secrets", "LOG_LEVEL", "STRING", "info")], "LOG_LEVEL");
    assert_eq!(
        plan_of(&l).changes,
        vec![Change::Moved {
            field: "api/LOG_LEVEL".into(),
            from: "Secrets".into()
        }]
    );
}

#[test]
fn a_differently_spelled_product_section_is_relabelled() {
    let l = layout(&[
        ("API", "OPENAI_API_KEY", "CONCEALED", "sk-x"),
        ("API", "LOG_LEVEL", "STRING", "info"),
        ("API", "STRIPE_KEY", "CONCEALED", "sk_x"),
        ("web", "SESSION_KEY", "CONCEALED", "s"),
        ("opv", "convention", "STRING", "1"),
    ]);
    assert_eq!(
        plan_of(&l).changes,
        vec![Change::RenamedSection {
            from: "API".into(),
            to: "api".into()
        }]
    );
}

#[test]
fn a_duplicate_goes_to_kept_with_its_origin_and_date() {
    let l = with(&[("", "LOG_LEVEL", "STRING", "debug")], "");
    let p = plan_of(&l);
    assert!(p.ops.iter().any(|op| matches!(op,
        Op::Place { index: 5, section: Some(s), label, .. }
            if s == KEPT_SECTION && label == "LOG_LEVEL (from top level, 2026-10-08)")));
}

#[test]
fn a_duplicate_of_a_secret_is_kept_concealed() {
    let l = with(&[("", "OPENAI_API_KEY", "STRING", "sk-old")], "");
    let p = plan_of(&l);
    assert!(p.ops.iter().any(|op| matches!(
        op,
        Op::Place {
            index: 5,
            conceal: true,
            ..
        }
    )));
}

#[test]
fn a_trailing_newline_is_removed_when_the_rules_reject_it() {
    let l = with(
        &[("api", "OPENAI_API_KEY", "CONCEALED", "sk-x\n")],
        "OPENAI_API_KEY",
    );
    assert!(plan_of(&l).changes.contains(&Change::Normalized {
        field: "api/OPENAI_API_KEY".into(),
        fix: Fix::Trimmed
    }));
}

#[test]
fn a_normalized_original_is_kept_concealed() {
    let l = with(
        &[("api", "OPENAI_API_KEY", "CONCEALED", "sk-x\n")],
        "OPENAI_API_KEY",
    );
    let p = plan_of(&l);
    assert!(p.ops.iter().any(|op| matches!(op,
        Op::Add { section: Some(s), concealed: true, value: Some(v), .. }
            if s == KEPT_SECTION && v.expose() == "sk-x\n")));
}

#[test]
fn a_missing_ensure_prefix_is_added() {
    let l = with(&[("api", "STRIPE_KEY", "CONCEALED", "abc")], "STRIPE_KEY");
    assert!(plan_of(&l).changes.contains(&Change::Normalized {
        field: "api/STRIPE_KEY".into(),
        fix: Fix::Prefixed
    }));
}

#[test]
fn a_value_the_trim_cannot_fix_is_left_as_is() {
    let l = with(
        &[("api", "OPENAI_API_KEY", "CONCEALED", "x\n")],
        "OPENAI_API_KEY",
    );
    assert!(plan_of(&l).is_empty());
}

#[test]
fn the_marker_is_added_with_other_changes() {
    let l = layout(&[]);
    assert!(plan_of(&l).ops.iter().any(|op| matches!(op,
        Op::Add { section: Some(s), label, .. } if s == MARKER_SECTION && label == MARKER_FIELD)));
}

#[test]
fn the_marker_alone_is_never_a_reason_to_write() {
    let fs: Vec<F<'static>> = tidy_fields().into_iter().filter(|f| f.0 != "opv").collect();
    assert!(plan_of(&layout(&fs)).is_empty());
}

#[test]
fn a_secret_stored_as_text_reads_as_a_secret() {
    let l = with(
        &[("api", "OPENAI_API_KEY", "STRING", "sk-x")],
        "OPENAI_API_KEY",
    );
    let fields = read_fields(&l, &fleet(), "dev");
    let f = fields.iter().find(|f| f.label == "OPENAI_API_KEY").unwrap();
    assert_eq!(f.kind, Kind::Secret);
}

#[test]
fn a_misplaced_field_reads_under_its_key() {
    let l = with(&[("Misc", "log-level", "STRING", "info")], "LOG_LEVEL");
    let fields = read_fields(&l, &fleet(), "dev");
    assert!(
        fields
            .iter()
            .any(|f| f.section == "api" && f.label == "LOG_LEVEL")
    );
}

#[test]
fn a_read_value_is_normalized() {
    let l = with(
        &[("api", "OPENAI_API_KEY", "CONCEALED", "sk-x\r\n")],
        "OPENAI_API_KEY",
    );
    let fields = read_fields(&l, &fleet(), "dev");
    let f = fields.iter().find(|f| f.label == "OPENAI_API_KEY").unwrap();
    assert_eq!(f.value.expose(), "sk-x");
}

#[test]
fn kept_fields_are_never_read() {
    let l = with(
        &[(KEPT_SECTION, "LOG_LEVEL (from top level, x)", "STRING", "d")],
        "",
    );
    let fields = read_fields(&l, &fleet(), "dev");
    assert!(fields.iter().all(|f| f.section != KEPT_SECTION));
}

#[test]
fn a_simple_profile_key_in_a_section_is_moved_to_the_top_level() {
    let l = layout(&[
        ("misc", "DB_URL", "CONCEALED", "x"),
        ("opv", "convention", "STRING", "1"),
    ]);
    assert_eq!(
        plan(&l, &simple(), "dev", DATE).changes,
        vec![Change::Moved {
            field: "DB_URL".into(),
            from: "misc".into()
        }]
    );
}

#[test]
fn the_summary_names_keys_never_values() {
    let l = with(
        &[
            ("", "OPENAI_API_KEY", "STRING", "sk-CONVMARKER\n"),
            ("Misc", "OPENAI_API_KEY", "STRING", "sk-CONVMARKER-old"),
        ],
        "OPENAI_API_KEY",
    );
    let p = plan_of(&l);
    assert!(!format!("{} {:?}", p.summary(), p.ops).contains(MARK));
}
