//! The CI job summary (H8): when `$GITHUB_STEP_SUMMARY` is set, `status`, `plan` and `sync`
//! append a Markdown section through [`CommandRunner::step_summary`].
//!
//! Names, kinds and state words only (SR-1): never a value, a value fragment, a rule
//! reason or a link. Rule reasons stay in the terminal output and the JSON, and the
//! 1Password link (it names the account) is never written to a file other people read.
//!
//! [`CommandRunner::step_summary`]: crate::runner::CommandRunner::step_summary

use super::{is_blocking, kind_label, problems_first};
use crate::domain::{KeyState, Row};

/// A `status` or `plan` section: a heading, the count line, `changes` when known, and one
/// table row per key (problems first), with `target` rendering the TARGET word.
pub(crate) fn table(
    heading: &str,
    count_line: &str,
    changes: Option<&str>,
    rows: &[Row],
    simple: bool,
    target: impl Fn(&Row) -> String,
) -> String {
    let mut md = format!("### {}\n\n{}\n", cell(heading), cell(count_line));
    if let Some(c) = changes {
        md.push_str(&format!("\nchanges: **{c}**\n"));
    }
    md.push('\n');
    let mut head = vec!["Product", "Key", "Kind", "State", "Target"];
    if simple {
        head.remove(0);
    }
    md.push_str(&format!("| {} |\n", head.join(" | ")));
    md.push_str(&format!("|{}\n", "---|".repeat(head.len())));
    for r in problems_first(rows) {
        let mut cells = vec![
            r.product.clone(),
            r.key.clone(),
            kind_label(r.kind).to_string(),
            state_word(r),
            target(r),
        ];
        if simple {
            cells.remove(0);
        }
        let cells: Vec<String> = cells.iter().map(|c| cell(c)).collect();
        md.push_str(&format!("| {} |\n", cells.join(" | ")));
    }
    let n = rows.iter().filter(|r| is_blocking(r)).count();
    if n > 0 {
        md.push_str(&format!(
            "\n{n} to fix in 1Password: run the job's opv command locally for the reasons \
             and an open link per key.\n"
        ));
    }
    md.push('\n');
    md
}

/// A `sync` section: a heading, the summary line, then one bullet per non-empty list of
/// `product/KEY (NAME)` labels.
pub(crate) fn lists(heading: &str, summary: &str, lists: &[(&str, &str)]) -> String {
    let mut md = format!("### {}\n\n{}\n\n", cell(heading), cell(summary));
    for (label, names) in lists.iter().filter(|(_, n)| !n.is_empty()) {
        md.push_str(&format!("- **{label}:** {}\n", cell(names)));
    }
    md.push('\n');
    md
}

/// The STATE word without the rule's reason: `failed <rule>` (H5 vocabulary).
fn state_word(r: &Row) -> String {
    match &r.state {
        KeyState::Missing => "missing".into(),
        KeyState::WrongKind => "wrong kind".into(),
        KeyState::RuleFailed(rule, _) => format!("failed {rule}"),
        KeyState::Ready => "saved".into(),
        KeyState::Skipped => "skipped".into(),
    }
}

/// One Markdown table cell: pipes, backticks and line breaks cannot break the table.
fn cell(s: &str) -> String {
    s.replace('|', "\\|")
        .replace('`', "'")
        .replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::rules::Reason;
    use crate::domain::{Kind, TargetState};

    fn row(key: &str, state: KeyState) -> Row {
        Row {
            product: "api".into(),
            key: key.into(),
            kind: Kind::Secret,
            state,
            target: TargetState::Absent,
            guidance: "Stripe dashboard".into(),
        }
    }

    fn md(rows: &[Row]) -> String {
        table(
            "opv plan prod",
            "prod: 2 keys",
            Some("some"),
            rows,
            false,
            |_| "new".into(),
        )
    }

    #[test]
    fn summary_lists_problem_rows_first() {
        let out = md(&[
            row("A_OK", KeyState::Ready),
            row("B_BAD", KeyState::Missing),
        ]);
        assert!(
            out.find("B_BAD").unwrap() < out.find("A_OK").unwrap(),
            "{out}"
        );
    }

    #[test]
    fn summary_names_the_failing_rule_without_its_reason() {
        let out = md(&[row(
            "K",
            KeyState::RuleFailed("enum", Reason::NotOneOf(vec!["FIXTUREVALUE".into()])),
        )]);
        assert!(
            out.contains("| failed enum |") && !out.contains("FIXTUREVALUE"),
            "{out}"
        );
    }

    #[test]
    fn summary_carries_no_guidance_text() {
        assert!(!md(&[row("K", KeyState::Missing)]).contains("Stripe dashboard"));
    }

    #[test]
    fn summary_escapes_pipes_in_cells() {
        assert_eq!(cell("a|b"), "a\\|b");
    }

    #[test]
    fn sync_summary_skips_empty_lists() {
        let out = lists("opv sync prod", "summary: written 0", &[("written", "")]);
        assert!(!out.contains("written:"), "{out}");
    }
}
