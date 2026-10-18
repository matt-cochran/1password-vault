//! The review step of `opv ui`'s import flow (#94): turns the rows of
//! `opv import <env> --from <src> --dry-run --json` and a person's per-key decisions into
//! the exact `opv import ...` argument list (which writes by default). Names, actions and
//! decisions only; a secret value is never read or kept here.

use super::docs::AdoptDoc;

/// What a person decided for one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Take the found value (import, or replace a differing one).
    Take,
    /// Keep 1Password's value.
    Keep,
    /// Leave the key out of this adoption entirely.
    Skip,
}

/// One row of the adoption review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewRow {
    pub product: Option<String>,
    pub key: Option<String>,
    pub label: String,
    pub action: String,
    pub found: Vec<String>,
    pub immutable: bool,
    pub decision: Option<Decision>,
}

/// One row per row of the document. `label(product, key)` gives the display/CLI name; rows
/// without a key get `label = found joined with ", "`. `immutable(product, key)` says
/// whether the key is immutable. `decision = default_decision(action)`.
pub fn rows_from(
    doc: &AdoptDoc,
    label: &dyn Fn(&str, &str) -> String,
    immutable: &dyn Fn(&str, &str) -> bool,
) -> Vec<ReviewRow> {
    doc.rows
        .iter()
        .map(|r| {
            let product = r.product.clone();
            let key = r.key.clone();
            let found = r.found.clone();
            let action = r.action.clone();
            let label = match &key {
                Some(k) => label(product.as_deref().unwrap_or(""), k),
                None => found.join(", "),
            };
            let immutable = match (&product, &key) {
                (Some(p), Some(k)) => immutable(p, k),
                _ => false,
            };
            let decision = default_decision(&action);
            ReviewRow {
                product,
                key,
                label,
                action,
                found,
                immutable,
                decision,
            }
        })
        .collect()
}

/// `imported` -> `Some(Take)`; `skipped_already_set` -> `Some(Keep)`; every other action ->
/// `None` (not the person's to decide here). The words are the import document's own.
pub fn default_decision(action: &str) -> Option<Decision> {
    match action {
        "imported" => Some(Decision::Take),
        "skipped_already_set" => Some(Decision::Keep),
        _ => None,
    }
}

/// The next decision on a key press: `imported` cycles Take -> Skip -> Take;
/// `skipped_already_set` cycles Keep -> Take -> Skip -> Keep; `None` stays `None`.
pub fn toggle(row: &ReviewRow) -> Option<Decision> {
    match (row.action.as_str(), row.decision) {
        ("imported", Some(Decision::Take)) => Some(Decision::Skip),
        ("imported", Some(Decision::Skip)) => Some(Decision::Take),
        ("skipped_already_set", Some(Decision::Keep)) => Some(Decision::Take),
        ("skipped_already_set", Some(Decision::Take)) => Some(Decision::Skip),
        ("skipped_already_set", Some(Decision::Skip)) => Some(Decision::Keep),
        _ => None,
    }
}

/// How many fields applying would write: rows decided Take.
pub fn writes(rows: &[ReviewRow]) -> usize {
    rows.iter()
        .filter(|r| r.decision == Some(Decision::Take))
        .count()
}

/// `["import", env, "--from", from]` then, in row order, `--skip` label for every
/// `imported` row decided Skip, `--replace` label for every `skipped_already_set` row
/// decided Take, and additionally `--rotate` label right after that `--replace` when the row
/// is immutable. There is no `--apply`: import writes by default. Rows with decision None
/// add nothing.
pub fn command(env: &str, from: &str, rows: &[ReviewRow]) -> Vec<String> {
    let mut out = vec![
        "import".to_string(),
        env.to_string(),
        "--from".to_string(),
        from.to_string(),
    ];
    for row in rows {
        match (row.action.as_str(), row.decision) {
            ("imported", Some(Decision::Skip)) => {
                out.push("--skip".to_string());
                out.push(row.label.clone());
            }
            ("skipped_already_set", Some(Decision::Take)) => {
                out.push("--replace".to_string());
                out.push(row.label.clone());
                if row.immutable {
                    out.push("--rotate".to_string());
                    out.push(row.label.clone());
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
#[path = "adopt_review_tests.rs"]
mod tests;
