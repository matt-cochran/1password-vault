//! "Did you mean …?" for names typed on the command line (P8). Candidates are names from
//! the configuration only (products, keys, environments), never values.

/// The candidates closest to `input` by edit distance, ignoring case: at most three, the
/// closest first (ties in the given order). A candidate is close when at most a third of
/// the longer name differs (and at least one edit is always allowed).
pub(crate) fn close<'a>(
    input: &str,
    candidates: impl IntoIterator<Item = &'a str>,
) -> Vec<&'a str> {
    let want = input.to_ascii_lowercase();
    let mut scored: Vec<(usize, &'a str)> = candidates
        .into_iter()
        .filter_map(|c| {
            let d = distance(&want, &c.to_ascii_lowercase());
            let limit = (want.chars().count().max(c.chars().count()) / 3).max(1);
            (d <= limit).then_some((d, c))
        })
        .collect();
    scored.sort_by_key(|(d, _)| *d);
    scored.into_iter().take(3).map(|(_, c)| c).collect()
}

/// `; did you mean A or B?`, or nothing when no candidate is close.
pub(crate) fn hint<'a>(input: &str, candidates: impl IntoIterator<Item = &'a str>) -> String {
    let close = close(input, candidates);
    if close.is_empty() {
        String::new()
    } else {
        format!("; did you mean {}?", close.join(" or "))
    }
}

/// Levenshtein distance over chars.
fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cur = row[j + 1];
            row[j + 1] = if ca == *cb {
                prev
            } else {
                1 + prev.min(cur).min(row[j])
            };
            prev = cur;
        }
    }
    row[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_one_letter_typo_is_suggested() {
        assert_eq!(
            close("OPENAI_API_KY", ["OPENAI_API_KEY", "DATABASE_URL"]),
            ["OPENAI_API_KEY"]
        );
    }

    #[test]
    fn case_is_ignored() {
        assert_eq!(
            close("openai_api_key", ["OPENAI_API_KEY"]),
            ["OPENAI_API_KEY"]
        );
    }

    #[test]
    fn a_distant_name_is_not_suggested() {
        assert!(close("NOPE", ["OPENAI_API_KEY", "DATABASE_URL"]).is_empty());
    }

    #[test]
    fn hint_is_empty_without_a_close_candidate() {
        assert_eq!(hint("NOPE", ["DATABASE_URL"]), "");
    }
}
