//! "Did you mean …?" for names typed on the command line (P8). Candidates are names from
//! the configuration only (products, keys, environments), never values.

/// The candidates closest to `input` by edit distance, ignoring case: at most three, the
/// closest first (ties in the given order). A candidate is close when at most a third of
/// the longer name differs (and at least one edit is always allowed).
pub fn close<'a>(input: &str, candidates: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
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

/// The one candidate strictly closest to `input` among those [`close`] keeps; `None` when
/// none is close or two tie (never a guess, X2).
pub fn closest<'a>(input: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let want = input.to_ascii_lowercase();
    let near = close(input, candidates);
    let d = |c: &str| distance(&want, &c.to_ascii_lowercase());
    match near.as_slice() {
        [one] => Some(*one),
        [a, b, ..] if d(a) < d(b) => Some(*a),
        _ => None,
    }
}

/// Edit distance over chars where swapping two neighbouring letters is one edit (optimal
/// string alignment): `prdo` is one edit from `prod` (09.13).
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = v;
        }
    }
    d[a.len()][b.len()]
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
    fn a_transposed_name_is_suggested() {
        // 09.13: `prdo` is `prod` with two letters swapped.
        assert_eq!(close("prdo", ["dev", "prod"]), ["prod"]);
    }

    #[test]
    fn a_distant_name_is_not_suggested() {
        assert!(close("NOPE", ["OPENAI_API_KEY", "DATABASE_URL"]).is_empty());
    }
}
