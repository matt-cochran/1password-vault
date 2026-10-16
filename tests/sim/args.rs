//! Reading a tool's argv: flag values and the subcommand words (flags left out).

/// The value of `name` in `args`: `name value` or `name=value`.
pub fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            return None;
        }
        if a == name {
            return it.next().map(String::as_str);
        }
        if let Some(v) = a.strip_prefix(name).and_then(|v| v.strip_prefix('=')) {
            return Some(v);
        }
    }
    None
}

/// Whether the switch `name` is present (before any `--`).
pub fn has(args: &[String], name: &str) -> bool {
    args.iter().take_while(|a| *a != "--").any(|a| a == name)
}

/// The positional words of `args`: every flag is left out with its value, except the
/// switches in `boolean` (which take none) and `--x=value` forms. `-` (stdin) is kept out.
/// Stops at `--`.
pub fn words(args: &[String], boolean: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            break;
        }
        if a == "-" {
            continue;
        }
        if a.starts_with('-') {
            if !a.contains('=') && !boolean.contains(&a.as_str()) {
                it.next();
            }
            continue;
        }
        out.push(a.clone());
    }
    out
}
