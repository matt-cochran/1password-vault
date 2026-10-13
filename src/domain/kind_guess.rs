//! Guess a dotenv key's [`Kind`] from its NAME alone (FR-14, issue #90).
//!
//! `opv init --from <file.env>` declares every key of a dotenv file, so it must decide
//! whether each belongs in a concealed field or a text field (FR-14). The decision is by name only, never by value: a value
//! can look like a secret or like config and mislead either way. Secret is the safe default —
//! a database or webhook URL carries credentials even though its name ends in `_URL`.
//!
//! Names are matched case-sensitively, as the uppercase names `opv` accepts. Any name
//! containing SECRET, TOKEN, PASSWORD, PASSWD, PRIVATE or CREDENTIAL is always a secret, even
//! when it also ends in a config suffix (`PRIVATE_KEY_ID`, `TOKEN_ISSUER`).

use crate::domain::Kind;

/// Config suffixes: a key whose name ends in one of these is plain configuration.
const CONFIG_SUFFIXES: [&str; 26] = [
    "_ENABLED",
    "_DISABLED",
    "_MODEL",
    "_PORT",
    "_ORIGIN",
    "_BIND",
    "_HOST",
    "_ENVIRONMENT",
    "_ENV",
    "_REGION",
    "_LOG_LEVEL",
    "_CLIENT_ID",
    "_KEY_ID",
    "_PRICE_ID",
    "_ACCOUNT_ID",
    "_PROJECT_ID",
    "_REDIRECT_URI",
    "_ISSUER",
    "_AUDIENCE",
    "_PROVIDER",
    "_MODE",
    "_TIMEOUT",
    "_TTL",
    "_DOMAIN",
    "_EMAIL",
    "_FROM",
];

/// Exact config names that no suffix rule catches (`NODE_ENV` and `LOG_LEVEL` are also
/// caught by `_ENV` and `_LOG_LEVEL`).
const CONFIG_NAMES: [&str; 4] = ["NODE_ENV", "LOG_LEVEL", "RUST_LOG", "TZ"];

/// Substrings that force a secret wherever they appear in the name.
const ALWAYS_SECRET: [&str; 6] = [
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PRIVATE",
    "CREDENTIAL",
];

/// Decide the [`Kind`] of a dotenv key from its name alone.
///
/// Config when the name is exactly `PORT` or `NODE_ENV`/`LOG_LEVEL`/`RUST_LOG`/`TZ`, or ends
/// in a known config suffix. A name carrying SECRET, TOKEN, PASSWORD, PASSWD, PRIVATE or
/// CREDENTIAL anywhere is always a secret, whatever else it matches. Everything else is a
/// secret, the safe default. Never panics, including on an empty name.
pub fn kind_for_name(name: &str) -> Kind {
    if ALWAYS_SECRET.iter().any(|&word| name.contains(word)) {
        return Kind::Secret;
    }
    if name == "PORT"
        || CONFIG_SUFFIXES.iter().any(|&suffix| name.ends_with(suffix))
        || CONFIG_NAMES.contains(&name)
    {
        return Kind::Config;
    }
    Kind::Secret
}

#[cfg(test)]
#[path = "kind_guess_tests.rs"]
mod tests;
