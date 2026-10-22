//! The HTTP target's destination (design `http-target` §4.2).
//!
//! `base_url` is parsed once, before any call: its scheme, host and path prefix are checked
//! together ([`parse_base_url`]), and [`Destination::uri`] builds every request URI from the
//! same parsed value, so the host checked is the host connected to (T11). A refusal is one
//! of this module's fixed reasons, never the input (SR-1).

use std::net::IpAddr;

/// A parsed `base_url` (§4.2): the target host and the path prefix, already checked against
/// the configuration's `http.host`. Built only by [`parse_base_url`], so a request URI is
/// never assembled from unparsed text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// The host, lower-case ASCII and equal to `http.host` (§4.2).
    pub host: String,
    /// The path prefix: empty, or `/`-separated `[A-Za-z0-9._-]` segments.
    pub prefix: String,
}

impl Destination {
    /// The request URI: the host, the path prefix and `path`, all from the one parsed value.
    /// `path` begins with `/`; the result is host plus path only, as the runner's HTTPS call
    /// carries it (`crate::runner_https`), never a scheme.
    pub fn uri(&self, path: &str) -> String {
        format!("{}{}{}", self.host, self.prefix, path)
    }
}

/// Parse `s` as the item's `base_url` and check its host against `expect_host` (the
/// configuration's `http.host`), or refuse with a fixed reason that never quotes `s`
/// (§4.2).
pub fn parse_base_url(s: &str, expect_host: &str) -> Result<Destination, &'static str> {
    let rest = s
        .strip_prefix("https://")
        .ok_or("base_url must use https")?;
    if rest.contains('?') {
        return Err("base_url must not have a query");
    }
    if rest.contains('#') {
        return Err("base_url must not have a fragment");
    }
    let (authority, path) = match rest.split_once('/') {
        Some((a, _)) => (a, &rest[a.len()..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err("base_url must have a host");
    }
    if authority.contains('@') {
        return Err("base_url must not have userinfo");
    }
    if authority.contains(':') {
        return Err("base_url must not have a port");
    }
    let host = authority;
    if host.ends_with('.') {
        return Err("base_url host must not end with a dot");
    }
    if host.parse::<IpAddr>().is_ok() {
        return Err("base_url host must not be an IP address");
    }
    if !is_lower_host(host) {
        return Err("base_url host must be lower-case ASCII");
    }
    if host != expect_host {
        return Err("base_url host does not match http.host");
    }
    Ok(Destination {
        host: host.to_string(),
        prefix: path_prefix(path)?,
    })
}

/// The host is lower-case ASCII: labels of `[a-z0-9-]`, never empty, never starting or
/// ending with `-`.
fn is_lower_host(host: &str) -> bool {
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

/// The path prefix from a `base_url` path (§4.2): empty for no path or `/`, otherwise
/// `/`-separated segments of `[A-Za-z0-9._-]`.
fn path_prefix(path: &str) -> Result<String, &'static str> {
    if path.is_empty() || path == "/" {
        return Ok(String::new());
    }
    let segments = path.strip_prefix('/').unwrap_or(path);
    let ok = !segments.is_empty()
        && segments.split('/').all(|seg| {
            !seg.is_empty()
                && seg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        });
    if ok {
        Ok(path.to_string())
    } else {
        Err("base_url path must be /-separated [A-Za-z0-9._-] segments")
    }
}

#[cfg(test)]
#[path = "url_tests.rs"]
mod tests;
