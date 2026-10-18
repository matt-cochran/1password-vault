//! The name check every MCP document passes through ([`identifier`]). The 0.11.0 tool
//! projections that lived here are gone with their tools (rows `mcp-propose-a` and
//! `mcp-state`): each tool now answers the CLI command's own `--json` document.

/// A declared name, safe to echo: non-empty, at most 128 bytes, ASCII letters, digits and
/// `_.-/` only. Everything that reaches a document passes through here or a stricter check.
pub(crate) fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-/".contains(&b))
}
