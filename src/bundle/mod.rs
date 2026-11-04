//! The sealed target's bundle codec (design sealed-target §5, lane B1): the pure
//! `opv-sealed/1` format — a format line, a canonical value-free header, an age armor block,
//! an SSHSIG armor block and the binary payload framing.
//!
//! The module is a codec only. It has no dependency on configuration, runners or adapters,
//! and it holds no crypto: lane st-b2 adds age and SSHSIG in `crypto.rs` over these parts.

pub mod format;

#[cfg(test)]
#[path = "format_tests.rs"]
mod format_tests;
