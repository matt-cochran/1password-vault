//! The sealed target's bundle codec (design sealed-target §5, lane B1): the pure
//! `opv-sealed/1` format — a format line, a canonical value-free header, an age armor block,
//! an SSHSIG armor block and the binary payload framing.
//!
//! The module is a codec only. It has no dependency on configuration, runners or adapters,
//! and it holds no crypto of its own: `crypto.rs` (lane st-b2) adds age and SSHSIG over these
//! parts, and `allowed_signers.rs` the strict trusted-signer file.

pub mod format;

#[cfg(test)]
#[path = "format_tests.rs"]
mod format_tests;

pub mod allowed_signers;
pub mod crypto;

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod crypto_tests;

#[cfg(test)]
#[path = "allowed_signers_tests.rs"]
mod allowed_signers_tests;
