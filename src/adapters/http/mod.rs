//! The HTTP target's shared modules (design `http-target` §5, §6).
//!
//! The descriptor is pinned by hash ([`descriptor`]) and the configuration is parsed into
//! plain types ([`model`]) before any call is made. The gRPC-Web codec, the `Store` and the
//! catalog mappings are later lanes; nothing here is in [`crate::adapters::registry`].

pub mod descriptor;
pub mod login;
pub mod model;
pub mod url;
