//! The HTTP target's shared modules (design `http-target` §5, §6).
//!
//! The descriptor is pinned by hash ([`descriptor`]) and the configuration is parsed into
//! plain types ([`model`]) before any call is made. The gRPC-Web codec, the `Store` and the
//! catalog mappings are later lanes; the provider ([`PROVIDER`]) is registered in
//! [`crate::adapters::registry`].

pub mod config;
pub mod descriptor;
pub mod grpc_decode;
pub mod grpc_encode;
pub mod login;
pub mod model;
pub mod propose;
pub mod provider;
pub mod store;
pub mod url;

pub use provider::PROVIDER;
