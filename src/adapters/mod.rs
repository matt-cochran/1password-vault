//! Vendor adapters behind the `CommandRunner` seam (FR-12). Each wraps an official CLI.

pub mod fly;
pub mod onepassword;
/// Dev-time title lookup and value-free item read, for `opv init` only (FR-23).
pub mod onepassword_init;
