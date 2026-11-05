//! The sealed target (#271, `docs/design/sealed-target.md`): `opv sync` reads 1Password at
//! release time and writes one signed, encrypted bundle per product; the runtime opens it
//! with `opv unseal` and never reads 1Password.
//!
//! - [`config`]: the section and the §3.1 load rules, including the rules across targets
//!   (trust groups, D11) and the `sealed.out` resolver (D12).
//! - [`provider`]: the registered [`PROVIDER`] and the target's [`crate::provider::TargetConfig`].
//! - [`login`]: the SSH Key deploy credential (P2), checked against `sealed.signer` at sign-in
//!   and handed only to the runner's seal effect.
//!
//! A later lane adds `store.rs` (P3, the `StagedStore`); until then the target's `open`
//! refuses as an internal error naming the missing lane.

pub mod config;
pub mod login;
pub mod provider;

pub use provider::PROVIDER;
