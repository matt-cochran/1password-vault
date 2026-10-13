//! GitHub deploy credentials (FR-40, FR-46): the item's `GH_TOKEN` (a fine-grained token
//! with Secrets and Variables write on the listed repositories) is handed to every `gh`
//! call of the run in the child's environment only (never argv, never a file, SR-3/SR-4).
//!
//! CONTRACT STUB (plan deliverable `github-target-config`).
