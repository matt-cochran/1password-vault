# Build once and promote

Refs https://github.com/matt-cochran/execution-policy/issues/9.

Every dev change references an issue. Keep the full existing CI suite before main.
Build gate on main verifies the complete staging tree and retained CI evidence;
it never rebuilds or reruns tests, including hotfixes and missing artifacts.

Release builds all six existing targets on staging after validated CI. All existing
host/smoke tests are preserved there. Package seven npm tarballs on staging and
retain them with every binary, SHA256SUMS and a repository/tree/run/attempt manifest
for 90 days. Main and v-tags resolve and verify that artifact; no build job runs.
Tags must identify main. Production publishes those bytes and needs the existing
npm trusted-publisher setup. Native Windows/macOS builds stay on native runners;
CI_RUNNER_MODE selects GitHub or Blacksmith for supported Linux jobs.

Missing/expired/mismatched evidence stops publication. Rebuild/validate a staging
candidate before trying main again. Merge promotions and back-merges with merge
commits; preserve source tree identity. Apply the main Build gate requirement and
retire matrix/cargo-deny/gitflow-guard requirements only after the main promotion
has a green reuse gate. Preserve all other review and branch protections.

This PR changes workflow contracts, not a live release. Validate a staging run and
its retained candidate before promoting. A published version must not be replaced.
