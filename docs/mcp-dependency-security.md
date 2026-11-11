# MCP dependency floor for the 0.18.3 candidate

The current RustSec database rejects `rmcp` 3.5.1. The minimum version that clears
all three reported advisories is 3.9.0:

| Advisory | Fixed version | Primary upstream fix |
| --- | --- | --- |
| [RUSTSEC-2026-0457](https://rustsec.org/advisories/RUSTSEC-2026-0457) | 3.7.0 | [DNS/address policy](https://github.com/modelcontextprotocol/rust-sdk/commit/ac808abcb40d3c90c743a097cd97c7dfc8f71b5d) |
| [RUSTSEC-2026-0461](https://rustsec.org/advisories/RUSTSEC-2026-0461) | 3.6.0 | [Tool cache removal](https://github.com/modelcontextprotocol/rust-sdk/pull/1349) |
| [RUSTSEC-2026-0462](https://rustsec.org/advisories/RUSTSEC-2026-0462) | 3.9.0 | [Bounded response bodies](https://github.com/modelcontextprotocol/rust-sdk/commit/3e0156c1eaf1573a1b878e2a8998d2fa2d0b1439) |

The source contract requires at least 3.9.0 and the lockfile selects exactly
`rmcp`/`rmcp-macros` 3.9.0. Existing enabled features remain `server`, `macros`,
`transport-io`; this change adds no HTTP transport or MCP capability. No advisory
ignore is added. The authoritative advisory records were checked at RustSec
advisory-db commit `28d73fc95e5972af3403225a217def57dcaba3c4`.

Release eligibility requires the affected MCP/CLI tests and dependency policy
gate, plus fresh six-platform native/npm qualification of this changed source.
Earlier candidate bytes do not establish qualification of this dependency update.
