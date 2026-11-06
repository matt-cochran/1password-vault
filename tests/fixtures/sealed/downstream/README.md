# Downstream fixture: the owner's platform host (infra)

This fixture describes the first consumer of the sealed target (#271): the platform host in
`matt-cochran-products/infra`, at commit `50833e19` (`origin/staging`). It holds **names only**:
environments, products and key names. It holds no value, no recipient and no key material. The
comparison with `opv-sealed/1` is in `docs/design/sealed-target.md` §5.8.

There is no binary bundle here yet. Lane B1 builds the codec, and the known-answer bundles come
from S0/B1.

## Files

| File | What it is |
|---|---|
| `shape.json` | Per platform: the environment pattern, products, each product's environment, the downstream's bundle path, and key names and kinds. Generated from `fly/platform/{staging,production}/opv/secrets.toml` |
| `downstream-v1-envelope.example.json` | The shape of the downstream's own `opv-sealed/v1` envelope, with every value replaced by a placeholder. For D9; opv does not read this format |
| `unseal.example.sh` | Value-free examples of how the runtime side will call `opv unseal` |

## The downstream's shape

- **Two platforms**, `staging` and `production`. Each is one Fly Machine running `platformd`, a
  supervisor that starts every product container with `docker run -e NAME`.
- **One opv environment per product**: `staging-<p>` and `prod-<p>`. There are ten products:
  - allumata, endorz, fantasticus, journeeze, licenz;
  - nearvado, preveti, pubops, resoniche, zonetico.
- **One bundle per (environment, product).** Today it is at `sealed/<env>/<product>.age`, with a
  detached `.sig`, in the platform's manifest store, a separate git repository that `platformd`
  pulls.
- **One trust unit per platform:**
  - one age recipient (the machine's identity, which also opens `index.age`);
  - one ed25519 signer (the release signing key).

  These are shared by all ten environments of that platform. See D11 in the design.
- **The identity** is the Fly secret `PLATFORM_MANIFEST_AGE_KEY`, delivered as an environment
  variable only. `platformd` reads it once and removes it from its environment.
- **Never sealed:** the `<env>-platform` scope, which holds the identity, the signing key, the
  registry tokens and the owner's proof token.
- **No sealed key is an opv `file` key.** Per-key file delivery (`/run/secrets/<NAME>`) is
  chosen in the downstream's unit manifest, and `platformd` writes those files itself.
- **Largest scope:** `prod-zonetico`, with 39 names. Values include multi-line PEM and JSON.

## How the runtime will use `opv-sealed/1`

`platformd` stays the consumer. It reads `opv-sealed/1` natively:

1. Split the file in memory.
2. Verify with `ssh-keygen -Y verify -n opv-sealed -I <env>`.
3. Check the env, product and revision floor.
4. Decrypt with `age -d -i -`, the identity on stdin.
5. Parse the payload.

It keeps the values in memory across container restarts. `opv unseal` is used for:

- **checks:** `--verify-only`, with no identity and zero calls, for the owner's unattended
  "bundles exist" step;
- **the per-container form,** for any consumer without a supervisor. It replaces the pre-sealing
  `opv run <env> --product <p> -- platformd env-map … -- docker run …` line one for one.

`unseal.example.sh` shows both forms.
