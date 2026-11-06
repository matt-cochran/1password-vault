#!/bin/sh
# Value-free examples: how the downstream platform host (infra, platformd) will call opv unseal.
# Not executed by any test. Placeholders: <revision>, <container args>. No identity, value,
# recipient or key appears here. See README.md and docs/design/sealed-target.md section 5.8.
set -eu

ENV=staging-zonetico          # one opv environment per product on this platform
PRODUCT=zonetico
BUNDLE=sealed/$ENV/$PRODUCT.opv-sealed     # in the platform's manifest store checkout (D12)
SIGNERS=/etc/platform/opv-sealed-signers   # baked at image build; see the line format below

# allowed_signers line format (B2, G5): principals are the platform's environments, so one
# staging key signs for every staging product and never for prod:
#   staging-allumata,staging-endorz,...,staging-zonetico namespaces="opv-sealed" ssh-ed25519 <base64> platform signing (staging)

# 1. The owner's unattended check ("the bundles exist and verify"): zero calls, no identity.
opv unseal "$BUNDLE" --env "$ENV" --product "$PRODUCT" --signers "$SIGNERS" \
  --min-revision "<revision>" --verify-only --json

# 2. Per-container form: the one-for-one replacement of the pre-sealing start line
#      opv run "$ENV" --product "$PRODUCT" -- platformd env-map K=NAME... -- docker run -e NAME... <container args>
#    The identity comes from the Fly secret (environment only, D4(b)); opv removes it from the
#    child's environment. Variables only: this downstream has no opv file keys.
opv unseal "$BUNDLE" --env "$ENV" --product "$PRODUCT" --signers "$SIGNERS" \
  --identity-env PLATFORM_MANIFEST_AGE_KEY --min-revision "<revision>" \
  --exec -- platformd env-map DATABASE_URL=FLEET__ZONETICO__DATABASE_URL \
  -- docker run -e FLEET__ZONETICO__DATABASE_URL "<container args>"

# platformd itself (the path the downstream actually takes) does not call opv at all: it
# verifies with ssh-keygen -Y verify -n opv-sealed -I "$ENV", decrypts with age -d -i - and
# keeps the values in memory across restarts (README.md, "How the runtime will use").
