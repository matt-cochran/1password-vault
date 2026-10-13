# A team with personal keys and a devops-only production

- **Shared development values** (a team database URL) live in the dev vault, shared with the developers' group in 1Password.
- **Each developer's own keys** (an OpenAI key, so each person's spend is on their own key) live in their own item, in their own Private (or Employee) vault: `personal = true`. One shared personal value (`shared/OPENAI_API_KEY`) feeds every product's key with `from`.
- **Production** is shared in 1Password only with the devops group. Developers still see it listed, as "not available to you (audience: devops)"; people in devops see and sync it. Nobody's role is written down in opv: 1Password's sharing decides.

## Each developer, once

```sh
opv account list           # pick your account; opv account use <ID> if asked
opv bootstrap              # creates your own item "<project> · dev (personal)" in your Private vault
opv ready                  # your personal keys show as yours; fill them in 1Password
opv open shared/OPENAI_API_KEY --env dev
```

## Every day

```sh
opv run dev --product api -- npm run dev   # team values plus your own keys
opv check dev --product api               # your keys and the team's, saved?
```

Personal keys are never deployed: declaring one for `staging` or `prod` is a configuration error, and deployed environments use `SERVICE_OPENAI_API_KEY`, the service's own key.

Reference: [personal keys](../../docs/configuration.md#personal-keys-each-developers-own-values), [environment titles and audience](../../docs/configuration.md#environment-display-name-order-and-audience).
