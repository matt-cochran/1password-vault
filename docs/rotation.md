# Rotating a key

A key is exposed, or it has reached the date it was due to be rotated. Rotate it with an
overlap: the new value goes live everywhere before the old one is switched off. opv has no
rotation planner. This page is the one safe procedure, and it says what to do about the
places opv cannot see.

## The procedure

### 1. Put the new value alongside the old

Ask the provider to issue a second credential for the same key. Leave the old one valid.
Put the new value into the key's field in 1Password, in the 1Password app or with
`opv set <product/KEY> --env <env>` (masked entry in your own terminal). Both values are accepted at the provider from here on.

### 2. Deliver the new value, environment by environment

Rotate the key in one environment at a time. `--rotate` replaces a key that is already set
even when it is immutable; a sync without it leaves the old value in place.

```sh
opv sync <env> --rotate <product/KEY>
```

Preview the change first if you want to see exactly what the sync would write:

```sh
opv plan <env> --rotate <product/KEY>
```

Move to the next environment only after the one before it verified.

### 3. Confirm every running revision holds the new value

Check the placements, then read the platform's rollout status:

```sh
opv delivery verify <env>
```

`opv delivery verify` reports each placement as verified, changed or not delivered. Read the
target's rollout status too. A revision that still holds the old value is not a failure of
this step: wait for it, or redeploy, before moving on.

### 4. Revoke the old value at the provider

Only after every environment verified, and every running revision holds the new value,
revoke the old credential at the provider. That is your step. opv never revokes a value.

## Consumers outside opv

Another host, a partner's webhook, a scheduled job on a machine opv does not manage: these
read the key without opv seeing them. They are listed in the key's guidance. Check every one
of them before step 4, and update or restart each one. A consumer left behind breaks the
moment the old value is revoked.

## Expiry

A key may carry an optional expiry date. Record it on the key in the configuration file, as
a quoted calendar date:

```toml
[products.api.keys.SIGNING_KEY]
expires = "2027-01-31"
```

`opv ready` reports an advisory finding, `expires_soon`, when a key is within 30 days of its
expiry date. The finding points at this page and never blocks a sync. When you see it, run
the procedure above.

```sh
opv ready <env>
```
