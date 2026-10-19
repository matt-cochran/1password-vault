# Spike A-1: can a 1Password member write a vault they cannot read?

Row `a1-spike` of plan `v0120` (`assistant-guided-setup.md` §23, R4, §24 R9(a)). Run by the owner on 2026-10-18 in the project account's 1Password app, with a throwaway vault. No value was entered or recorded.

## What was tried

1. The owner created a throwaway vault.
2. In that vault's permissions, the owner took away the viewing permission and kept write-type permissions.

## What 1Password did

As soon as viewing was taken away, the vault was no longer visible in 1Password to the identity whose permissions changed. In 1Password, a vault you cannot view is a vault you do not see. Nothing in the app is left to create or edit items in.

The owner's report: "if I change the permissions, I can't see the vault anymore in 1Password."

`op item create` and `op item edit` against the hidden vault were not tried. Through the app, write-without-read has no usable surface: the vault isn't listed, so a person has nowhere to enter a value.

## Which form holds

**The weak form.** 1Password offers no usable "write but not read" for a vault: writing needs viewing. So:

- **R4 / R9(a):** anyone who can set a deployed tier's values can also read them. opv cannot narrow that, and the design doesn't try.
- **The hardened option (owner decision D-A)** stays as documented: people who enter production values do it from a separate 1Password admin account used only for production work. The everyday account, and any assistant running in that person's shell, then has no access to production vaults.
- **What opv reports:** a session that can read a production-tier vault (`doctor`, `access`), and the admin-account setup as the fix. It is a finding, never a block.

## Follow-up

None for 0.12.0. If 1Password later adds write-only vault access, revisit R4's strong form.
