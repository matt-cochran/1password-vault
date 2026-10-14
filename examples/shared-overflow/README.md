# A shared Fly app and a dedicated overflow app for one product

One project with three products (`web`, `api`, `p`) and one source-only `shared` product.
`shared` holds one database URL that `web` and `api` read with `from`, so the value is
entered once. In `prod`, the shared app `portfolio-prod` delivers all three products, and
the overflow app `p-overflow-prod` delivers `p` again under bare names. Each placement has
its own delivery evidence.

| File | What it is |
|---|---|
| [secrets.toml](secrets.toml) | the configuration: one values vault per product, four products, two prod targets |

## 1. Create the vaults and items

This section creates every boundary item and target state vault the example needs.

```sh
opv bootstrap
```

`opv bootstrap` creates one values vault and item per product (`myapp-p-dev`, and in prod
`myapp-shared-prod`, `myapp-web-prod`, `myapp-api-prod` and `myapp-p-prod`) and one
state vault per target, then fills the empty IDs in `secrets.toml`. Commit the result.
The overflow app's deploy identity then reads only `myapp-p-prod` (and writes its state vault):
`opv access prod --target p-overflow` prints exactly that.

## 2. Check the local product

This section checks the one product that runs on this machine.

```sh
opv check dev
```

`dev` has no target, so only `p` has keys there and no `--product` is needed.

## 3. Plan and sync production

This section previews both placements, then applies exactly the reviewed plan.

```sh
opv plan prod
opv sync prod --expect-plan <id>
```

One plan covers both targets: the shared app and the overflow app. The plan id is the
reviewed confirmation.

## 4. Verify each placement

This section reads the delivery evidence of `p` on each app.

```sh
opv delivery verify prod --product p
```

Without `--target`, `verify` reports both placements of `p`, `shared` and `p-overflow`,
each with its own state and its own evidence item. Add `--target p-overflow` to narrow it.

## 5. How `p-overflow` was added

This section shows the command that wrote the `[environments.prod.targets.p-overflow]`
table.

```sh
opv target add prod p-overflow --fly-app p-overflow-prod --fly-secret-name '{KEY}' --products p
```

`--fly-app` names the app, `--fly-secret-name '{KEY}'` is the bare-name template, and
`--products p` restricts the target to `p`. The command also creates the target's state
vault, records `state_vault_id`, and ends with `Next: opv access prod --target p-overflow`.
The `shared` target has no `products` list, so it delivers every product with a key in
`prod`, `p` included.
