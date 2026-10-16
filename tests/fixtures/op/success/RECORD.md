# Recording op success output (owner)

The simulator (`tests/sim/op.rs`) still prints its own JSON for `account list`, `vault list`, `vault get`, `vault user list`, `item list` and the writes. Those replies need a signed-in 1Password session, which only the owner runs. This page gives the exact commands and the scrubbing. Every command below is a read except section 3, which is optional and touches only a throwaway vault.

Use op 2.40.0 or later (`op --version`), the project account (A, `<ACCOUNT_2>` in `../failures/`) signed in, and stdin closed on every call.

## 1. Record (reads only)

```bash
set -u
A=<the project account ID>          # as in ../failures/cases.tsv: <ACCOUNT_2>
V=<a vault of A with at least one item that holds no real secret, e.g. a test vault>
OUT=$(mktemp -d); cd "$OUT"
rec() { n=$1; shift; "$@" </dev/null >"$n.stdout" 2>"$n.stderr"; echo $? >"$n.exit"; echo "$n exit $(cat "$n.exit")"; }
rec 01-account-list    op account list --format json
rec 02-vault-list      op vault list --account "$A" --format json
rec 03-vault-get       op vault get "$V" --account "$A" --format json
rec 04-vault-user-list op vault user list "$V" --account "$A" --format json
rec 05-item-list       op item list --vault "$V" --account "$A" --format json
echo "$OUT"
```

`item list` prints titles, tags and IDs, never field values, but pick a vault whose item titles you are happy to publish (they are replaced below anyway).

## 2. Scrub (structural, keeps the layout byte for byte)

The script walks each JSON document and collects every identifying string: the values of `id`, `account_uuid`, `user_uuid`, `email`, `url`, `shorthand`, `name`, `title`, `tags`, `additional_information`, `description`, `created_at`, `updated_at`, `last_edited_by`. It then replaces each distinct value with a numbered marker, in the text, so whitespace, key order and the trailing newline stay exactly as op printed them. The marker names follow `../failures/`: the project account keeps `<ACCOUNT_2>`, the other `<ACCOUNT_1>`.

```bash
cat >scrub.py <<'EOF'
import json, sys, pathlib, re
KEYS = {"id": "ID", "account_uuid": "ACCOUNT", "user_uuid": "USER", "email": "EMAIL",
        "url": "ADDRESS", "shorthand": "SHORTHAND", "name": "NAME", "title": "TITLE",
        "tags": "TAG", "additional_information": "INFO", "description": "DESCRIPTION", "created_at": "TIME",
        "updated_at": "TIME", "last_edited_by": "USER"}
project = sys.argv[1]
seen = {project: "<ACCOUNT_2>"}
count = {}
def mark(kind, v):
    if v not in seen:
        count[kind] = count.get(kind, 0) + 1
        seen[v] = f"<{kind}_{count[kind]}>"
    return seen[v]
def walk(x, key=None):
    if isinstance(x, dict):
        for k, v in x.items(): walk(v, k)
    elif isinstance(x, list):
        for v in x: walk(v, key)
    elif isinstance(x, str) and key in KEYS and x:
        mark(KEYS[key], x)
for f in sorted(pathlib.Path(".").glob("*.stdout")):
    text = f.read_text()
    if text.strip(): walk(json.loads(text))
for f in sorted(pathlib.Path(".").glob("*.std*")):
    text = f.read_text()
    for v in sorted(seen, key=len, reverse=True):
        text = text.replace(json.dumps(v, ensure_ascii=False)[1:-1], seen[v])
    f.with_suffix(f.suffix + ".scrubbed").write_text(text)
print(len(seen), "values replaced")
EOF
python3 -I scrub.py "$A"
grep -l -i -E '@|1password\.(com|eu|ca)|[A-Z0-9]{26}' *.scrubbed || echo "no identifiers left"
```

Read every `*.scrubbed` file before copying it: nothing in it may name a person, an account, a vault or an item. Then copy them here without the `.scrubbed` suffix, with the `.exit` files:

```bash
for f in *.scrubbed; do cp "$f" "<repo>/tests/fixtures/op/success/${f%.scrubbed}"; done
cp *.exit "<repo>/tests/fixtures/op/success/"
```

and add a `README.md` here with the op version, the date, the commands above and the marker table, as `../failures/README.md` has.

## 3. Optional: the writes, in a throwaway vault

Only if you want `vault create`, `item create` and `item edit` recorded too. This creates a vault named `opv-recording-scratch` in account A and deletes it at the end; the item holds a marker, never a secret.

```bash
rec 07-vault-create op vault create opv-recording-scratch --account "$A" --format json
printf '%s' '{"title":"opv-recording","category":"SECURE_NOTE","fields":[{"id":"notesPlain","type":"STRING","purpose":"NOTES","label":"notesPlain","value":"<MARKER>"}]}' >tmpl.json
op item create - --vault opv-recording-scratch --title opv-recording --account "$A" --format json <tmpl.json >08-item-create.stdout 2>08-item-create.stderr; echo $? >08-item-create.exit
op item get opv-recording --vault opv-recording-scratch --account "$A" --format json </dev/null >item.json
op item edit opv-recording --vault opv-recording-scratch --account "$A" --format json <item.json >09-item-edit.stdout 2>09-item-edit.stderr; echo $? >09-item-edit.exit
op vault delete opv-recording-scratch --account "$A" </dev/null
```

Scrub them with section 2 before copying.

## 4. Then

Tell the next deliverable which files landed. `tests/sim/op.rs` then answers these calls from the recordings, the way `whoami` uses `../failures/10-whoami-a`, and its header drops them from "awaiting owner recording".
