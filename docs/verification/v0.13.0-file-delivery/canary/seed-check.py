"""A4-V0 seed check: does 1Password hold exactly the canary bytes? Prints digests' verdicts only.

    python3 -I seed-check.py <opv> <project dir> <canary dir> <env> [<env> ...]

For each key the environment declares, it asks `opv open <key> --env <env> --json` for the
section and field (opens nothing), takes the vault and item ids from secrets.bindings.toml,
reads the field with `op read --no-newline` into memory, and compares SHA-256 with the
canary the generator wrote. It prints `<env> <KEY>: match|differ|unreadable`, never a value.
Run it in the person's shell (the owner's own `op` session), not the CI-like shell.

Uncertain (record it if it shows): whether `op read` returns a field's trailing newline.
A `differ` on DATABASE_URL or DATABASE_URL_UNPOOLED only is that question, not a seeding
error; A4-V8 then shows what opv actually delivers.
"""
import hashlib
import json
import os
import subprocess
import sys
import tomllib

opv, project, canary, envs = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
cfg = tomllib.load(open(os.path.join(project, "secrets.toml"), "rb"))
bind = tomllib.load(open(os.path.join(project, "secrets.bindings.toml"), "rb"))


def canary_values(env):
    name = {"verify-nofsgroup": "verify", "verify": "verify", "verify-fly": "verify-fly", "dev": "dev"}[env]
    vals = {}
    with open(os.path.join(canary, "values", f"{name}.env"), "rb") as f:
        for line in f.read().decode().splitlines():
            k, _, v = line.partition("=")
            vals[k] = v.encode()
    ml = os.path.join(canary, "values", "multiline")
    for k in os.listdir(ml):
        vals.setdefault(k, open(os.path.join(ml, k), "rb").read())
    return vals


bad = 0
for env in envs:
    vals = canary_values(env)
    b = bind["environments"][env]["boundaries"]["journeeze"]
    for key, spec in sorted(cfg["products"]["journeeze"]["keys"].items()):
        if env not in spec.get("environments", []):
            continue
        o = subprocess.run([opv, "open", f"journeeze/{key}", "--env", env, "--json",
                            "--config", os.path.join(project, "secrets.toml")],
                           capture_output=True, text=True)
        try:
            doc = json.loads(o.stdout)
            sec, field = doc.get("section"), doc["field"]
        except (ValueError, KeyError):
            print(f"{env} {key}: unreadable (opv open exit {o.returncode})")
            bad += 1
            continue
        ref = f"op://{b['vault_id']}/{b['item_id']}/" + (f"{sec}/{field}" if sec else field)
        r = subprocess.run(["op", "read", "--no-newline", ref], capture_output=True)
        if r.returncode != 0:
            verdict = f"unreadable (op exit {r.returncode})"
        elif hashlib.sha256(r.stdout).digest() == hashlib.sha256(vals[key]).digest():
            verdict = "match"
        else:
            verdict = "differ"
        bad += verdict != "match"
        print(f"{env} {key}: {verdict}")
        r = None  # drop the bytes
print("seed-check:", "ok" if bad == 0 else f"{bad} not matching")
sys.exit(0 if bad == 0 else 1)
