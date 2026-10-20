#!/usr/bin/env python3
"""Canary generator for the opv 0.13.0 live checks (A4, A5 of #136).

Makes clearly fake values, every one carrying a unique run prefix `opvcanary<8 hex>`,
and writes them, with their SHA-256 expectations and the scan patterns, into a private
directory on a RAM filesystem. It never reads, copies or derives anything from a real
secret, and it refuses to write anywhere that is not tmpfs or that is inside a git work
tree, so a canary file can't be committed by accident.

Run it with `python3 -I`:

    python3 -I gen-canary.py --out "$XDG_RUNTIME_DIR/opv-canary"       # new run
    python3 -I gen-canary.py --self-test                                # no files written

It prints the run id (8 hex digits) and the file list, never a value or the prefix: the
prefix is the scan's needle, and printing it would put a hit in the transcript.

Output (directory 0700, files 0600):
    run                          the run id (8 hex), nothing else
    values/verify.env            single-line keys, KEY=value, for `opv import verify`
    values/verify-fly.env        the Fly-leg keys (single-line only), for `opv import verify-fly`
    values/dev.env               same values as verify.env, for `opv import dev`
    values/multiline/<KEY>       raw bytes of the multi-line / trailing-newline keys
    values/rotate/rotate.env     GITHUB_WEBHOOK_SECRET=<the V10 replacement>, for `opv import`
    a5/file-v1.raw, a5/file-v2.raw        the A5 file content (binary-safe bytes)
    a5/import-v1, a5/import-v2            `OPVCANARY_A5_FILE=<base64>` for `fly secrets import`
    expect/expect.txt            `<destination> <sha256>` lines for the consumer (no value)
    expect/expect-rotated.txt    the same after V10
    expect/a5.txt                `file-v1 <sha256>`, `file-v2 <sha256>`
    patterns.txt                 the scan needles (the prefix, base64 forms); stays here
"""
import argparse
import base64
import hashlib
import os
import secrets
import stat
import subprocess
import sys

# Journeeze's mapping (docs/design/delivery-transports.md §4.6): key -> (destination, role).
SERVE = [
    ("DATABASE_URL", "database/url"),
    ("GITHUB_APP_PRIVATE_KEY", "github-app/private-key"),
    ("GITHUB_WEBHOOK_SECRET", "github/webhook-secret"),
    ("TYPESAFE_JEV_API_KEY", "jev/api-key"),
    ("BLOB_ACCESS_KEY_ID", "blob/access-key-id"),
    ("BLOB_SECRET_ACCESS_KEY", "blob/secret-access-key"),
    ("GUIDE_ASSET_SIGNING_KEY", "guide-assets/signing-key"),
    ("OTEL_EXPORTER_OTLP_ENDPOINT", "otel/endpoint"),
    ("OTEL_EXPORTER_OTLP_HEADERS", "otel/headers"),
]
MIGRATE = [
    ("DATABASE_URL_UNPOOLED", "database/owner-url"),
    ("JOURNEEZE_APP_PASSWORD", "database/app-password"),
]
# Keys the Fly leg (environment verify-fly) does not carry: their values are multi-line or
# end in a newline, which a Fly variable can't hold verbatim (§4.5 change 4).
NOT_ON_FLY = {"DATABASE_URL", "GITHUB_APP_PRIVATE_KEY", "DATABASE_URL_UNPOOLED"}
STATIC_NEEDLE = "opvcanary"


def values(p):
    """Every value contains the prefix `p`; hosts use the reserved `.invalid` TLD."""
    return {
        "DATABASE_URL": f"postgres://{p}-user:{p}-pw@db.invalid:5432/{p}\n",
        "GITHUB_APP_PRIVATE_KEY": (
            "-----BEGIN OPV CANARY NOT A KEY-----\n"
            f"{p}LINE1\n{p}LINE2\n"
            "-----END OPV CANARY NOT A KEY-----\n"
        ),
        # Journeeze's rule for the real key is [A-Za-z0-9]{32,256}; keep the canary inside it.
        "GITHUB_WEBHOOK_SECRET": f"{p}webhook{p}",
        "TYPESAFE_JEV_API_KEY": f"{p}-jev",
        "BLOB_ACCESS_KEY_ID": f"{p}-blob-id",
        "BLOB_SECRET_ACCESS_KEY": f"{p}-blob-secret",
        "GUIDE_ASSET_SIGNING_KEY": f"{p}-guide",
        "OTEL_EXPORTER_OTLP_ENDPOINT": f"https://{p}.otel.invalid",
        "OTEL_EXPORTER_OTLP_HEADERS": f"x-{p}=1",
        "DATABASE_URL_UNPOOLED": f"postgres://{p}-owner@db.invalid:5432/{p}\n",
        "JOURNEEZE_APP_PASSWORD": f"{p}-app-password",
        "LOG_LEVEL": f"{p}-log-level",
    }


def rotated_webhook(p):
    return f"{p}webhook2{p}"


def a5_file(p, version):
    """Binary-safe content: CRLF, a NUL, 0xFE/0xFF and trailing spaces, so F3 shows any
    decode or newline change. Never valid UTF-8, on purpose."""
    return (
        f"OPV CANARY FILE v{version} {p}\n-----BEGIN OPV CANARY-----\n{p}\r\n".encode()
        + b"\x00\x01\xfe\xff"
        + f"  {p}-end-v{version}  \n".encode()
    )


def b64_forms(data: bytes):
    """base64 (standard and URL-safe, padding dropped) of the data itself."""
    out = set()
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        out.add(enc(data).decode().rstrip("="))
    return out


def offset_forms(needle: str):
    """base64 of the needle at byte offsets 0, 1, 2 inside a longer value: the characters
    that depend only on the needle (the prefix and the tail are dropped). Long enough to be
    specific (>= 8 characters)."""
    out = set()
    nb = needle.encode()
    for off in range(3):
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            b = enc(b"\0" * off + nb + b"\0\0\0").decode()
            start = 0 if off == 0 else (4 * ((off + 2) // 3))  # first group fully inside
            # stop before any group that also holds bytes after the needle
            end = 4 * ((off + len(nb)) // 3)
            s = b[start:end]
            if len(s) >= 8:
                out.add(s)
    return out


def patterns(p, vals):
    pats = {p}
    pats |= offset_forms(p)
    for v in list(vals.values()) + [rotated_webhook(p)]:
        pats |= b64_forms(v.encode())
    for ver in (1, 2):
        raw = a5_file(p, ver)
        pats |= b64_forms(raw)
        pats |= b64_forms(f"OPVCANARY_A5_FILE={base64.b64encode(raw).decode()}".encode())
    return sorted(x for x in pats if len(x) >= 8)


def fs_type(path):
    """The filesystem type holding `path`, from the longest matching /proc/self/mounts entry."""
    path = os.path.realpath(path)
    best, kind = "", "unknown"
    with open("/proc/self/mounts") as f:
        for line in f:
            parts = line.split()
            mnt = parts[1].replace("\\040", " ")
            if (path == mnt or path.startswith(mnt.rstrip("/") + "/")) and len(mnt) >= len(best):
                best, kind = mnt, parts[2]
    return kind


def in_git_tree(path):
    try:
        r = subprocess.run(
            ["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=10,
        )
        return r.returncode == 0 and r.stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def write(path, data: bytes):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def sha(b: bytes):
    return hashlib.sha256(b).hexdigest()


def expect_lines(p, vals, webhook):
    lines = [f"needle_hex {p.encode().hex()}"]
    for key, dest in SERVE + MIGRATE:
        v = webhook if key == "GITHUB_WEBHOOK_SECRET" else vals[key]
        lines.append(f"{dest} {sha(v.encode())}")
    lines.append(f"LOG_LEVEL {sha(vals['LOG_LEVEL'].encode())}")
    return ("\n".join(lines) + "\n").encode()


def self_test():
    p = STATIC_NEEDLE + "0123abcd"
    vals = values(p)
    pats = patterns(p, vals)
    assert all(p in v for v in vals.values()), "a value lacks the prefix"
    assert p in rotated_webhook(p)
    for host in ("db.invalid", "otel.invalid"):
        assert any(host in v for v in vals.values())
    # The webhook canary stays inside Journeeze's real rule [A-Za-z0-9]{32,256}.
    w = vals["GITHUB_WEBHOOK_SECRET"]
    assert w.isalnum() and 32 <= len(w) <= 256
    # Every needle is found in the plain value and in base64 of the value at any offset.
    for v in list(vals.values()) + [a5_file(p, 1).decode("latin-1")]:
        raw = v.encode("latin-1") if isinstance(v, str) else v
        for off in range(3):
            blob = b"x" * off + raw
            hay = blob.decode("latin-1") + "\n" + base64.b64encode(blob).decode() + "\n" + \
                base64.urlsafe_b64encode(blob).decode()
            assert any(x in hay for x in pats), f"no pattern hits offset {off}"
    # The prefix inside a longer base64 blob (a Secret's data, a Fly import line).
    for off in range(3):
        blob = os.urandom(5 + off) + p.encode() + os.urandom(7)
        assert any(x in base64.b64encode(blob).decode() for x in pats), off
    # No pattern hits ordinary text or the scan's own command lines.
    clean = "\n".join([
        "opv sync verify --deploy --expect-plan 1b2c3d4e", "OPVCANARY__JOURNEEZE__LOG_LEVEL",
        "FLEET__JOURNEEZE__GITHUB_WEBHOOK_SECRET", "grep -c -F -f patterns.txt",
        base64.b64encode(os.urandom(4096)).decode(),
    ])
    hits = [x for x in pats if x in clean]
    assert not hits, f"false positive: {len(hits)} pattern(s)"
    print(f"self-test ok: {len(pats)} patterns")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", help="a new directory on tmpfs, outside any git work tree")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        self_test()
        return
    if not a.out:
        ap.error("--out is required (or --self-test)")
    out = os.path.abspath(a.out)
    parent = os.path.dirname(out)
    if fs_type(parent) != "tmpfs":
        sys.exit(f"refused: {parent} is not on tmpfs (use $XDG_RUNTIME_DIR)")
    if in_git_tree(parent):
        sys.exit(f"refused: {parent} is inside a git work tree")
    os.umask(0o077)
    os.mkdir(out, 0o700)  # fails if it exists: one directory per run
    run = secrets.token_hex(4)
    p = STATIC_NEEDLE + run
    vals = values(p)
    for d in ("values", "values/multiline", "values/rotate", "a5", "expect"):
        os.mkdir(os.path.join(out, d), 0o700)
    write(os.path.join(out, "run"), (run + "\n").encode())

    def env_file(keys):
        lines = [f"{k}={vals[k]}" for k in keys]
        for line in lines:
            assert "\n" not in line and p in line
        return ("\n".join(lines) + "\n").encode()

    single = [k for k in vals if "\n" not in vals[k]]
    write(os.path.join(out, "values/verify.env"), env_file(single))
    write(os.path.join(out, "values/dev.env"), env_file(single))
    fly_keys = [k for k, _ in SERVE if k not in NOT_ON_FLY] + ["LOG_LEVEL"]
    write(os.path.join(out, "values/verify-fly.env"), env_file(fly_keys))
    for k in vals:
        if "\n" in vals[k]:
            write(os.path.join(out, "values/multiline", k), vals[k].encode())
    write(os.path.join(out, "values/rotate/rotate.env"),
          f"GITHUB_WEBHOOK_SECRET={rotated_webhook(p)}\n".encode())
    write(os.path.join(out, "expect/expect.txt"), expect_lines(p, vals, vals["GITHUB_WEBHOOK_SECRET"]))
    write(os.path.join(out, "expect/expect-rotated.txt"), expect_lines(p, vals, rotated_webhook(p)))
    a5 = []
    for ver in (1, 2):
        raw = a5_file(p, ver)
        write(os.path.join(out, f"a5/file-v{ver}.raw"), raw)
        write(os.path.join(out, f"a5/import-v{ver}"),
              f"OPVCANARY_A5_FILE={base64.b64encode(raw).decode()}\n".encode())
        a5.append(f"file-v{ver} {sha(raw)}")
    write(os.path.join(out, "expect/a5.txt"), ("\n".join(a5) + "\n").encode())
    pats = patterns(p, vals)
    write(os.path.join(out, "patterns.txt"), ("\n".join(pats) + "\n").encode())
    print(f"run {run}")
    print(f"{len(pats)} patterns; files under the output directory:")
    for root, _, files in sorted(os.walk(out)):
        for f in sorted(files):
            st = os.stat(os.path.join(root, f))
            print(f"  {oct(stat.S_IMODE(st.st_mode))} {os.path.relpath(os.path.join(root, f), out)}")


if __name__ == "__main__":
    main()
