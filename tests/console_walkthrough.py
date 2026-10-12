"""Actual console walkthrough; fake vendor only, no real accounts or credentials."""
import json
import os
import pathlib
import pty
import select
import sys
import tempfile
import termios
import time

with tempfile.TemporaryDirectory() as tmp:
    root = pathlib.Path(tmp)
    vendor = root / "op"
    vendor.write_text("""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
store = Path(os.environ["OPV_TEST_STORE"])
if args == ["--version"]:
    print("2.40.0")
elif args[:2] == ["vault", "list"]:
    print(json.dumps([{"id":"vault-id","name":"Development"}]))
elif args[:2] == ["item", "list"]:
    print(json.dumps([{"id":"item-id","title":"api"}] if store.exists() else []))
elif args[:2] == ["item", "get"]:
    print(store.read_text())
elif args[:2] == ["item", "create"]:
    doc = json.load(sys.stdin)
    doc["id"] = "item-id"
    store.write_text(json.dumps(doc))
    print(json.dumps(doc))
else:
    sys.exit(91)
""")
    vendor.chmod(0o700)
    (root / "opv.setup.toml").write_text(
        "title='Local example'\nenvironment='dev'\nvault='Development'\nitem='api'\n"
        "[[fields]]\nkey='API_KEY'\ntitle='Provider login'\n"
        "description='Lets this API call its provider.'\nsource='Provider dashboard.'\n"
    )
    env = os.environ.copy()
    for name in list(env):
        if name.startswith("OP_SESSION") or name in ("CI", "GITHUB_ACTIONS", "OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN"):
            env.pop(name)
    env["PATH"] = str(root) + os.pathsep + env["PATH"]
    env["OPV_TEST_STORE"] = str(root / "fake-item.json")

    def walkthrough(resume=False):
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(root)
            os.execve(sys.argv[1], [sys.argv[1], "setup"], env)
        transcript = bytearray()
        sent_value = sent_save = False
        deadline = time.monotonic() + 20
        status = None
        try:
            while time.monotonic() < deadline:
                if select.select([fd], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(fd, 4096)
                    except OSError:
                        chunk = b""
                    if chunk:
                        transcript.extend(chunk)
                    text = transcript.decode(errors="replace")
                    if not resume and not sent_save and "[y/N]" in text:
                        os.write(fd, b"y\n")
                        sent_save = True
                # Prompt output can arrive before the password reader changes the
                # terminal flags. Send input only once its hidden mode is active;
                # keep polling the flag even when no further output is produced.
                if not resume and not sent_value and b"Provider login (hidden; Enter to skip): " in transcript:
                    if not termios.tcgetattr(fd)[3] & termios.ECHO:
                        os.write(fd, b"synthetic-private-value\n")
                        sent_value = True
                done, child_status = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = child_status
                    break
            assert status is not None, "Console walkthrough timed out"
            assert os.waitstatus_to_exitcode(status) == 0, transcript.decode(errors="replace")
            assert b"synthetic-private-value" not in transcript, "Secret echoed by console"
            assert b"All settings are saved" in transcript
            if resume:
                assert b"[y/N]" not in transcript, "Resume asked for unnecessary save"
                assert b"existing value kept" in transcript
            else:
                assert sent_value and sent_save
                assert transcript.count(b"[y/N]") == 1
        finally:
            if status is None:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            os.close(fd)

    walkthrough()
    manifest = (root / "secrets.toml").read_text()
    assert "synthetic-private-value" not in manifest
    doc = json.loads((root / "fake-item.json").read_text())
    assert doc["fields"][0]["value"] == "synthetic-private-value"
    walkthrough(resume=True)

