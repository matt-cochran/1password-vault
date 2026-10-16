#!/usr/bin/env python3
"""Opt-in Claude Code SessionStart adapter for opv's read-only receipt."""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading

LIMIT = 65536


def emit(message):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "SessionStart", "additionalContext": message}}))


def capture(command, cwd, timeout):
    # No shell, interactive stdin, stderr forwarding, receipt file, or transcript read.
    process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    result = bytearray()
    overflow = threading.Event()

    def read():
        while chunk := process.stdout.read(4096):
            if len(result) + len(chunk) > LIMIT:
                overflow.set()
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break
            result.extend(chunk)

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        process.wait(timeout=timeout)
        reader.join(timeout=max(0.1, timeout))
        if reader.is_alive() or overflow.is_set() or process.returncode != 0:
            raise ValueError("unavailable")
        return bytes(result)
    finally:
        # Also stop descendants left holding stdout after their parent exits.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        reader.join(timeout=1)
        process.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env", required=True)
    parser.add_argument("--opv", default="opv", help="Trusted installed opv executable")
    parser.add_argument("--timeout", type=float, default=5)
    args = parser.parse_args()
    if os.name != "posix":
        emit("opv readiness hook is supported on macOS/Linux only; run opv ready manually.")
        return
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", args.env) or not 0 < args.timeout <= 10:
        emit("opv readiness hook configuration is invalid; review its environment and timeout.")
        return
    try:
        raw = sys.stdin.buffer.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError("oversized event")
        event = json.loads(raw)
        if not isinstance(event, dict) or event.get("hook_event_name") != "SessionStart":
            return
        cwd = event.get("cwd")
        if not isinstance(cwd, str) or not os.path.isabs(cwd) or not os.path.isdir(cwd):
            raise ValueError("invalid cwd")
        doc = json.loads(capture([args.opv, "ready", args.env, "--json"], cwd, args.timeout))
        # The readiness receipt has the same fields in schema 1 (opv 0.9) and 2 (opv 0.10).
        if not isinstance(doc, dict) or type(doc.get("schema_version")) is not int or doc["schema_version"] not in (1, 2):
            raise ValueError("unsupported receipt")
        findings = doc.get("findings")
        matrix = doc.get("matrix")
        if not isinstance(findings, list) or not isinstance(matrix, list) or not matrix:
            raise ValueError("incomplete receipt")
        if any(not isinstance(f, dict) or type(f.get("blocking")) is not bool for f in findings):
            raise ValueError("invalid findings")
        if any(not isinstance(m, dict) or m.get("environment") != args.env for m in matrix):
            raise ValueError("wrong environment")
        blocking = sum(f["blocking"] for f in findings)
        state = (f"{blocking} blocking finding(s)" if blocking else
                 "no blocking findings in the receipt")
        emit(f"opv readiness for {args.env}: {state}. "
             f"Use opv ready {args.env} --json for current details before configuration-dependent work. "
             "Follow opv guide agent. Owner authentication and secret entry require the human; "
             "do not print secrets or automatically repair, sync, or deploy. "
             "This session-start snapshot is advisory, not execution authorization or a security boundary.")
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        emit("opv readiness could not be confirmed. Run opv ready manually in the project "
             "and let the owner handle authentication if required. "
             "No raw command output was forwarded. This advisory hook does not block the session.")


if __name__ == "__main__":
    main()
