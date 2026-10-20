"""Capture opv's MCP delivery preview for the canary scan (A4-V16 channel "mcp").

    python3 -I mcp-preview.py <opv binary> <project dir> <env> <product> <out.json>

Starts `opv mcp serve --project <dir>` over stdio, initializes, calls `opv_state` with
`section = delivery_preview` (docs/mcp.md), and writes the raw JSON-RPC replies (tools/list
and the call) to <out.json>. It prints only whether the call returned a result or an error.
The preview reads no value by construction; this capture is what the scan checks.
"""
import json
import queue
import subprocess
import sys
import threading

opv, project, env, product, out = sys.argv[1:6]
proc = subprocess.Popen([opv, "mcp", "serve", "--project", project],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True)
msgs = queue.Queue()
threading.Thread(target=lambda: [msgs.put(json.loads(l)) for l in proc.stdout], daemon=True).start()
errs = []
threading.Thread(target=lambda: errs.extend(proc.stderr), daemon=True).start()


def send(method, params, rid=None):
    m = {"jsonrpc": "2.0", "method": method, "params": params}
    if rid is not None:
        m["id"] = rid
    proc.stdin.write(json.dumps(m) + "\n")
    proc.stdin.flush()
    if rid is None:
        return None
    while True:
        r = msgs.get(timeout=60)
        if r.get("id") == rid:
            return r


replies = {}
try:
    replies["initialize"] = send("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                                "clientInfo": {"name": "opv-136-live", "version": "1"}}, 1)
    send("notifications/initialized", {})
    replies["tools/list"] = send("tools/list", {}, 2)
    replies["delivery_preview"] = send("tools/call", {"name": "opv_state", "arguments": {
        "section": "delivery_preview", "env": env, "product": product}}, 3)
finally:
    proc.stdin.close()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
replies["stderr"] = "".join(errs)
with open(out, "w") as f:
    json.dump(replies, f, indent=2)
r = replies["delivery_preview"]
print("delivery_preview:", "result" if "result" in r else "error",
      "isError=" + str(r.get("result", {}).get("isError")))
