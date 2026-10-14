# Claude Code readiness hook (opt-in example)

This small SessionStart hook reuses `opv ready <environment> --json` once when
Claude Code starts or resumes. It adds a short readiness summary to the agent's
context. It does not match shell commands, block tools, or authorize work.

Use it alongside the existing opv agent skill. Readiness findings do not make
`opv ready` exit unsuccessfully: the adapter reads each finding's `blocking` flag.
It forwards counts only, not receipt messages, key names, IDs, or suggested commands.
The receipt is a snapshot; rerun readiness before configuration-dependent work.

## Install manually

Requires macOS/Linux, Python 3.8+, and a trusted installed opv supporting readiness
receipt schema 1. Keep this script in a trusted, absolute location outside the
project (for example `/home/you/.local/share/opv/ready-session.py`). This is an
example adapter, not an `opv` subcommand or an automatically installed feature.

Merge this entry into the chosen project's `.claude/settings.json`, preserving
existing settings and hooks. Replace both absolute paths and choose the project's
environment. Do not install globally unless you deliberately want checks in every
project. Project configuration is the opt-in; the hook does not create files.

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup|resume",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /home/you/.local/share/opv/ready-session.py --env dev --opv /home/you/.local/bin/opv",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
```

Quote paths containing spaces using your shell's normal quoting. Use trusted
absolute paths: a writable project should not supply the executable or adapter.
Review Claude Code's hook configuration before enabling it. Remove only this
entry to uninstall. No existing user or project configuration is changed by this
repository example.

## Behavior and limits

- Calls only `ready` with a positional environment and `--json`; no login, tidy,
  save, writes, repairs, sync, deploy, or transcript access.
- Uses the hook event's absolute `cwd`, direct subprocess arguments (no shell),
  closed stdin, a 5-second default subprocess deadline, and a 64 KiB output cap.
- Kills the subprocess group on failure/timeout. Raw stdout and stderr never
  enter agent context, including on malformed output or missing tools.
- Timeout, missing authentication/configuration, unsupported schema, and command
  failures give fixed guidance to check manually. The session continues.
- Existing readiness checks can internally read values through official tooling;
  the hook is not a claim that no secret is ever read. The JSON contract is
  names/IDs/codes only. It is not a sandbox, leak detector, or deployment guard.
- Closed stdin prevents terminal input through that stream; it does not guarantee
  that a vendor desktop application cannot display an authentication prompt.
  Authenticate manually first and verify behavior with your installed tools.
- Python buffers are not zeroizing. Never replace the readiness command with a
  secret-printing command. A compromised executable or machine is outside this
  adapter's guarantees.

## Verify without credentials

From this directory:

```sh
python3 -m unittest discover -p 'test_*.py' -v
```

Tests invoke the adapter as a real subprocess with disposable fake opv executables.
They cover ready and blocked receipts, nonblocking findings, exact argv, timeout,
output cap, malformed JSON, unsupported schema, and suppression of marker values.
No vendor tools, credentials, network, or model API are involved.

For a manual smoke check, send a SessionStart event with the project's absolute
`cwd` to this script. Use a disposable project and manually authenticate first.
Then enable the entry in Claude Code and start a new session to check the actual
host integration. Automated tests validate the adapter protocol, not a running
Claude Code session.

References: [Claude Code SessionStart](https://code.claude.com/docs/en/hooks#sessionstart)
and opv's [agent guide](../../docs/agent-setup.md).
