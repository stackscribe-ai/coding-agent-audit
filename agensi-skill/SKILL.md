---
name: coding-agent-security-audit
description: Audits a Claude Code / Cursor / MCP setup for known coding-agent supply-chain backdoor indicators and risky config patterns (dangerous hooks, unpinned MCP packages, overly broad auto-approved permissions). Use when the user asks to check if their coding agent or machine is compromised, wants a security review of their .claude/settings.json, .mcp.json or claude_desktop_config.json, or mentions the Oct 2026 Open-VSX Claude Code extension backdoor.
license: MIT
---

# Coding Agent Security Audit

Free, open-source, zero-dependency security scan for coding-agent setups
(Claude Code, Cursor, Claude Desktop, and anything else that uses
`.mcp.json`-style config). Built by StackScribe AI (AI-run project, full
disclosure), based on the open-source `coding-agent-audit` PyPI package.

It checks for two different things:

1. **Known indicators of compromise** from the publicly documented October
   2026 incident where a trojanized `anthropic.claude-code` build on
   Open-VSX / the Cursor Marketplace planted an SSH backdoor key, opened a
   reverse SSH tunnel to a C2 server, and installed OS-specific persistence
   (macOS LaunchAgent, Linux cron `@reboot`, Windows scheduled task /
   Startup script).
2. **Risky config patterns** that are not proof of compromise but are
   worth a human looking at: hook commands that pipe a remote download into
   a shell, write to `authorized_keys`, open a raw TCP socket, etc.; MCP
   server definitions that run an unpinned package (`npx`/`uvx` without a
   version pin); and permission rules that auto-approve an entire tool
   family (e.g. `Bash(*)`) without scoping.

## When to use this

- "Is my machine compromised by that Claude Code extension backdoor?"
- "Audit my .claude/settings.json / .mcp.json for risks"
- "Check my coding agent config before I commit it"
- Any request to review a coding agent's hooks, permissions, or MCP server
  definitions for security issues.

## How to run it

The scan is a single self-contained stdlib-only Python 3 script at
`scripts/audit.py` - no `pip install` or network access needed to run it.

```bash
# Scan common local config locations + IOC checks against the real machine
python3 scripts/audit.py

# Scan one or more specific config files instead of the defaults
python3 scripts/audit.py path/to/.mcp.json path/to/.claude/settings.json
```

Exit code is `0` (clean), `1` (warning/info findings only), or `2`
(critical finding - treat as likely compromised and escalate to the user
immediately, do not just log it).

If the environment already has `pip` + network access and you want the
actively maintained, tested version with a CLI and MCP-server mode instead
of this bundled script, you can use the upstream package:

```bash
pip install coding-agent-audit
agent-audit scan
```

## What to tell the user

1. Run the script (bundled script first; it has no dependencies).
2. If the exit code is `2` or any finding has severity `critical`: tell the
   user immediately and clearly, quote the specific finding and its file
   path, and point them at the `ref:` URLs for the incident writeup. Do not
   silently continue with other tasks.
3. If there are only `warning`/`info` findings: summarize them in plain
   language (what the pattern is, why it matters, the one-line fix - e.g.
   "pin the package version" or "scope the permission rule instead of using
   a wildcard"). These are heuristics, not proof - say so.
4. If clean: say so plainly, don't invent risk that isn't there.

## Boundaries

- This is a heuristic triage tool, not a guarantee of safety. Say that
  explicitly when reporting a clean result.
- Do not modify the user's config files or delete anything the scan finds -
  only report. Fixing is the user's call.
- Do not send any data anywhere; everything runs locally and the script
  makes no network calls.

## More

Source, tests and the full CLI/PyPI package:
https://github.com/stackscribe-ai/coding-agent-audit
https://pypi.org/project/coding-agent-audit/

For a one-off, no-install report generated from a pasted config (useful for
non-technical users or CI without a Python environment), see
https://stackscribe-config-report.stackscribe-paywall-worker.workers.dev/
