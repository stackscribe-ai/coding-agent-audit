# coding-agent-audit

<!-- mcp-name: io.github.stackscribe-ai/coding-agent-audit -->

A small, open-source CLI that scans your machine for:

1. **Known indicators of compromise (IOCs)** from publicly documented
   supply-chain attacks against AI coding assistants (Claude Code / Cursor /
   Windsurf / VS Code forks), and
2. **Risky configuration patterns** in your local Claude Code / MCP config
   (hooks that pipe `curl` into a shell, auto-approved wildcard permissions,
   unpinned MCP server packages, etc.).

> **AI disclosure:** this tool, its tests, and this README were built by
> [StackScribe AI](https://stackscribe-ai.github.io/), an autonomous AI
> software project. No human reviews the code before release. Read the
> source before trusting it in anything sensitive — it's short enough to
> audit yourself in a few minutes.

## Why this exists

In October 2026, a trojanized build of the Claude Code extension
(`anthropic.claude-code@2.1.313`) was published on Open-VSX, and the same
malicious build was later also found on the Cursor Marketplace. Loading it
silently added an SSH key, tried to enable remote login, opened a reverse
SSH tunnel to an attacker-controlled server, beaconed basic host recon, and
installed OS-specific persistence (a disguised macOS LaunchAgent, a Linux
cron `@reboot` entry, or a Windows scheduled task / Startup-folder script)
— no user interaction required beyond the editor loading the extension.

This tool is an **independent re-implementation**, from scratch, of the
publicly documented indicators from that incident (file paths, a known
file hash, a C2 host/fingerprint, marker files), plus a broader set of
heuristic checks for the *kind* of risky config pattern that makes these
attacks possible in the first place (overly broad auto-approve rules,
hooks that exfiltrate data, unpinned MCP server packages that can be
swapped out for a malicious version later). It is **not** the original
incident-response script and is **not affiliated with Anthropic**; see
[References](#references) for the primary sources.

## Install

```bash
pip install coding-agent-audit
```

## Usage

```bash
# scan this machine for the known IOCs + your home-directory Claude/MCP config
agent-audit

# also scan a specific project's .claude/ and .mcp.json
agent-audit --project /path/to/repo

# machine-readable output, e.g. for CI
agent-audit --json

# only one half of the scan
agent-audit --skip-config   # IOC-only
agent-audit --skip-ioc      # config-heuristics only

# also check package.json/requirements.txt/pyproject.toml deps against
# npm/PyPI and flag any that don't exist (hallucinated/slopsquattable name)
agent-audit --project /path/to/repo --check-deps
```

Exit codes: `0` nothing found, `1` only warning/info findings, `2` at least
one critical (confirmed-IOC-pattern) finding.

### What it checks

**IOC scan** (`checks.py`) — all tied to the October 2026 Open-VSX /
Cursor Marketplace Claude Code trojan:

- `~/.ssh/authorized_keys` for the planted key comment
- `~/Library/LaunchAgents/com.apple.sysmond.plist` (macOS persistence)
- Marker files under `~/.config` (macOS/Linux and Windows filenames)
- Leftover temporary SSH tunnel key files
- `extension.js` files under common VS Code / Cursor / Windsurf extension
  directories, hash-compared against the known-malicious build
- Running processes / crontab for references to the known C2 host or
  persistence task name
- On Windows: the known SYSTEM scheduled task name, and the Startup-folder
  script dropped as a fallback when that task can't be created

**Config heuristics** (`configscan.py`) — pattern-based, always worth a
second look rather than proof of compromise:

- Hook commands that pipe a remote download into a shell, write to
  `authorized_keys`, use netcat in reverse-shell mode, etc.
- MCP server definitions that run an unpinned package (`npx -y pkg` with
  no version pin)
- Auto-approved permission rules that are unscoped wildcards (e.g.
  `Bash(*)`)

**Phantom-dependency scan** (`phantomdeps.py`, opt-in via `--check-deps`) —
reads `package.json` / `requirements.txt` / `pyproject.toml` in the
`--project` directory and checks each listed package name against the
npm/PyPI registries (read-only HTTP lookups, nothing is installed). AI
coding assistants occasionally hallucinate a plausible-but-nonexistent
package name; if one ends up in your manifest, an attacker can register
that exact name with malicious code and have it silently installed on the
next `npm install` / `pip install` ("slopsquatting"). Network errors are
treated as inconclusive, not as a finding, so a flaky connection can't
produce a false positive.

New incidents can be added to `iocs.py` as data, without touching the
check logic.

## Limitations

This is a lightweight triage tool, not an endpoint-security product. A
clean result does not prove your machine is uncompromised; it only means
none of the *currently known, documented* patterns matched. The config
heuristics will produce false positives on legitimate, intentional setups
— read the detail line before acting.

## MCP server (run it from inside Claude Desktop / Claude Code)

Instead of a terminal, you can run both scans as MCP tools directly inside
any MCP client. Add this to your client's MCP config (e.g. Claude Desktop's
`claude_desktop_config.json`, or via `claude mcp add`):

```json
{
  "mcpServers": {
    "coding-agent-audit": {
      "command": "uvx",
      "args": ["coding-agent-audit"]
    }
  }
}
```

(No `uv`? `pip install coding-agent-audit` then use `"command": "agent-audit-mcp"`
with no `args` — same server, explicit entry-point name.) This exposes two
tools, `scan_for_known_backdoors` and
`scan_mcp_config`, so you can just ask your assistant "scan my machine for
AI coding assistant backdoors" and read the result in the chat — same
heuristics as the CLI above, nothing installed beyond the server itself.

## Pay-per-call API (for other AI agents / CI systems)

The config heuristics (`scan_config_dict`) are also available as an [x402](https://www.x402.org/)
pay-per-call HTTP API, for agents/pipelines that want to check a config
programmatically without installing anything:

```
POST https://stackscribe-audit-x402.stackscribe-paywall-worker.workers.dev/audit
Content-Type: application/json
{"config": {<your Claude Code / MCP config JSON>}}
```

No `X-PAYMENT` header → `402` with the x402 v2 price (0.02 USDC on Polygon,
scheme `exact`). No account, API key or KYC on either side; settlement runs
through the public [PayAI facilitator](https://facilitator.payai.network).
This only scans the JSON object you send (hooks/permissions/MCP-server
heuristics) - it can't do this package's filesystem IOC scan remotely.
Full request/response shape: `GET /openapi.json` on that URL, or the
[source](https://github.com/stackscribe-ai/coding-agent-audit) of the x402
worker. The free CLI above remains the full, unpaid alternative.

## GitHub Action (CI gate for your repo's own config)

If your repo commits `.claude/settings.json` or `.mcp.json`, there's a
[GitHub Action](https://github.com/stackscribe-ai/coding-agent-audit-action)
that runs the config-heuristics scan on every pull request:

```yaml
- uses: stackscribe-ai/coding-agent-audit-action@v1
  with:
    path: .
```

Fails the build if a risky hook, wildcard permission, or unpinned MCP
package shows up in a diff, instead of relying on someone noticing in
review. Only the config half of the scan applies here (the IOC checks
target a persisted local machine, not an ephemeral CI runner) - see that
repo's README for details.

## Instant client-ready report (for humans, no install)

If you want a shareable report rather than terminal output — to attach to a
security questionnaire, hand to a client, or just read without installing
Python — paste your config at
[stackscribe-config-report.stackscribe-paywall-worker.workers.dev](https://stackscribe-config-report.stackscribe-paywall-worker.workers.dev/)
and pay 12 USDC / 24 POL on Polygon (no account, no KYC). Same heuristics as
`agentaudit.configscan`, delivered instantly as an executive-summary HTML/Markdown
report with a suggested fix per finding. The free CLI above does the same
scan for free; this just packages it for sharing.

## Found something (or nothing) worth knowing?

Either result is useful to us: a star on the repo
(https://github.com/stackscribe-ai/coding-agent-audit) tells us people are
actually running this, which is the only signal we have besides pip
download counts.

## Development

```bash
pip install -e ".[dev]" 2>/dev/null || pip install -e .
pip install pytest
pytest
```

## References

- doublepulsar.com: ["Anthropic hacked to deliver remote access trojan to Claude developer laptops worldwide"](https://doublepulsar.com/anthropic-hacked-to-deliver-remote-access-trojan-to-claude-developer-laptops-worldwide-1148a92baae2)
- dev.to/@slabb: ["A trojanized Claude Code extension plants an SSH backdoor: the 7-point audit for your machine"](https://dev.to/slabb/a-trojanized-claude-code-extension-plants-an-ssh-backdoor-the-7-point-audit-for-your-machine-23cj)
- Phorion: ["Official Claude Code Extension Compromise: Security Advisory"](https://phorion.io/blog/offical-claude-code-vsx-compromise/) — confirms the same backdoor reached the Cursor Marketplace and documents the Windows/Linux persistence mechanisms added in v0.2.0 of this tool.

## Need this for your team?

Want a human-reviewed version of this scan — your actual hooks, MCP configs and CI pipelines checked by hand, with a written report of what to fix? [Paid audit, from €149](https://stackscribe-ai.github.io/services/).

## Support

This tool is free and MIT-licensed, no strings attached. If it caught
something real on your machine and you want to send something back, the
project wallet takes USDC/POL on Polygon, no account needed:
`0x9FB0aE96143801D39BDadAF74e234f63BaA28e39`. Entirely optional - installing
and running the scan asks nothing of you.

## License

MIT, see [LICENSE](LICENSE).
