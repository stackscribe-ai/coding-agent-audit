"""Known indicators of compromise (IOCs) for publicly documented AI-coding-
assistant supply-chain incidents.

Source for the 2026-10 Open-VSX "svc-telemetry" Claude Code extension
trojan: public incident write-up (doublepulsar.com, "Anthropic hacked to
deliver remote access trojan to Claude developer laptops worldwide") and the
independent community audit script published on dev.to by @slabb
("A trojanized Claude Code extension plants an SSH backdoor: the 7-point
audit for your machine"). This module re-implements those *publicly
documented* indicators from scratch in Python; it does not copy code from
either source. New incidents can be added here as new dict entries without
touching the check logic in checks.py.
"""

from __future__ import annotations

INCIDENTS = {
    "openvsx-claude-code-2026-10": {
        "name": "Trojanized Claude Code extension on Open-VSX / Cursor Marketplace (Oct 2026)",
        "description": (
            "anthropic.claude-code@2.1.313, distributed via both Open-VSX "
            "and the Cursor Marketplace, had a malicious loader prepended "
            "to extension.js. It added an SSH key, tried to enable remote "
            "login, opened a reverse SSH tunnel to a C2 server, beaconed "
            "basic host recon, and installed OS-specific persistence "
            "(macOS LaunchAgent, Linux cron @reboot entry, Windows "
            "scheduled task / Startup-folder script)."
        ),
        "references": [
            "https://doublepulsar.com/anthropic-hacked-to-deliver-remote-access-trojan-to-claude-developer-laptops-worldwide-1148a92baae2",
            "https://dev.to/slabb/a-trojanized-claude-code-extension-plants-an-ssh-backdoor-the-7-point-audit-for-your-machine-23cj",
            "https://phorion.io/blog/offical-claude-code-vsx-compromise/",
        ],
        # SSH public key comment appended to ~/.ssh/authorized_keys
        "ssh_key_comment": "svc-telemetry",
        # SHA-256 of the trojanized extension.js
        "extension_sha256": "ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15",
        # SSH host key fingerprint of the C2 server
        "c2_ssh_fingerprint": "SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk",
        "c2_hosts": ["134.209.82.225"],
        "c2_ports": [22, 8099],
        # Marker / persistence file names observed on infected hosts
        "macos_launch_agent": "com.apple.sysmond.plist",
        "marker_filenames": [".smt", ".smtk", "smt.cmd", "smtk"],
        "tmp_tunnel_glob": ".stk_*",
        "linux_cron_marker": "SysMon",
        "windows_task_name": "SysMon",
        # Startup-folder fallback used on Windows when creating the SYSTEM
        # scheduled task fails (relative to %APPDATA%)
        "windows_startup_relpath": (
            "Microsoft/Windows/Start Menu/Programs/Startup/sysmon.cmd"
        ),
    },
    "embrace-embedded-browser-2026-10": {
        "name": "EMBRACE embedded-browser flaws in AI coding assistants (Forever Security, Oct 2026)",
        "description": (
            "Forever Security's EMBRACE research (published 2026-10-29) found "
            "that five AI coding tools grant their embedded preview/agent "
            "browser the same filesystem trust as the IDE itself: code "
            "execution in Cursor, address-bar spoofing in GitHub Copilot, "
            "and arbitrary local-file read (SSH keys, .env files, npm "
            "tokens) in OpenAI Codex, VS Code and Claude Desktop, triggered "
            "by a single HTML page opened in the tool's internal browser. "
            "Cursor was fixed 2026-10-01 and GitHub Copilot in extension "
            "version 1.1.29 (2026-10-13); Codex and VS Code were still "
            "unpatched as of 2026-11-02, and Claude Desktop's status was "
            "not confirmed by the researchers."
        ),
        "references": [
            "https://www.helpnetsecurity.com/2026/10/29/research-ai-assistant-browser-vulnerabilities/",
            "https://www.theregister.com/security/2026/10/29/researchers_find_bugs_in_5_ai_developer_tools_with_openai_and_microsoft_flaws_still_unpatched/5306508",
            "https://hackread.com/embrace-flaws-ai-coding-tools-code-execution-theft/",
        ],
        # GitHub Copilot extension version that ships the address-bar-spoofing fix.
        "copilot_patched_version": (1, 1, 29),
        # As of the references above; re-check before treating as current.
        "unpatched_products": ["OpenAI Codex", "VS Code"],
    },
    "mini-shai-hulud-gh-token-monitor-2026": {
        "name": "Mini Shai-Hulud npm worm, gh-token-monitor persistence (2026)",
        "description": (
            "A self-propagating npm supply-chain worm (tracked by several "
            "vendors as Mini Shai-Hulud) that runs from a compromised "
            "package's install script, drops an obfuscated Bun payload "
            "(.claude/router_runtime.js, .claude/setup.mjs) in the "
            "repo it's invoked in, and writes a SessionStart hook into "
            "that repo's .claude/settings.json so the payload re-executes "
            "every time Claude Code opens the project; a matching "
            ".vscode/tasks.json folderOpen task does the same for VS Code. "
            "On the host it also installs an OS-level persistence service "
            "named gh-token-monitor (a systemd user service on Linux, a "
            "LaunchAgent on macOS) that harvests GitHub/npm/cloud "
            "credentials and, per a documented dead-man's switch, runs "
            "`rm -rf ~` if the stolen GitHub token is revoked before the "
            "service is removed."
        ),
        "references": [
            "https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem",
            "https://www.mend.io/blog/shai-hulud-sap-cap-supply-chain-attack-claude-code/",
            "https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised",
        ],
        "linux_systemd_relpath": ".config/systemd/user/gh-token-monitor.service",
        "macos_launch_agent": "com.user.gh-token-monitor.plist",
        "project_marker_files": [
            ".claude/router_runtime.js",
            ".claude/setup.mjs",
            ".vscode/setup.mjs",
        ],
    },
    "sandworm-mode-npm-2026-11": {
        "name": "SANDWORM_MODE npm supply-chain worm, rogue MCP server (Nov 2026)",
        "description": (
            "A self-propagating npm supply-chain worm (SANDWORM_MODE), "
            "distributed via 19 typosquatted packages published under the "
            "'official334' and 'javaorg' npm aliases (e.g. suport-color, a "
            "typosquat of supports-color). Its install script drops a "
            "hidden directory, ~/.dev-utils/, containing a rogue local MCP "
            "server and registers it with Claude Code, Cursor, Windsurf "
            "and Continue under three innocuous-sounding tool names "
            "(index_project, lint_check, scan_dependencies) so the AI "
            "assistant itself ends up invoking it; the server then reads "
            "SSH keys, AWS credentials and password-manager secrets, "
            "installs Git-hooks persistence, and propagates by publishing "
            "further typosquatted packages."
        ),
        "references": [
            "https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning",
            "https://www.endorlabs.com/learn/sandworm-mode-dissecting-a-multi-stage-npm-supply-chain-attack",
            "https://www.securityweek.com/new-sandworm_mode-supply-chain-attack-hits-npm/",
        ],
        "hidden_dir": ".dev-utils",
        "rogue_tool_names": ["index_project", "lint_check", "scan_dependencies"],
        "typosquat_aliases": ["official334", "javaorg"],
    },
}
