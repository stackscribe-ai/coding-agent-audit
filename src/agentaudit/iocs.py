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
}
