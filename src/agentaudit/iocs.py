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
        "name": "Trojanized Claude Code extension on Open-VSX (Oct 2026)",
        "description": (
            "anthropic.claude-code@2.1.313 published on Open-VSX had a "
            "66-line malicious loader prepended to extension.js. It added "
            "an SSH key, enabled remote login, opened a reverse SSH tunnel "
            "to a C2 server, and installed persistence disguised as a "
            "system daemon."
        ),
        "references": [
            "https://doublepulsar.com/anthropic-hacked-to-deliver-remote-access-trojan-to-claude-developer-laptops-worldwide-1148a92baae2",
            "https://dev.to/slabb/a-trojanized-claude-code-extension-plants-an-ssh-backdoor-the-7-point-audit-for-your-machine-23cj",
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
        "marker_filenames": [".smt", ".smtk", "smt.cmd"],
        "tmp_tunnel_glob": ".stk_*",
        "linux_cron_marker": "SysMon",
        "windows_task_name": "SysMon",
    }
}
