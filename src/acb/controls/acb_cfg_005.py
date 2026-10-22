"""ACB-CFG-005: Tool server tools are pre-approved by name, never server-wide."""

from __future__ import annotations

import re

from acb.extensions import rule_list, settings_by_client
from acb.model import Finding, Outcome

CONTROL_ID = "ACB-CFG-005"
_AUDIT = "tools-allowed-by-name"


def _check_tools_allowed_by_name(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for client, files in settings_by_client(ctx.inventory.agent_settings).items():
        profile = ctx.clients.profile(client)
        patterns = [re.compile(p) for p in profile.get("tool_server_allow_patterns", {}).get("patterns", [])]
        if not patterns or "allow_rules_key" not in profile.get("agent_settings", {}):
            anchor = ctx.relative(min(files, key=lambda s: s.scope != "project").path)
            findings.append(
                Finding(
                    CONTROL_ID,
                    _AUDIT,
                    Outcome.NOT_EVALUATED,
                    f"client {client} defines no allow rule forms for tool server tools",
                    anchor,
                )
            )
            continue
        for settings in files:
            for rule in rule_list(settings, profile, "allow_rules_key"):
                if any(p.search(rule.strip()) for p in patterns):
                    findings.append(
                        Finding(
                            CONTROL_ID,
                            _AUDIT,
                            Outcome.FAIL,
                            f"allow rule {rule.strip()!r} approves tools the server adds later; name each tool",
                            ctx.relative(settings.path),
                        )
                    )
    return findings


AUDITS = {
    _AUDIT: _check_tools_allowed_by_name,
}
