"""ACB-CFG-001: The agent cannot modify its own configuration, extensions or instructions."""

from __future__ import annotations

from acb.extensions import missing_rule_groups, settings_by_client
from acb.model import Finding, Outcome

CONTROL_ID = "ACB-CFG-001"
_AUDIT = "self-protection-rules"


def _check_self_protection_rules(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for client, files in settings_by_client(ctx.inventory.agent_settings).items():
        # Deny lists combine across settings scopes, so the requirement holds for the files together.
        anchor = ctx.relative(sorted(files, key=lambda s: s.scope != "project")[0].path)
        missing = missing_rule_groups(files, ctx.clients.profile(client), "self_protection_rules")
        if missing is None:
            findings.append(
                Finding(CONTROL_ID, _AUDIT, Outcome.NOT_EVALUATED, f"client {client} defines no self-protection rules", anchor)
            )
            continue
        for group in missing:
            findings.append(
                Finding(
                    CONTROL_ID,
                    _AUDIT,
                    Outcome.FAIL,
                    f"no deny rule protects the {group['target']}; add one of: {', '.join(group['any_of'])}",
                    anchor,
                )
            )
    return findings


AUDITS = {
    _AUDIT: _check_self_protection_rules,
}
