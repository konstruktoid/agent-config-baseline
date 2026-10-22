"""ACB-CFG-002: The agent cannot install, enable or sideload extensions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from acb.extensions import missing_rule_groups, requirement_failures, settings_by_client
from acb.model import Finding, Outcome

if TYPE_CHECKING:
    from acb.controls import CheckContext

CONTROL_ID = "ACB-CFG-002"


def _check_install_commands_denied(ctx: CheckContext) -> list[Finding]:
    audit = "install-commands-denied"
    findings: list[Finding] = []
    for client, files in settings_by_client(ctx.inventory.agent_settings).items():
        anchor = ctx.relative(min(files, key=lambda s: s.scope != "project").path)
        missing = missing_rule_groups(files, ctx.clients.profile(client), "extension_install_rules")
        if missing is None:
            findings.append(
                Finding(
                    CONTROL_ID,
                    audit,
                    Outcome.NOT_EVALUATED,
                    f"client {client} defines no extension install rules",
                    anchor,
                )
            )
            continue
        findings.extend(
            Finding(
                CONTROL_ID,
                audit,
                Outcome.FAIL,
                f"no deny rule covers {group['target']}; add one of: {', '.join(group['any_of'])}",
                anchor,
            )
            for group in missing
        )
    return findings


def _check_managed_sideload_disabled(ctx: CheckContext) -> list[Finding]:
    audit = "managed-sideload-disabled"
    managed = [s for s in ctx.inventory.agent_settings if s.scope == "managed"]
    if not managed:
        return [Finding(CONTROL_ID, audit, Outcome.NOT_APPLICABLE, "no managed settings file in the repository")]
    findings: list[Finding] = []
    for settings in managed:
        rel = ctx.relative(settings.path)
        requirements = ctx.clients.profile(settings.client).get("managed_requirements", {}).get("sideload_restriction")
        if not requirements:
            findings.append(
                Finding(
                    CONTROL_ID,
                    audit,
                    Outcome.NOT_EVALUATED,
                    f"client {settings.client} defines no sideload restriction",
                    rel,
                )
            )
            continue
        findings.extend(
            Finding(CONTROL_ID, audit, Outcome.FAIL, failure, rel)
            for failure in requirement_failures(settings, requirements)
        )
    return findings


AUDITS = {
    "install-commands-denied": _check_install_commands_denied,
    "managed-sideload-disabled": _check_managed_sideload_disabled,
}
