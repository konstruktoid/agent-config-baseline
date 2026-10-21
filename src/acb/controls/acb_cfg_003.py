"""ACB-CFG-003: Blocking policy is enforced in a layer user-installed extensions cannot override."""

from __future__ import annotations

from typing import TYPE_CHECKING

from acb.extensions import requirement_failures
from acb.model import Finding, Outcome

if TYPE_CHECKING:
    from acb.controls import CheckContext

CONTROL_ID = "ACB-CFG-003"
_AUDIT = "managed-extension-restriction"


def _check_managed_extension_restriction(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for settings in ctx.inventory.agent_settings:
        if settings.scope != "managed":
            continue
        rel = ctx.relative(settings.path)
        requirements = ctx.clients.profile(settings.client).get("managed_requirements", {}).get("extension_restriction")
        if not requirements:
            findings.append(
                Finding(
                    CONTROL_ID,
                    _AUDIT,
                    Outcome.NOT_EVALUATED,
                    f"client {settings.client} defines no extension restriction",
                    rel,
                )
            )
            continue
        findings.extend(
            Finding(CONTROL_ID, _AUDIT, Outcome.FAIL, failure, rel)
            for failure in requirement_failures(settings, requirements)
        )
    return findings


AUDITS = {
    _AUDIT: _check_managed_extension_restriction,
}
