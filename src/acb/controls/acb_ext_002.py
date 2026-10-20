"""ACB-EXT-002: Content packages contain no executable extension components."""

from __future__ import annotations

from acb.extensions import analyse_package
from acb.model import Finding, Outcome

CONTROL_ID = "ACB-EXT-002"
_AUDIT = "no-executable-components"


def _check_no_executable_components(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for package in ctx.inventory.extension_packages:
        analysis = analyse_package(package, ctx.clients.profile(package.client))
        for rel in analysis.unreadable:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id=_AUDIT,
                    outcome=Outcome.NOT_EVALUATED,
                    message=f"hook configuration {rel} could not be read or parsed",
                    path=ctx.relative(package.manifest),
                )
            )
        if not analysis.content:
            continue
        content = ", ".join(analysis.content)
        for kind, label, anchor in analysis.components:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id=_AUDIT,
                    outcome=Outcome.FAIL,
                    message=f"package ships content ({content}) and an executable component: {kind} ({label})",
                    path=ctx.relative(anchor),
                )
            )
    return findings


AUDITS = {
    _AUDIT: _check_no_executable_components,
}
