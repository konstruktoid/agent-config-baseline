"""ACB-CFG-004: Human approval requirements are defined by configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from acb.extensions import analyse_package, module_capabilities, rule_list
from acb.model import Finding, Outcome

if TYPE_CHECKING:
    from acb.controls import CheckContext

CONTROL_ID = "ACB-CFG-004"


def _check_approval_rules_present(ctx: CheckContext) -> list[Finding]:
    audit = "approval-rules-present"
    if not ctx.inventory.agent_settings:
        return [Finding(CONTROL_ID, audit, Outcome.NOT_APPLICABLE, "no agent settings file in the repository")]
    findings: list[Finding] = []
    for settings in ctx.inventory.agent_settings:
        profile = ctx.clients.profile(settings.client)
        if not (rule_list(settings, profile, "ask_rules_key") or rule_list(settings, profile, "deny_rules_key")):
            findings.append(
                Finding(
                    CONTROL_ID,
                    audit,
                    Outcome.FAIL,
                    "settings file defines no ask or deny rule",
                    ctx.relative(settings.path),
                )
            )
    return findings


def _check_approval_not_delegated(ctx: CheckContext) -> list[Finding]:
    audit = "approval-not-delegated"
    findings: list[Finding] = []
    for package in ctx.inventory.extension_packages:
        profile = ctx.clients.profile(package.client)
        approval_events = set(profile.get("extension_packages", {}).get("approval_events", []))
        for module in analyse_package(package, profile).modules:
            capabilities = module_capabilities(module, profile)
            if capabilities is None:
                findings.append(
                    Finding(CONTROL_ID, audit, Outcome.NOT_EVALUATED, "module could not be read", ctx.relative(module))
                )
                continue
            findings.extend(
                Finding(
                    CONTROL_ID,
                    audit,
                    Outcome.FAIL,
                    f"module handles the tool-approval event {event}",
                    ctx.relative(module),
                )
                for event in sorted(capabilities[0] & approval_events)
            )
    return findings


AUDITS = {
    "approval-rules-present": _check_approval_rules_present,
    "approval-not-delegated": _check_approval_not_delegated,
}
