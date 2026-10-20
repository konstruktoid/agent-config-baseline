"""Orchestrate control evaluation over a discovered inventory."""

from __future__ import annotations

from pathlib import Path

from acb.clients import ClientData
from acb.controls import REGISTRY, CheckContext
from acb.discovery import Inventory
from acb.model import Control, Finding, Outcome

_AUDIT_OUTCOMES = {Outcome.FAIL, Outcome.NOT_EVALUATED, Outcome.NOT_APPLICABLE}


def _not_evaluated(control: Control, audit_id: str, message: str) -> Finding:
    return Finding(control_id=control.id, audit_id=audit_id, outcome=Outcome.NOT_EVALUATED, message=message)


def _run_audit(control: Control, audit_id: str, check, ctx: CheckContext) -> list[Finding]:
    """Run one audit, converting anything other than a well-formed result into
    NOT_EVALUATED. A crash or a malformed finding must never read as a pass,
    and a finding filed under another control or audit would otherwise be
    silently ignored when outcomes are tallied."""
    try:
        result = check(ctx)
    except Exception as exc:
        return [_not_evaluated(control, audit_id, f"audit raised {type(exc).__name__}: {exc}")]
    if not isinstance(result, list):
        return [_not_evaluated(control, audit_id, f"audit returned {type(result).__name__}, not a list of findings")]
    for finding in result:
        if (
            not isinstance(finding, Finding)
            or finding.control_id != control.id
            or finding.audit_id != audit_id
            or finding.outcome not in _AUDIT_OUTCOMES
        ):
            return [_not_evaluated(control, audit_id, f"audit returned a malformed finding: {finding!r}")]
    return result


def run(
    controls: list[Control], inventory: Inventory, clients: ClientData, root: Path, run_validators: bool = False
) -> list[Finding]:
    ctx = CheckContext(inventory=inventory, clients=clients, root=Path(root).resolve(), run_validators=run_validators)
    findings: list[Finding] = []

    for control in controls:
        if inventory.unscanned:
            findings.append(
                _not_evaluated(
                    control,
                    "*",
                    f"inventory incomplete: {len(inventory.unscanned)} path(s) under PATH could not be scanned",
                )
            )

        module_audits = REGISTRY.get(control.id)
        if module_audits is None:
            findings.append(_not_evaluated(control, "*", f"{control.id} has no checker module implementation"))
            continue

        for audit in control.audit:
            check = module_audits.get(audit.id)
            if check is None:
                findings.append(_not_evaluated(control, audit.id, f"audit procedure {audit.id!r} is not implemented"))
                continue
            findings.extend(_run_audit(control, audit.id, check, ctx))

    return findings


def is_applicable(control: Control, inventory: Inventory) -> bool:
    return any(inventory.has_artifacts(kind) for kind in control.applies_to)


def control_outcome(control: Control, findings: list[Finding], inventory: Inventory) -> Outcome:
    relevant = [f for f in findings if f.control_id == control.id]
    if any(f.outcome == Outcome.NOT_EVALUATED and f.audit_id == "*" for f in relevant):
        return Outcome.NOT_EVALUATED
    if any(f.outcome == Outcome.FAIL for f in relevant):
        return Outcome.FAIL
    if not is_applicable(control, inventory):
        return Outcome.NOT_APPLICABLE
    if any(f.outcome == Outcome.NOT_EVALUATED for f in relevant):
        return Outcome.NOT_EVALUATED
    return Outcome.PASS


def all_pass(controls: list[Control], findings: list[Finding], inventory: Inventory) -> bool:
    return all(
        control_outcome(c, findings, inventory) in (Outcome.PASS, Outcome.NOT_APPLICABLE) for c in controls
    )
