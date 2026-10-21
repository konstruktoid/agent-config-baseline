from pathlib import Path
from typing import Any

import pytest

from acb import runner
from acb.clients import ClientData
from acb.discovery import InstructionFile, Inventory, Unscanned
from acb.model import AuditProcedure, Control, Finding, Outcome, Severity


def _control() -> Control:
    return Control(
        id="ACB-GEN-999",
        title="Test control",
        status="draft",
        profiles=("strict-general",),
        applies_to=("instruction-file",),
        check_type="static",
        severity=Severity.HIGH,
        description="x" * 20,
        rationale="x" * 20,
        audit=(AuditProcedure(id="a1", method="pattern", procedure="x" * 20),),
        remediation="x" * 20,
        exceptions="permitted",
        references={},
        deprecated_by=None,
        source_path=Path("controls/ACB-GEN-999.yaml"),
        raw={},
    )


def _inventory(tmp_path: Path, with_artifact: bool = True, unscanned: tuple = ()) -> Inventory:
    files = (InstructionFile(path=tmp_path / "AGENTS.md", source="AGENTS.md"),) if with_artifact else ()
    return Inventory(root=tmp_path, skills=(), instruction_files=files, mcp_declarations=(), unscanned=unscanned)


def _outcome(monkeypatch, tmp_path, audit, inventory=None) -> tuple[Outcome, list[Finding]]:
    control = _control()
    monkeypatch.setitem(runner.REGISTRY, control.id, {"a1": audit})
    inventory = inventory or _inventory(tmp_path)
    findings = runner.run([control], inventory, ClientData(), tmp_path)
    return runner.control_outcome(control, findings, inventory), findings


def _finding(**overrides) -> Finding:
    values: dict[str, Any] = {"control_id": "ACB-GEN-999", "audit_id": "a1", "outcome": Outcome.FAIL, "message": "bad", "path": "x"}
    return Finding(**{**values, **overrides})


def test_clean_audit_passes(monkeypatch, tmp_path):
    assert _outcome(monkeypatch, tmp_path, lambda ctx: [])[0] == Outcome.PASS


def test_audit_that_raises_is_not_evaluated(monkeypatch, tmp_path):
    def boom(ctx):
        raise RuntimeError("kaboom")

    outcome, findings = _outcome(monkeypatch, tmp_path, boom)
    assert outcome == Outcome.NOT_EVALUATED
    assert "RuntimeError: kaboom" in findings[0].message


@pytest.mark.parametrize(
    "result",
    [
        None,
        [_finding(control_id="ACB-GEN-04")],
        [_finding(audit_id="other")],
        [_finding(outcome=Outcome.PASS)],
        ["not a finding"],
    ],
)
def test_malformed_results_are_not_evaluated(monkeypatch, tmp_path, result):
    assert _outcome(monkeypatch, tmp_path, lambda ctx: result)[0] == Outcome.NOT_EVALUATED


def test_unscanned_inventory_makes_every_control_not_evaluated(monkeypatch, tmp_path):
    inventory = _inventory(tmp_path, unscanned=(Unscanned("linked", "outside"),))
    assert _outcome(monkeypatch, tmp_path, lambda ctx: [], inventory)[0] == Outcome.NOT_EVALUATED


def test_control_without_artifacts_is_not_applicable(monkeypatch, tmp_path):
    inventory = _inventory(tmp_path, with_artifact=False)
    outcome, _ = _outcome(monkeypatch, tmp_path, lambda ctx: [], inventory)
    assert outcome == Outcome.NOT_APPLICABLE
    assert runner.all_pass([_control()], [], inventory)
