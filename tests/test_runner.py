from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Never

import pytest

from acb import runner
from acb.clients import ClientData
from acb.discovery import InstructionFile, Inventory, Unscanned
from acb.model import AuditProcedure, Control, Finding, Outcome, Severity

if TYPE_CHECKING:
    from collections.abc import Callable

    from acb.controls import CheckContext


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


def _inventory(tmp_path: Path, *, with_artifact: bool = True, unscanned: tuple[Unscanned, ...] = ()) -> Inventory:
    files = (InstructionFile(path=tmp_path / "AGENTS.md", source="AGENTS.md"),) if with_artifact else ()
    return Inventory(root=tmp_path, skills=(), instruction_files=files, mcp_declarations=(), unscanned=unscanned)


def _outcome(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    audit: Callable[[CheckContext], object],
    inventory: Inventory | None = None,
) -> tuple[Outcome, list[Finding]]:
    control = _control()
    monkeypatch.setitem(runner.REGISTRY, control.id, {"a1": audit})
    inventory = inventory or _inventory(tmp_path)
    findings = runner.run([control], inventory, ClientData(), tmp_path)
    return runner.control_outcome(control, findings, inventory), findings


def _finding(**overrides: object) -> Finding:
    values: dict[str, Any] = {
        "control_id": "ACB-GEN-999",
        "audit_id": "a1",
        "outcome": Outcome.FAIL,
        "message": "bad",
        "path": "x",
    }
    merged: dict[str, Any] = {**values, **overrides}
    return Finding(**merged)


def test_clean_audit_passes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert _outcome(monkeypatch, tmp_path, lambda _ctx: [])[0] == Outcome.PASS


def test_audit_that_raises_is_not_evaluated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def boom(_ctx: CheckContext) -> Never:
        msg = "kaboom"
        raise RuntimeError(msg)

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
def test_malformed_results_are_not_evaluated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, result: object) -> None:
    assert _outcome(monkeypatch, tmp_path, lambda _ctx: result)[0] == Outcome.NOT_EVALUATED


def test_unscanned_inventory_makes_every_control_not_evaluated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    inventory = _inventory(tmp_path, unscanned=(Unscanned("linked", "outside"),))
    assert _outcome(monkeypatch, tmp_path, lambda _ctx: [], inventory)[0] == Outcome.NOT_EVALUATED


def test_control_without_artifacts_is_not_applicable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    inventory = _inventory(tmp_path, with_artifact=False)
    outcome, _ = _outcome(monkeypatch, tmp_path, lambda _ctx: [], inventory)
    assert outcome == Outcome.NOT_APPLICABLE
    assert runner.all_pass([_control()], [], inventory)
