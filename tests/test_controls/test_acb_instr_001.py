from __future__ import annotations

from typing import TYPE_CHECKING

from acb.clients import ClientData
from acb.controls.acb_instr_001 import AUDITS
from acb.model import Outcome
from tests._harness import context_for
from tests.test_controls._shared import FIXTURES_ROOT, check_pass_and_fail

if TYPE_CHECKING:
    from pathlib import Path


def test_acb_instr_001_fixtures() -> None:
    check_pass_and_fail("ACB-INSTR-001", AUDITS, skip=frozenset({"bypass-flags"}))


def test_acb_instr_001_bypass_flags_not_evaluated_with_no_client_data() -> None:
    # With no client-declared bypass flags, there is nothing to check: that
    # is reported as NOT_APPLICABLE, not as a silent PASS.
    findings = AUDITS["bypass-flags"](context_for(FIXTURES_ROOT / "ACB-INSTR-001" / "bypass-flags" / "pass"))
    assert len(findings) == 1
    assert findings[0].outcome == Outcome.NOT_APPLICABLE


def test_acb_instr_001_bypass_flags() -> None:
    clients = ClientData(permission_bypass_flags=("--yolo",))
    check = AUDITS["bypass-flags"]
    fixtures = FIXTURES_ROOT / "ACB-INSTR-001" / "bypass-flags"

    pass_findings = check(context_for(fixtures / "pass", clients=clients))
    assert pass_findings == []

    fail_findings = check(context_for(fixtures / "fail", clients=clients))
    assert fail_findings


def test_acb_instr_001_bypass_flags_case_insensitive() -> None:
    clients = ClientData(permission_bypass_flags=("--yolo",))
    check = AUDITS["bypass-flags"]
    fixtures = FIXTURES_ROOT / "ACB-INSTR-001" / "bypass-flags"

    fail_findings = check(context_for(fixtures / "fail-case-insensitive", clients=clients))
    assert fail_findings
    assert all(f.outcome == Outcome.FAIL for f in fail_findings)


def test_acb_instr_001_unreadable_file_is_not_evaluated(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_bytes(b"\xff\xfe not valid utf-8 \x80")
    findings = AUDITS["oversight-bypass-directives"](context_for(tmp_path))
    assert len(findings) == 1
    assert findings[0].outcome == Outcome.NOT_EVALUATED
    assert "could not be read" in findings[0].message
