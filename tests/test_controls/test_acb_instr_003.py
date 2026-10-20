from acb.controls.acb_instr_003 import AUDITS
from acb.model import Outcome
from tests._harness import context_for
from tests.test_controls._shared import check_pass_and_fail


def test_acb_instr_003_fixtures():
    check_pass_and_fail("ACB-INSTR-003", AUDITS)


def test_acb_instr_003_unreadable_file_is_not_evaluated(tmp_path):
    (tmp_path / "AGENTS.md").write_bytes(b"\xff\xfe not valid utf-8 \x80")
    findings = AUDITS["hidden-directives"](context_for(tmp_path))
    assert len(findings) == 1
    assert findings[0].outcome == Outcome.NOT_EVALUATED
    assert "could not be read" in findings[0].message
