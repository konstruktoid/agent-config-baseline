from acb.controls.acb_skill_001 import AUDITS
from tests.test_controls._shared import check_pass_and_fail


def test_acb_skill_001_fixtures():
    check_pass_and_fail("ACB-SKILL-001", AUDITS)
