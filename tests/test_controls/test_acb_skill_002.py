from acb.controls.acb_skill_002 import AUDITS
from tests.test_controls._shared import check_pass_and_fail


def test_acb_skill_002_fixtures() -> None:
    check_pass_and_fail("ACB-SKILL-002", AUDITS)
