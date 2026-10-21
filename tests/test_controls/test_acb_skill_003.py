from acb.controls.acb_skill_003 import AUDITS
from tests.test_controls._shared import check_pass_and_fail


def test_acb_skill_003_fixtures() -> None:
    check_pass_and_fail("ACB-SKILL-003", AUDITS)
