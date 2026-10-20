from acb.controls.acb_cfg_004 import AUDITS
from acb.model import Outcome
from tests._harness import context_for
from tests.test_controls._bundled import BUNDLED
from tests.test_controls._shared import FIXTURES_ROOT, check_pass_and_fail


def test_acb_cfg_004_fixtures():
    check_pass_and_fail("ACB-CFG-004", AUDITS, clients=BUNDLED)


def test_approval_rules_not_applicable_without_settings():
    fixture = FIXTURES_ROOT / "ACB-CFG-004" / "approval-not-delegated" / "fail"
    findings = AUDITS["approval-rules-present"](context_for(fixture, BUNDLED))
    assert [f.outcome for f in findings] == [Outcome.NOT_APPLICABLE]
