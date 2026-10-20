from acb.controls.acb_cfg_002 import AUDITS
from acb.model import Outcome
from tests._harness import context_for
from tests.test_controls._bundled import BUNDLED
from tests.test_controls._shared import FIXTURES_ROOT, check_pass_and_fail


def test_acb_cfg_002_fixtures():
    check_pass_and_fail("ACB-CFG-002", AUDITS, skip=frozenset({"managed-sideload-disabled"}), clients=BUNDLED)


def test_managed_sideload_disabled():
    fixtures = FIXTURES_ROOT / "ACB-CFG-002" / "managed-sideload-disabled"
    check = AUDITS["managed-sideload-disabled"]
    assert check(context_for(fixtures / "pass", BUNDLED)) == []
    assert [f.outcome for f in check(context_for(fixtures / "fail", BUNDLED))] == [Outcome.FAIL]


def test_managed_sideload_not_applicable_without_managed_settings():
    fixture = FIXTURES_ROOT / "ACB-CFG-002" / "install-commands-denied" / "pass"
    findings = AUDITS["managed-sideload-disabled"](context_for(fixture, BUNDLED))
    assert [f.outcome for f in findings] == [Outcome.NOT_APPLICABLE]
