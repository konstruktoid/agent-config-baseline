from acb.controls.acb_cfg_003 import AUDITS
from tests._harness import context_for
from tests.test_controls._bundled import BUNDLED
from tests.test_controls._shared import FIXTURES_ROOT, check_pass_and_fail


def test_acb_cfg_003_fixtures():
    check_pass_and_fail("ACB-CFG-003", AUDITS, clients=BUNDLED)


def test_each_requirement_is_reported():
    fixture = FIXTURES_ROOT / "ACB-CFG-003" / "managed-extension-restriction" / "fail"
    messages = [f.message for f in AUDITS["managed-extension-restriction"](context_for(fixture, BUNDLED))]
    assert len(messages) == 3
    assert any("allowManagedModsOnly" in m and "unset" in m for m in messages)
    assert any("allowModsToOverrideDenyRules" in m for m in messages)
    assert any("prependPlugins" in m for m in messages)
