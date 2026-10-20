import json

from acb.controls.acb_cfg_001 import AUDITS
from acb.model import Outcome
from tests._harness import context_for
from tests.test_controls._bundled import BUNDLED
from tests.test_controls._shared import FIXTURES_ROOT, check_pass_and_fail


def test_acb_cfg_001_fixtures():
    check_pass_and_fail("ACB-CFG-001", AUDITS, clients=BUNDLED)


def test_every_unprotected_target_is_reported():
    fixture = FIXTURES_ROOT / "ACB-CFG-001" / "self-protection-rules" / "fail"
    findings = AUDITS["self-protection-rules"](context_for(fixture, BUNDLED))
    assert len(findings) == len(BUNDLED.profile("claude-code")["self_protection_rules"])
    assert all(f.outcome == Outcome.FAIL and f.path == ".claude/settings.json" for f in findings)


def test_bare_tool_deny_covers_every_target(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"deny": ["Edit"]}}))
    assert AUDITS["self-protection-rules"](context_for(tmp_path, BUNDLED)) == []


def test_write_rules_and_allow_rules_do_not_count(tmp_path):
    (tmp_path / ".claude").mkdir()
    rules = {"deny": ["Write(.claude/**)"], "ask": ["Edit(.claude/**)"]}
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"permissions": rules}))
    findings = AUDITS["self-protection-rules"](context_for(tmp_path, BUNDLED))
    assert any(".claude/" in f.message for f in findings)


def test_unparseable_settings_file_is_unscanned(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text('{"permissions": {"deny": [],}}')
    ctx = context_for(tmp_path, BUNDLED)
    assert ctx.inventory.unscanned and not ctx.inventory.agent_settings
