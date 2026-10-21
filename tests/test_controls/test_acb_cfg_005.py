import json

import pytest

from acb.controls.acb_cfg_005 import AUDITS
from acb.model import Outcome
from tests._harness import context_for
from tests.test_controls._bundled import BUNDLED
from tests.test_controls._shared import FIXTURES_ROOT, check_pass_and_fail


def test_acb_cfg_005_fixtures():
    check_pass_and_fail("ACB-CFG-005", AUDITS, clients=BUNDLED)


def test_every_server_wide_rule_is_reported():
    fixture = FIXTURES_ROOT / "ACB-CFG-005" / "tools-allowed-by-name" / "fail"
    findings = AUDITS["tools-allowed-by-name"](context_for(fixture, BUNDLED))
    assert len(findings) == 3
    assert all(f.outcome == Outcome.FAIL and f.path == ".claude/settings.json" for f in findings)


def _findings_for(tmp_path, rule: str):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"allow": [rule]}}))
    return AUDITS["tools-allowed-by-name"](context_for(tmp_path, BUNDLED))


@pytest.mark.parametrize("rule", ["mcp__my_server", " mcp__reports__v2__* ", "mcp__plugin_p_db__q*"])
def test_server_wide_and_pattern_forms_fail(tmp_path, rule):
    assert [f.outcome for f in _findings_for(tmp_path, rule)] == [Outcome.FAIL]


@pytest.mark.parametrize("rule", ["mcp__github__get_issue", "mcp__reports__v2", "mcp__*", "*", "Bash(npm *)"])
def test_named_tools_and_skipped_globs_pass(tmp_path, rule):
    assert _findings_for(tmp_path, rule) == []


def test_deny_and_ask_rules_are_not_checked(tmp_path):
    (tmp_path / ".claude").mkdir()
    rules = {"deny": ["mcp__github"], "ask": ["mcp__github__*"]}
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"permissions": rules}))
    assert AUDITS["tools-allowed-by-name"](context_for(tmp_path, BUNDLED)) == []
