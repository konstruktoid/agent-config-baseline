from __future__ import annotations

import json
from typing import TYPE_CHECKING

from acb.controls.acb_ext_004 import AUDITS
from tests._harness import context_for
from tests.test_controls._bundled import BUNDLED
from tests.test_controls._shared import check_pass_and_fail

if TYPE_CHECKING:
    from pathlib import Path

    from acb.model import Finding


def test_acb_ext_004_fixtures() -> None:
    check_pass_and_fail("ACB-EXT-004", AUDITS, clients=BUNDLED)


def _settings(tmp_path: Path, command: str) -> list[Finding]:
    (tmp_path / ".claude").mkdir()
    hooks = {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": command}]}]}
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"hooks": hooks}))
    return AUDITS["guards-have-tests"](context_for(tmp_path, BUNDLED))


def test_inline_blocking_command_fails(tmp_path: Path) -> None:
    findings = _settings(tmp_path, "jq -e '.tool_input.command | test(\"rm\") | not' || exit 2")
    assert len(findings) == 1
    assert "no script file" in findings[0].message


def test_relative_script_referenced_by_a_test_passes(tmp_path: Path) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "guard.py").write_text("import sys\nsys.exit(2)\n")
    (tmp_path / "test_guard.py").write_text("GUARD = 'scripts/guard.py'\n")
    assert _settings(tmp_path, "python3 scripts/guard.py") == []


def test_non_blocking_events_are_out_of_scope(tmp_path: Path) -> None:
    (tmp_path / ".claude").mkdir()
    hooks = {"PostToolUse": [{"hooks": [{"type": "command", "command": "echo done"}]}]}
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps({"hooks": hooks}))
    assert AUDITS["guards-have-tests"](context_for(tmp_path, BUNDLED)) == []


def test_guard_module_without_module_test_fails(tmp_path: Path) -> None:
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text('{"name": "p"}')
    (tmp_path / "hooks").mkdir()
    (tmp_path / "hooks" / "hooks.json").write_text('{"modules": ["./register.js"]}')
    (tmp_path / "hooks" / "register.js").write_text("export function register(on) { on('tool.call', g) }\n")
    findings = AUDITS["guards-have-tests"](context_for(tmp_path, BUNDLED))
    assert [f.path for f in findings] == ["hooks/register.js"]
    (tmp_path / "hooks" / "other.test.ts").write_text("// tests something else\n")
    assert AUDITS["guards-have-tests"](context_for(tmp_path, BUNDLED))
    (tmp_path / "hooks" / "register.test.ts").write_text("import { register } from './register.js'\n")
    assert AUDITS["guards-have-tests"](context_for(tmp_path, BUNDLED)) == []


def test_notes_under_tests_do_not_count_as_a_test(tmp_path: Path) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "guard.sh").write_text("exit 2\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "notes.txt").write_text("TODO: test guard.sh\n")
    assert _settings(tmp_path, "sh scripts/guard.sh")
