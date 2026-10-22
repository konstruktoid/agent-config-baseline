from __future__ import annotations

from typing import TYPE_CHECKING

from acb.controls.acb_ext_001 import AUDITS
from acb.model import Outcome
from tests._harness import context_for
from tests.test_controls._bundled import BUNDLED
from tests.test_controls._shared import FIXTURES_ROOT, check_pass_and_fail

if TYPE_CHECKING:
    from pathlib import Path


def test_acb_ext_001_fixtures() -> None:
    check_pass_and_fail("ACB-EXT-001", AUDITS, clients=BUNDLED)


def test_no_packages_without_client_data() -> None:
    fixture = FIXTURES_ROOT / "ACB-EXT-001" / "modules-documented" / "fail"
    assert AUDITS["modules-documented"](context_for(fixture)) == []


def test_module_without_hooks_json_is_still_found(tmp_path: Path) -> None:
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text('{"name": "p"}')
    (tmp_path / "hooks").mkdir()
    (tmp_path / "hooks" / "register.ts").write_text("export function register(on) {}\n")
    (tmp_path / "hooks" / "register.test.ts").write_text("// test\n")
    findings = AUDITS["modules-documented"](context_for(tmp_path, BUNDLED))
    assert [f.path for f in findings] == ["hooks/register.ts"]
    assert "no README" in findings[0].message


def test_manifest_named_hook_file_modules_are_found(tmp_path: Path) -> None:
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text('{"name": "p", "hooks": "./config/extra.json"}')
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "extra.json").write_text('{"modules": ["../lib/mod.mjs"]}')
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "mod.mjs").write_text("export function register(on) {}\n")
    (tmp_path / "README.md").write_text("Nothing here.\n")
    findings = AUDITS["modules-documented"](context_for(tmp_path, BUNDLED))
    assert [f.path for f in findings] == ["lib/mod.mjs"]


def test_unparseable_hook_file_is_not_evaluated(tmp_path: Path) -> None:
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text('{"name": "p"}')
    (tmp_path / "hooks").mkdir()
    (tmp_path / "hooks" / "hooks.json").write_text("{not json")
    findings = AUDITS["modules-documented"](context_for(tmp_path, BUNDLED))
    assert [f.outcome for f in findings] == [Outcome.NOT_EVALUATED]
