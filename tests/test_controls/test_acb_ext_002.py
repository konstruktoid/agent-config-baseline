from __future__ import annotations

from typing import TYPE_CHECKING

from acb.controls.acb_ext_002 import AUDITS
from tests._harness import context_for
from tests.test_controls._bundled import BUNDLED
from tests.test_controls._shared import FIXTURES_ROOT, check_pass_and_fail

if TYPE_CHECKING:
    from pathlib import Path


def test_acb_ext_002_fixtures() -> None:
    check_pass_and_fail("ACB-EXT-002", AUDITS, clients=BUNDLED)


def test_every_executable_component_is_reported() -> None:
    fixture = FIXTURES_ROOT / "ACB-EXT-002" / "no-executable-components" / "fail"
    paths = {f.path for f in AUDITS["no-executable-components"](context_for(fixture, BUNDLED))}
    assert paths == {
        "release-notes/hooks/hooks.json",
        "release-notes/hooks/register.js",
        "release-notes/.mcp.json",
    }


def test_inline_manifest_component_beside_root_skill_fails(tmp_path: Path) -> None:
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text(
        '{"name": "p", "mcpServers": {"s": {"command": "node", "args": ["s.js"]}}}'
    )
    (tmp_path / "SKILL.md").write_text("---\nname: p\ndescription: d\n---\n")
    findings = AUDITS["no-executable-components"](context_for(tmp_path, BUNDLED))
    assert [f.path for f in findings] == [".claude-plugin/plugin.json"]


def test_code_only_package_is_out_of_scope(tmp_path: Path) -> None:
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text('{"name": "p"}')
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "tool").write_text("#!/bin/sh\n")
    assert AUDITS["no-executable-components"](context_for(tmp_path, BUNDLED)) == []
