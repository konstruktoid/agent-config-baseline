from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from acb.controls.acb_skill_003 import AUDITS
from tests._harness import context_for
from tests.test_controls._shared import check_pass_and_fail

if TYPE_CHECKING:
    from pathlib import Path

    from acb.model import Finding


def test_acb_skill_003_fixtures() -> None:
    check_pass_and_fail("ACB-SKILL-003", AUDITS)


def _reference_findings(tmp_path: Path, ref: str) -> list[Finding]:
    skill = tmp_path / "s"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        f"---\nname: s\ndescription: A skill that names one file.\n---\n\nSee {ref} first.\n"
    )
    return AUDITS["references-contained"](context_for(tmp_path))


@pytest.mark.parametrize(
    "ref",
    ["file:///etc/passwd", "file://localhost/etc/passwd", "FILE://LOCALHOST/etc/passwd", "file:/etc/passwd"],
)
def test_local_file_uri_is_an_absolute_path(tmp_path: Path, ref: str) -> None:
    findings = _reference_findings(tmp_path, ref)
    assert [f.message for f in findings] == [f"reference {ref!r} is an absolute path"]


def test_file_uri_naming_another_host_is_outside(tmp_path: Path) -> None:
    findings = _reference_findings(tmp_path, "file://fileserver/share/notes.md")
    assert [f.message for f in findings] == [
        "reference 'file://fileserver/share/notes.md' names a remote host, outside the skill directory"
    ]


def test_relative_reference_inside_the_skill_passes(tmp_path: Path) -> None:
    assert _reference_findings(tmp_path, "scripts/run.sh") == []
