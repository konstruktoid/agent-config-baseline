from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from acb.controls.acb_skill_003 import AUDITS
from acb.model import Outcome
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


def test_unparseable_file_uri_fails_only_that_reference(tmp_path: Path) -> None:
    findings = _reference_findings(tmp_path, "file://host\uff1a80/path")
    assert [(f.outcome, f.message) for f in findings] == [
        (Outcome.FAIL, "reference 'file://host\uff1a80/path' is not a valid file URI")
    ]


def test_relative_reference_inside_the_skill_passes(tmp_path: Path) -> None:
    assert _reference_findings(tmp_path, "scripts/run.sh") == []


@pytest.mark.parametrize(
    "ref",
    [
        "/dev/null",
        "/etc/profile",
        "PATH=/usr/bin:/bin",
        "~DEFAULT_BRANCH",
        "$HOME",
        "`..`",
        "[spec](https://example.com/a/../b)",
        "[contact](mailto:security@example.com)",
        "[section](#intro)",
        "[guide](references/guide.md#intro)",
    ],
)
def test_host_paths_and_other_schemes_are_not_file_references(tmp_path: Path, ref: str) -> None:
    assert _reference_findings(tmp_path, ref) == []


@pytest.mark.parametrize(
    ("ref", "message"),
    [
        ("[passwd](/etc/passwd)", "reference '/etc/passwd' is an absolute path"),
        ("[other](../other/SKILL.md)", "reference '../other/SKILL.md' contains a `..` path segment"),
        ("[other](%2e%2e/other.md)", "reference '%2e%2e/other.md' contains a `..` path segment"),
        ("[notes](~/notes.md)", "reference '~/notes.md' is a home-directory reference, outside the skill directory"),
        ("../sibling/notes.md", "reference '../sibling/notes.md' contains a `..` path segment"),
        ("~/.ssh/id_rsa", "reference '~/.ssh/id_rsa' is a home-directory reference, outside the skill directory"),
        (
            "$HOME/.ssh/id_rsa",
            "reference '$HOME/.ssh/id_rsa' is a home-directory reference, outside the skill directory",
        ),
        ("${HOME}/notes.md", "reference '${HOME}/notes.md' is a home-directory reference, outside the skill directory"),
    ],
)
def test_references_that_leave_the_skill_fail_once(tmp_path: Path, ref: str, message: str) -> None:
    assert [f.message for f in _reference_findings(tmp_path, ref)] == [message]


def test_pointy_link_with_spaces_is_reported_once(tmp_path: Path) -> None:
    findings = _reference_findings(tmp_path, "[other](<../other skill/notes.md>)")
    assert [f.message for f in findings] == ["reference '../other skill/notes.md' contains a `..` path segment"]


def test_reference_definition_target_is_a_reference(tmp_path: Path) -> None:
    findings = _reference_findings(tmp_path, "the notes.\n\n[notes]: ../other/notes.md")
    assert [(f.message, f.line) for f in findings] == [
        ("reference '../other/notes.md' contains a `..` path segment", 8)
    ]
