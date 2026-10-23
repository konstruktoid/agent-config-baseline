from pathlib import Path

import pytest

from acb.controls.acb_prov_001 import AUDITS
from acb.model import Outcome
from tests._harness import context_for
from tests.test_controls._shared import check_pass_and_fail

COMMIT = "0123456789abcdef0123456789abcdef01234567"
DIGEST = "sha256:" + "ab" * 32


def test_acb_prov_001_fixtures() -> None:
    check_pass_and_fail("ACB-PROV-001", AUDITS)


def _skill(root: Path, name: str) -> None:
    directory = root / "skills" / name
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(f"---\nname: {name}\ndescription: A test skill for provenance.\n---\n\nBody.\n")


def _entry(
    path: str, *, commit: str = COMMIT, digest: str = DIGEST, source: str = "https://github.com/example/s"
) -> str:
    return f"  - path: {path}\n    source: {source}\n    commit: {commit}\n    digest: {digest}\n"


def _messages(root: Path, audit: str) -> list[str]:
    return [f.message for f in AUDITS[audit](context_for(root)) if f.outcome == Outcome.FAIL]


def test_no_artifacts_means_nothing_to_record(tmp_path: Path) -> None:
    assert AUDITS["record-present"](context_for(tmp_path)) == []


def test_missing_file_fails_once_per_skill(tmp_path: Path) -> None:
    _skill(tmp_path, "a")
    _skill(tmp_path, "b")
    assert _messages(tmp_path, "record-present") == [".acb-provenance.yaml does not exist"] * 2


def test_missing_entry_names_the_skill(tmp_path: Path) -> None:
    _skill(tmp_path, "a")
    _skill(tmp_path, "b")
    (tmp_path / ".acb-provenance.yaml").write_text("artifacts:\n" + _entry("skills/a"))
    assert _messages(tmp_path, "record-present") == ["no entry for 'skills/b' in .acb-provenance.yaml"]


def test_symlinked_record_is_not_evaluated(tmp_path: Path) -> None:
    _skill(tmp_path, "a")
    (tmp_path / "elsewhere.yaml").write_text("artifacts: []\n")
    (tmp_path / ".acb-provenance.yaml").symlink_to("elsewhere.yaml")
    findings = AUDITS["record-present"](context_for(tmp_path))
    assert [f.outcome for f in findings] == [Outcome.NOT_EVALUATED]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("artifacts: [", "does not parse as YAML"),
        ("- a\n- b\n", "is not a mapping with an `artifacts` list"),
        ("artifacts: none\n", "is not a mapping with an `artifacts` list"),
        ("artifacts:\n  - just-a-string\n", "artifacts entry '#0': entry is not a mapping"),
    ],
)
def test_malformed_record_fails(tmp_path: Path, text: str, message: str) -> None:
    _skill(tmp_path, "a")
    (tmp_path / ".acb-provenance.yaml").write_text(text)
    assert any(message in m for m in _messages(tmp_path, "record-fields"))


def test_duplicate_path_fails(tmp_path: Path) -> None:
    _skill(tmp_path, "a")
    (tmp_path / ".acb-provenance.yaml").write_text("artifacts:\n" + _entry("skills/a") + _entry("skills/a"))
    assert _messages(tmp_path, "record-fields") == ["artifacts entry 'skills/a': `path` appears more than once"]


@pytest.mark.parametrize(
    "entry",
    [
        _entry("skills/a", commit=COMMIT.upper()),
        _entry("skills/a", commit=COMMIT[:39]),
        _entry("skills/a", digest="sha256:" + "ab" * 31),
        _entry("skills/a", digest="SHA256:" + "ab" * 32),
        _entry("skills/a", source="http://github.com/example/s"),
        _entry("skills/a", source="https://@/repo"),
        _entry("skills/a", source="https:///repo"),
        _entry("skills/a", source="https://example.com:invalid/repo"),
        _entry("skills/a", source="https://example.com:99999/repo"),
        _entry("skills/a", source="https://git.example.org/"),
        _entry("skills/a", commit=f'"{COMMIT}\\n"'),
        _entry("skills/a", digest=f'"{DIGEST}\\n"'),
        _entry("/skills/a"),
        _entry("../skills/a"),
        _entry("skills/../a"),
        _entry("skills\\a"),
    ],
)
def test_each_field_is_validated(tmp_path: Path, entry: str) -> None:
    _skill(tmp_path, "a")
    (tmp_path / ".acb-provenance.yaml").write_text("artifacts:\n" + entry)
    assert len(_messages(tmp_path, "record-fields")) == 1


def test_sha256_length_commit_is_accepted(tmp_path: Path) -> None:
    _skill(tmp_path, "a")
    (tmp_path / ".acb-provenance.yaml").write_text("artifacts:\n" + _entry("skills/a", commit="ab" * 32))
    assert _messages(tmp_path, "record-fields") == []


def test_non_string_path_does_not_stop_the_presence_audit(tmp_path: Path) -> None:
    _skill(tmp_path, "a")
    (tmp_path / ".acb-provenance.yaml").write_text("artifacts:\n" + _entry("[]") + _entry("skills/a"))
    assert _messages(tmp_path, "record-present") == []
    assert any("`path` is missing or not a string" in m for m in _messages(tmp_path, "record-fields"))


def test_source_with_a_valid_port_is_accepted(tmp_path: Path) -> None:
    (tmp_path / ".acb-provenance.yaml").write_text(
        "artifacts:\n" + _entry("skills/a", source="https://git.example.org:8443/org/repo")
    )
    assert _messages(tmp_path, "record-fields") == []


def test_malformed_record_is_ignored_without_applicable_artifacts(tmp_path: Path) -> None:
    (tmp_path / ".acb-provenance.yaml").write_text("artifacts: [")
    assert AUDITS["record-fields"](context_for(tmp_path)) == []
