import json
from pathlib import Path

import pytest

from acb.controls.acb_prov_001 import AUDITS
from acb.model import Outcome
from tests._harness import context_for
from tests.test_controls._bundled import BUNDLED
from tests.test_controls._shared import check_pass_and_fail

COMMIT = "0123456789abcdef0123456789abcdef01234567"
DIGEST = "sha256:" + "ab" * 32


def test_acb_prov_001_fixtures() -> None:
    check_pass_and_fail("ACB-PROV-001", AUDITS)


def _skill(root: Path, name: str) -> Path:
    directory = root / "skills" / name
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(f"---\nname: {name}\ndescription: A test skill for provenance.\n---\n\nBody.\n")
    return directory


def _record(*, commit: str = COMMIT, digest: str = DIGEST, source: str = "https://github.com/example/s") -> str:
    return f"source: {source}\ncommit: {commit}\ndigest: {digest}\n"


def _findings(root: Path, audit: str, outcome: Outcome = Outcome.FAIL) -> list[tuple[str | None, str]]:
    return [(f.path, f.message) for f in AUDITS[audit](context_for(root)) if f.outcome == outcome]


def test_no_artifacts_means_nothing_to_record(tmp_path: Path) -> None:
    assert AUDITS["record-present"](context_for(tmp_path)) == []
    assert AUDITS["record-fields"](context_for(tmp_path)) == []


def test_missing_record_fails_for_that_skill_only(tmp_path: Path) -> None:
    (_skill(tmp_path, "a") / ".acb-provenance.yaml").write_text(_record())
    _skill(tmp_path, "b")
    assert _findings(tmp_path, "record-present") == [
        ("skills/b", ".acb-provenance.yaml does not exist in the artifact directory")
    ]


def test_repository_root_record_does_not_cover_a_skill(tmp_path: Path) -> None:
    _skill(tmp_path, "a")
    (tmp_path / ".acb-provenance.yaml").write_text(_record())
    assert [path for path, _ in _findings(tmp_path, "record-present")] == ["skills/a"]


def test_extension_package_root_carries_its_record(tmp_path: Path) -> None:
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "p"}))
    missing = [(f.path, f.message) for f in AUDITS["record-present"](context_for(tmp_path, BUNDLED))]
    assert missing == [(".", ".acb-provenance.yaml does not exist in the artifact directory")]
    (tmp_path / ".acb-provenance.yaml").write_text(_record(commit="not-a-commit"))
    invalid = [(f.path, f.message) for f in AUDITS["record-fields"](context_for(tmp_path, BUNDLED))]
    assert invalid == [(".acb-provenance.yaml", "`commit` is not a full lowercase hexadecimal commit hash")]
    assert AUDITS["record-present"](context_for(tmp_path, BUNDLED)) == []


def test_symlinked_record_is_not_evaluated(tmp_path: Path) -> None:
    directory = _skill(tmp_path, "a")
    (tmp_path / "elsewhere.yaml").write_text(_record())
    (directory / ".acb-provenance.yaml").symlink_to(tmp_path / "elsewhere.yaml")
    for audit in ("record-present", "record-fields"):
        findings = AUDITS[audit](context_for(tmp_path))
        assert [(f.outcome, f.path) for f in findings] == [(Outcome.NOT_EVALUATED, "skills/a/.acb-provenance.yaml")]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("source: [", "does not parse as YAML"),
        ("- a\n- b\n", ".acb-provenance.yaml is not a mapping"),
        ("just-a-string\n", ".acb-provenance.yaml is not a mapping"),
    ],
)
def test_malformed_record_fails(tmp_path: Path, text: str, message: str) -> None:
    (_skill(tmp_path, "a") / ".acb-provenance.yaml").write_text(text)
    findings = _findings(tmp_path, "record-fields")
    assert len(findings) == 1
    assert findings[0][0] == "skills/a/.acb-provenance.yaml"
    assert message in findings[0][1]
    assert _findings(tmp_path, "record-present") == []


@pytest.mark.parametrize(
    "record",
    [
        _record(commit=COMMIT.upper()),
        _record(commit=COMMIT[:39]),
        _record(digest="sha256:" + "ab" * 31),
        _record(digest="SHA256:" + "ab" * 32),
        _record(source="http://github.com/example/s"),
        _record(source="https://@/repo"),
        _record(source="https:///repo"),
        _record(source="https://example.com:invalid/repo"),
        _record(source="https://example.com:99999/repo"),
        _record(source="https://git.example.org/"),
        _record(commit=f'"{COMMIT}\\n"'),
        _record(digest=f'"{DIGEST}\\n"'),
        _record(commit="[]"),
    ],
)
def test_each_field_is_validated(tmp_path: Path, record: str) -> None:
    (_skill(tmp_path, "a") / ".acb-provenance.yaml").write_text(record)
    assert len(_findings(tmp_path, "record-fields")) == 1


def test_sha256_length_commit_is_accepted(tmp_path: Path) -> None:
    (_skill(tmp_path, "a") / ".acb-provenance.yaml").write_text(_record(commit="ab" * 32))
    assert _findings(tmp_path, "record-fields") == []


def test_source_with_a_valid_port_is_accepted(tmp_path: Path) -> None:
    (_skill(tmp_path, "a") / ".acb-provenance.yaml").write_text(_record(source="https://git.example.org:8443/org/repo"))
    assert _findings(tmp_path, "record-fields") == []


def test_record_outside_any_artifact_is_ignored(tmp_path: Path) -> None:
    (tmp_path / ".acb-provenance.yaml").write_text("source: [")
    assert AUDITS["record-fields"](context_for(tmp_path)) == []
