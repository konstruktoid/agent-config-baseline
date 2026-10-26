from dataclasses import replace
from pathlib import Path

from acb.controls.acb_prov_002 import AUDITS
from acb.model import Outcome
from acb.provenance import OperatorRecords, artifact_digest
from tests._harness import context_for
from tests.test_controls._shared import check_pass_and_fail


def test_acb_prov_002_fixtures() -> None:
    check_pass_and_fail("ACB-PROV-002", AUDITS)


def _skill(root: Path, name: str = "a") -> Path:
    directory = root / "skills" / name
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(f"---\nname: {name}\ndescription: A test skill for provenance.\n---\n\nBody.\n")
    return directory


def _record(directory: Path, digest: str) -> None:
    (directory / ".acb-provenance.yaml").write_text(
        f"source: https://github.com/example/s\ncommit: {'ab' * 20}\ndigest: {digest}\n"
    )


def _findings(root: Path) -> list[tuple[Outcome, str | None, str]]:
    return [(f.outcome, f.path, f.message) for f in AUDITS["digest-matches"](context_for(root))]


def test_no_artifacts_means_nothing_to_compare(tmp_path: Path) -> None:
    assert _findings(tmp_path) == []


def test_matching_digest_passes_and_the_record_is_not_part_of_it(tmp_path: Path) -> None:
    directory = _skill(tmp_path)
    _record(directory, artifact_digest(directory))
    assert _findings(tmp_path) == []


def test_changed_content_fails_on_the_record(tmp_path: Path) -> None:
    directory = _skill(tmp_path)
    recorded = artifact_digest(directory)
    _record(directory, recorded)
    (directory / "SKILL.md").write_text("---\nname: a\ndescription: A test skill for provenance.\n---\n\nChanged.\n")
    [(outcome, path, message)] = _findings(tmp_path)
    assert (outcome, path) == (Outcome.FAIL, "skills/a/.acb-provenance.yaml")
    assert message == (
        f"recorded digest {recorded} does not match the content, which hashes to {artifact_digest(directory)}"
    )


def test_added_file_fails(tmp_path: Path) -> None:
    directory = _skill(tmp_path)
    _record(directory, artifact_digest(directory))
    (directory / "scripts").mkdir()
    (directory / "scripts" / "run.sh").write_text("echo hi\n")
    assert [outcome for outcome, _, _ in _findings(tmp_path)] == [Outcome.FAIL]


def test_missing_or_malformed_record_is_not_evaluated(tmp_path: Path) -> None:
    _skill(tmp_path, "none")
    _record(_skill(tmp_path, "old-format"), "sha256:" + "ab" * 32)
    (_skill(tmp_path, "broken") / ".acb-provenance.yaml").write_text("digest: [")
    assert _findings(tmp_path) == [
        (Outcome.NOT_EVALUATED, f"skills/{name}", "no well-formed recorded digest to compare (see ACB-PROV-001)")
        for name in ("broken", "none", "old-format")
    ]


def test_uncomputable_digest_is_not_evaluated(tmp_path: Path) -> None:
    directory = _skill(tmp_path)
    _record(directory, artifact_digest(directory))
    (directory / "link.md").symlink_to(directory / "SKILL.md")
    assert _findings(tmp_path) == [
        (Outcome.NOT_EVALUATED, "skills/a", "digest cannot be computed: link.md is a symlink")
    ]


def _operator_findings(root: Path, digest: str) -> list[tuple[Outcome, str | None, str]]:
    record = {"source": "https://github.com/example/s", "commit": "ab" * 20, "digest": digest}
    ctx = replace(
        context_for(root), provenance_records=OperatorRecords(source="records.yaml", records={"skills/a": record})
    )
    return [(f.outcome, f.path, f.message) for f in AUDITS["digest-matches"](ctx)]


def test_operator_record_replaces_a_wrong_in_directory_digest(tmp_path: Path) -> None:
    directory = _skill(tmp_path)
    _record(directory, "h1:" + "A" * 43 + "=")
    assert _operator_findings(tmp_path, artifact_digest(directory)) == []


def test_operator_record_mismatch_fails_on_the_artifact(tmp_path: Path) -> None:
    directory = _skill(tmp_path)
    actual = artifact_digest(directory)
    _record(directory, actual)
    wrong = "h1:" + "A" * 43 + "="
    assert _operator_findings(tmp_path, wrong) == [
        (
            Outcome.FAIL,
            "skills/a",
            f"operator record in records.yaml digest {wrong} does not match the content, which hashes to {actual}",
        )
    ]
