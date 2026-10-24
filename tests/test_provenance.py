import os
from pathlib import Path

import pytest

from acb.provenance import DigestError, artifact_digest, is_digest

# Computed independently with the coreutils pipeline in docs/artifact-digest.md.
VECTOR = "h1:o/uGDuAbkDBX1DRjlGY4rn/96S3QScbuSxrf9Xu9N4g="


def _tree(root: Path) -> Path:
    files = {
        "SKILL.md": b"---\nname: s\ndescription: d\n---\nBody\r\n",
        "references/B.md": b"a",
        "references/a.md": b"b",
        "references/deep/zero": b"",
        ".hidden": b"x",
        "references/ünï.md": "ü".encode(),
        "Z": b"z",
        ".acb-provenance.yaml": b"rec",
        "nested/.acb-provenance.yaml": b"inner",
    }
    for name, content in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(content)
    (root / "empty").mkdir()
    return root


def test_digest_matches_the_independent_vector(tmp_path: Path) -> None:
    assert artifact_digest(_tree(tmp_path)) == VECTOR


def test_root_record_is_excluded_and_nested_record_is_not(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / ".acb-provenance.yaml").write_bytes(b"changed")
    assert artifact_digest(root) == VECTOR
    (root / "nested" / ".acb-provenance.yaml").write_bytes(b"changed")
    assert artifact_digest(root) != VECTOR


def test_empty_directories_and_modes_do_not_count(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "another-empty").mkdir()
    (root / "Z").chmod(0o755)
    assert artifact_digest(root) == VECTOR


def test_content_bytes_are_not_normalised(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "SKILL.md").write_bytes(b"---\nname: s\ndescription: d\n---\nBody\n")
    assert artifact_digest(root) != VECTOR


def test_symlink_inside_the_artifact_is_refused(tmp_path: Path) -> None:
    root = _tree(tmp_path / "s")
    (root / "link.md").symlink_to(root / "Z")
    with pytest.raises(DigestError, match=r"link\.md is a symlink"):
        artifact_digest(root)


def test_symlinked_artifact_directory_is_refused(tmp_path: Path) -> None:
    root = _tree(tmp_path / "s")
    (tmp_path / "alias").symlink_to(root)
    with pytest.raises(DigestError, match="artifact directory is a symlink"):
        artifact_digest(tmp_path / "alias")


def test_special_file_is_refused(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    os.mkfifo(root / "pipe")
    with pytest.raises(DigestError, match="pipe is not a regular file or directory"):
        artifact_digest(root)


def test_newline_in_a_name_is_refused(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / "bad\nname").write_bytes(b"")
    with pytest.raises(DigestError, match="contains a newline"):
        artifact_digest(root)


def test_non_utf8_name_is_refused(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    try:
        (Path(os.fsencode(root).decode("utf-8", "surrogateescape")) / os.fsdecode(b"bad\xff")).write_bytes(b"")
    except (OSError, UnicodeError):
        pytest.skip("the file system does not accept non-UTF-8 names")
    with pytest.raises(DigestError, match="not valid UTF-8"):
        artifact_digest(root)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (VECTOR, True),
        ("h1:" + "A" * 43 + "=", True),
        ("sha256:" + "ab" * 32, False),
        ("H1:" + VECTOR[3:], False),
        (VECTOR[:-1], False),
        (VECTOR[:-2] + "h=", False),
        ("h1:" + "A" * 42 + "==", False),
        (VECTOR + "\n", False),
        (None, False),
    ],
)
def test_is_digest(value: object, *, expected: bool) -> None:
    assert is_digest(value) is expected
