import hashlib
import os
import re
import sys
from pathlib import Path

import pytest
import yaml

from acb.loader import schema_errors
from acb.provenance import (
    DigestError,
    OperatorFileError,
    OperatorRecords,
    TrustRoot,
    artifact_digest,
    is_digest,
    load_operator_records,
    load_trust_root,
)

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


def test_git_is_skipped_only_at_the_artifact_root(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    (root / ".git" / "objects").mkdir(parents=True)
    (root / ".git" / "HEAD").write_bytes(b"ref: refs/heads/main\n")
    os.mkfifo(root / ".git" / "objects" / "pipe")
    assert artifact_digest(root) == VECTOR
    (root / "nested" / ".git").write_bytes(b"gitdir: ../.git\n")
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


def test_nesting_deeper_than_the_recursion_limit_is_hashed(tmp_path: Path) -> None:
    depth = sys.getrecursionlimit() + 10
    deep = tmp_path
    for _ in range(depth):
        deep /= "d"
        deep.mkdir()
    (deep / "leaf").write_bytes(b"x")
    try:
        assert is_digest(artifact_digest(tmp_path))
    finally:
        # pytest cannot remove a tree this deep, so remove it level by level here.
        (deep / "leaf").unlink()
        for _ in range(depth):
            deep.rmdir()
            deep = deep.parent


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


_OPERATOR_RECORD = (
    f"  source: https://github.com/example/s\n  commit: 0123456789abcdef0123456789abcdef01234567\n  digest: {VECTOR}\n"
)


def _with_source(source: str) -> str:
    return "skills/a:\n" + _OPERATOR_RECORD.replace("https://github.com/example/s", source)


def test_operator_records_load_keyed_by_path(tmp_path: Path) -> None:
    path = tmp_path / "records.yaml"
    path.write_text(f"skills/a:\n{_OPERATOR_RECORD}.:\n{_OPERATOR_RECORD}")
    loaded = load_operator_records(path)
    assert loaded.source == str(path)
    assert sorted(loaded.records) == [".", "skills/a"]
    assert loaded.records["skills/a"]["digest"] == VECTOR


def test_no_operator_records_file_means_no_records() -> None:
    assert load_operator_records(None) == OperatorRecords()


def test_empty_operator_records_file_is_no_records(tmp_path: Path) -> None:
    path = tmp_path / "records.yaml"
    path.write_text("")
    assert load_operator_records(path).records == {}


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("- a list\n", "is not of type 'object'"),
        ("skills/a:\n  source: https://github.com/example/s\n", "'commit' is a required property"),
        (f"skills/a:\n{_OPERATOR_RECORD}  extra: x\n", "Additional properties"),
        (f"/abs:\n{_OPERATOR_RECORD}", "is not a normalised path"),
        (f"skills/../a:\n{_OPERATOR_RECORD}", "is not a normalised path"),
        (f"skills/a/:\n{_OPERATOR_RECORD}", "is not a normalised path"),
        (f"./skills/a:\n{_OPERATOR_RECORD}", "is not a normalised path"),
        (f"skills\\\\a:\n{_OPERATOR_RECORD}", "is not a normalised path"),
        ("1: []\nskills/a: []\n", "1 is not a normalised path"),
        ("skills/a:\n  source: https://github.com/example/s\n  commit: main\n  digest: x\n", "`commit` is not"),
        (_with_source("https://github.com/example/s.git"), "does not match"),
        (_with_source("https://github.com/example/s/"), "does not match"),
        (_with_source("git+https://github.com/example/s"), "does not match"),
        (_with_source("https://github.com"), "does not match"),
        ("skills/a: [\n", "not valid YAML"),
    ],
)
def test_invalid_operator_records_are_refused(tmp_path: Path, text: str, message: str) -> None:
    path = tmp_path / "records.yaml"
    path.write_text(text)
    with pytest.raises(OperatorFileError, match=re.escape(message)):
        load_operator_records(path)


def _write_trust_root(tmp_path: Path, root: dict, config: bytes = b"{}") -> Path:
    (tmp_path / "trust-config.json").write_bytes(config)
    root["sigstore"] = {"trust_config": "trust-config.json", "sha256": hashlib.sha256(b"{}").hexdigest()}
    path = tmp_path / "root.yaml"
    path.write_text(yaml.safe_dump(root))
    return path


def test_trust_root_is_parsed_and_hashed(tmp_path: Path) -> None:
    root = _documented_trust_root()
    path = _write_trust_root(tmp_path, root)
    assert load_trust_root(path) == TrustRoot(
        file=str(path),
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        reason=None,
        policy=root,
        trust_config=str((tmp_path / "trust-config.json").resolve()),
    )


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"config": b"changed"}, "not the pinned"),
        ({"trust_config": "/etc/trust-config.json"}, "is not a path relative to this file"),
        ({"trust_config": "missing.json"}, "is not a file"),
        ({"trust_config": "../trust-config.json"}, "is not inside this file's directory"),
        ({"version": 2}, "version"),
    ],
)
def test_invalid_trust_root_is_refused(tmp_path: Path, change: dict, message: str) -> None:
    root = _documented_trust_root()
    if "version" in change:
        root["version"] = change["version"]
    path = _write_trust_root(tmp_path, root, change.get("config", b"{}"))
    if "trust_config" in change:
        data = yaml.safe_load(path.read_text())
        data["sigstore"]["trust_config"] = change["trust_config"]
        path.write_text(yaml.safe_dump(data))
    with pytest.raises(OperatorFileError, match=re.escape(message)):
        load_trust_root(path)


def test_operator_bundles_resolve_beside_the_records_file(tmp_path: Path) -> None:
    (tmp_path / "bundles").mkdir()
    (tmp_path / "bundles" / "a.json").write_text("{}")
    path = tmp_path / "records.yaml"
    path.write_text(
        f"skills/a:\n  source: https://github.com/e/s\n  commit: {'ab' * 20}\n  digest: h1:{'A' * 43}=\n"
        "  bundles: [bundles/a.json]\n"
    )
    records = load_operator_records(path)
    assert records.bundles == {"skills/a": (str(tmp_path / "bundles" / "a.json"),)}
    assert "bundles" not in records.records["skills/a"]
    path.write_text(path.read_text().replace("bundles/a.json", "bundles/gone.json"))
    with pytest.raises(OperatorFileError, match=re.escape("'bundles/gone.json' is not a file")):
        load_operator_records(path)


@pytest.mark.parametrize("name", ["../outside.json", "bundles/../../outside.json", "link.json"])
def test_operator_bundles_outside_the_records_directory_are_refused(tmp_path: Path, name: str) -> None:
    (tmp_path / "outside.json").write_text("{}")
    (tmp_path / "base").mkdir()
    (tmp_path / "base" / "bundles").mkdir()
    (tmp_path / "base" / "link.json").symlink_to(tmp_path / "outside.json")
    path = tmp_path / "base" / "records.yaml"
    path.write_text(
        f"skills/a:\n  source: https://github.com/e/s\n  commit: {'ab' * 20}\n  digest: h1:{'A' * 43}=\n"
        f"  bundles: [{name}]\n"
    )
    with pytest.raises(OperatorFileError, match=re.escape(f"{name!r} is not inside this file's directory")):
        load_operator_records(path)


def test_operator_bundle_symlink_loop_is_refused(tmp_path: Path) -> None:
    (tmp_path / "loop.json").symlink_to(tmp_path / "loop.json")
    path = tmp_path / "records.yaml"
    path.write_text(
        f"skills/a:\n  source: https://github.com/e/s\n  commit: {'ab' * 20}\n  digest: h1:{'A' * 43}=\n"
        "  bundles: [loop.json]\n"
    )
    with pytest.raises(OperatorFileError, match=re.escape("'loop.json'")):
        load_operator_records(path)


def test_trust_config_symlink_outside_the_trust_root_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / "base").mkdir()
    path = _write_trust_root(tmp_path / "base", _documented_trust_root())
    (tmp_path / "outside.json").write_bytes(b"{}")
    (tmp_path / "base" / "trust-config.json").unlink()
    (tmp_path / "base" / "trust-config.json").symlink_to(tmp_path / "outside.json")
    with pytest.raises(OperatorFileError, match=re.escape("is not inside this file's directory")):
        load_trust_root(path)


def test_operator_bundles_are_absolute_when_the_records_path_is_relative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "bundles").mkdir()
    (tmp_path / "bundles" / "a.json").write_text("{}")
    (tmp_path / "records.yaml").write_text(
        f"skills/a:\n  source: https://github.com/e/s\n  commit: {'ab' * 20}\n  digest: h1:{'A' * 43}=\n"
        "  bundles: [bundles/a.json]\n"
    )
    (tmp_path / "target").mkdir()
    monkeypatch.chdir(tmp_path / "target")
    records = load_operator_records(Path("../records.yaml"))
    assert records.bundles == {"skills/a": (str((tmp_path / "bundles" / "a.json").resolve()),)}


def test_absent_trust_root_is_null_with_a_reason() -> None:
    root = load_trust_root(None)
    assert (root.file, root.sha256, root.reason) == (None, None, "--trust-root not given")


def _documented_trust_root() -> dict:
    doc = (Path(__file__).parents[1] / "docs" / "provenance-design.md").read_text(encoding="utf-8")
    block = re.search(r"trust root lists the identities.*?```yaml\n(.*?)```", doc, re.DOTALL)
    assert block
    root = yaml.safe_load(block.group(1))
    root["sigstore"]["sha256"] = "0" * 64
    return root


def test_documented_trust_root_matches_the_schema() -> None:
    assert schema_errors("trust-root.schema.json", _documented_trust_root()) == []


@pytest.mark.parametrize(
    ("section", "change"),
    [
        ("sigstore", {"sha256": "A" * 64}),
        ("sigstore", {"pattern": "x"}),
        ("build_provenance", {"builders": [{"id": "b", "build_type": "t"}]}),
        ("build_provenance", {"signers": [{"issuer": "i", "build_signer_uris": ["u"], "builders": []}]}),
        ("build_provenance", {"signers": [{"issuer": "i", "builders": [{"id": "b", "build_type": "t"}]}]}),
        ("source_vsa", {"verifiers": [{"id": "v", "issuer": "i", "identity": "a b", "min_source_level": 2}]}),
        ("source_vsa", {"verifiers": [{"id": "v", "issuer": "i", "identity": "a", "min_source_level": 0}]}),
    ],
)
def test_trust_root_schema_rejects(section: str, change: dict) -> None:
    root = _documented_trust_root()
    root[section].update(change)
    assert schema_errors("trust-root.schema.json", root)
