"""Provenance records and the artifact digest shared by the ACB-PROV controls.

The digest is version 1 of docs/artifact-digest.md: Go's dirhash `h1:` over the artifact directory.

A record comes from the artifact's own `.acb-provenance.yaml` unless the operator's records file
(--provenance-records FILE, schema/provenance-records.schema.json) has an entry for the artifact's
root-relative path; that entry replaces the in-directory record as a whole. Only an operator entry
can name Sigstore bundles, by paths relative to the records file:

    skills/example:
      source: https://github.com/example/skills
      commit: 0123456789abcdef0123456789abcdef01234567
      digest: h1:...
      bundles: [bundles/example.sigstore.json]

The trust root (--trust-root FILE, schema/trust-root.schema.json) is parsed, and the Sigstore client trust
configuration it names is checked against its pinned SHA-256 before any control reads it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import yaml

from acb.loader import schema_errors
from acb.scan import safe_read_text
from acb.yamlsafe import safe_load_strict

if TYPE_CHECKING:
    from pathlib import Path

    from acb.controls import CheckContext

RECORD_NAME = ".acb-provenance.yaml"
# A package at a repository root holds the repository's own `.git`, which changes on every fetch.
_SKIPPED_AT_ROOT = ".git"
DIGEST_PREFIX = "h1:"

MISSING = "does not exist"
NOT_READABLE = "could not be read (not valid UTF-8 text, or is a symlink); cannot verify"

_CHUNK = 1 << 16
_SHA256_BYTES = 32
_COMMIT_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


class DigestError(Exception):
    """The artifact digest cannot be computed for this directory."""


class OperatorFileError(Exception):
    """Raised when an operator-supplied provenance file is invalid or unreadable."""


@dataclass(frozen=True)
class OperatorRecords:
    """Provenance records from the operator's file, keyed by root-relative artifact path."""

    source: str | None = None
    records: dict[str, dict[str, str]] = field(default_factory=dict)
    # Bundle paths resolved against the records file, kept apart so a record stays a mapping of strings.
    bundles: dict[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class TrustRoot:
    """The operator's trust root: its SHA-256 or why there is none, its parsed policy and its trust config path."""

    file: str | None = None
    sha256: str | None = None
    reason: str | None = "--trust-root not given"
    policy: dict = field(default_factory=dict)
    trust_config: str | None = None


def _valid_source(value: object) -> bool:
    """Report whether value is an https URL with a hostname and a repository path."""
    if not isinstance(value, str) or re.search(r"\s", value):
        return False
    try:
        parts = urlsplit(value)
        # Reading the port raises ValueError for a non-numeric or out-of-range one.
        _ = parts.port
    except ValueError:
        return False
    return parts.scheme == "https" and bool(parts.hostname) and bool(parts.path.strip("/"))


def field_problems(data: dict) -> list[str]:
    """Return what is wrong with a record mapping's `source`, `commit` and `digest`."""
    problems = []
    if not _valid_source(data.get("source")):
        problems.append("`source` is not an https:// URL with a hostname and a repository path")
    if not isinstance(data.get("commit"), str) or not _COMMIT_RE.fullmatch(data["commit"]):
        problems.append("`commit` is not a full lowercase hexadecimal commit hash")
    if not is_digest(data.get("digest")):
        problems.append("`digest` is not `h1:` followed by a base64 SHA-256, as docs/artifact-digest.md defines")
    return problems


def _valid_key(key: object) -> bool:
    """Report whether key is a normalised root-relative POSIX path, `.` naming the root itself."""
    if key == ".":
        return True
    if not isinstance(key, str) or not key or key.startswith("/") or "\\" in key:
        return False
    parts = key.split("/")
    return all(part not in ("", ".", "..") for part in parts) and PurePosixPath(key).as_posix() == key


def _load_operator_yaml(path: Path) -> Any:  # noqa: ANN401
    try:
        return safe_load_strict(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        msg = f"{path}: cannot be read: {exc}"
        raise OperatorFileError(msg) from exc
    except (yaml.YAMLError, RecursionError, TypeError, ValueError) as exc:
        msg = f"{path}: not valid YAML: {exc}"
        raise OperatorFileError(msg) from exc


def _beside(path: Path, name: str, what: str) -> Path:
    """Return `name` resolved against the directory of the operator file at `path`, which must hold a file there."""
    if PurePosixPath(name).is_absolute() or "\\" in name:
        msg = f"{path}: {what} {name!r} is not a path relative to this file"
        raise OperatorFileError(msg)
    target = path.parent / name
    if not target.is_file():
        msg = f"{path}: {what} {name!r} is not a file"
        raise OperatorFileError(msg)
    return target


def load_operator_records(path: Path | None) -> OperatorRecords:
    """Load and validate the operator's provenance records file."""
    if path is None:
        return OperatorRecords()
    data = _load_operator_yaml(path)
    if data is None:
        data = {}

    # Schema errors sort by path, which raises TypeError when keys mix integers and strings.
    for key in data if isinstance(data, dict) else ():
        if not _valid_key(key):
            msg = f"{path}: {key!r} is not a normalised path relative to the audited root"
            raise OperatorFileError(msg)

    errors = schema_errors("provenance-records.schema.json", data)
    if errors:
        raise OperatorFileError(f"{path}: " + "; ".join(errors))

    records: dict[str, dict[str, str]] = {}
    bundles: dict[str, tuple[str, ...]] = {}
    for key, entry in data.items():
        problems = field_problems(entry)
        if problems:
            raise OperatorFileError(f"{path}: {key}: " + "; ".join(problems))
        records[key] = {name: value for name, value in entry.items() if name != "bundles"}
        if "bundles" in entry:
            bundles[key] = tuple(str(_beside(path, name, f"{key}: bundle").resolve()) for name in entry["bundles"])
    return OperatorRecords(source=str(path), records=records, bundles=bundles)


def load_trust_root(path: Path | None) -> TrustRoot:
    """Parse and validate the trust root, and check its Sigstore trust config against the pinned SHA-256."""
    if path is None:
        return TrustRoot()
    try:
        content = path.read_bytes()
    except OSError as exc:
        msg = f"{path}: cannot be read: {exc}"
        raise OperatorFileError(msg) from exc
    data = _load_operator_yaml(path)
    errors = schema_errors("trust-root.schema.json", data)
    if errors:
        raise OperatorFileError(f"{path}: " + "; ".join(errors))
    if not isinstance(data, dict):
        msg = f"{path}: not a mapping"
        raise OperatorFileError(msg)

    config = _beside(path, data["sigstore"]["trust_config"], "sigstore.trust_config")
    try:
        actual = hashlib.sha256(config.read_bytes()).hexdigest()
    except OSError as exc:
        msg = f"{config}: cannot be read: {exc}"
        raise OperatorFileError(msg) from exc
    if actual != data["sigstore"]["sha256"]:
        msg = f"{path}: {config} has SHA-256 {actual}, not the pinned {data['sigstore']['sha256']}"
        raise OperatorFileError(msg)
    return TrustRoot(
        file=str(path),
        sha256=hashlib.sha256(content).hexdigest(),
        reason=None,
        policy=data,
        trust_config=str(config.resolve()),
    )


def unused_operator_records(ctx: CheckContext) -> tuple[str, ...]:
    """Return operator record keys that name no inventoried skill or extension package."""
    inventoried = artifacts(ctx)
    return tuple(key for key in ctx.provenance_records.records if key not in inventoried)


def artifacts(ctx: CheckContext) -> dict[str, Path]:
    """Return every skill directory and extension package root, keyed by its root-relative path."""
    directories = {ctx.relative(skill.directory): skill.directory for skill in ctx.inventory.skills}
    directories.update({ctx.relative(package.root): package.root for package in ctx.inventory.extension_packages})
    return dict(sorted(directories.items()))


def record_path(relative: str) -> str:
    """Return the root-relative path of the record for the artifact at `relative`."""
    return RECORD_NAME if relative in ("", ".") else f"{relative}/{RECORD_NAME}"


def load_record(directory: Path) -> tuple[object, str | None]:
    """Return the parsed record and a problem, where a missing file is a problem and not an exception."""
    path = directory / RECORD_NAME
    if not path.is_file() and not path.is_symlink():
        return None, MISSING
    text = safe_read_text(path)
    if text is None:
        return None, NOT_READABLE
    try:
        return safe_load_strict(text), None
    except (yaml.YAMLError, ValueError, TypeError, RecursionError) as exc:
        return None, f"does not parse as YAML: {exc}"


def resolve_record(ctx: CheckContext, relative: str, directory: Path) -> tuple[object, str | None, bool]:
    """Return the record, a problem, and whether the record is the operator's rather than the in-directory one."""
    operator = ctx.provenance_records.records.get(relative)
    if operator is not None:
        return operator, None, True
    data, problem = load_record(directory)
    return data, problem, False


def is_digest(value: object) -> bool:
    """Report whether value is `h1:` followed by the padded standard base64 of 32 bytes."""
    if not isinstance(value, str) or not value.startswith(DIGEST_PREFIX):
        return False
    encoded = value[len(DIGEST_PREFIX) :]
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) == _SHA256_BYTES and base64.b64encode(raw).decode("ascii") == encoded


def _entry_name(prefix: str, entry: os.DirEntry[str]) -> str:
    """Return the entry's `/`-separated name, refusing one that is not valid UTF-8 or contains a newline."""
    name = f"{prefix}{entry.name}"
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        msg = f"name {name!r} is not valid UTF-8"
        raise DigestError(msg) from None
    if "\n" in name:
        msg = f"name {name!r} contains a newline"
        raise DigestError(msg)
    return name


def _entry_mode(entry: os.DirEntry[str], name: str) -> int:
    """Return the entry's own mode, refusing a symlink."""
    try:
        mode = entry.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        msg = f"cannot inspect {name}: {exc.strerror}"
        raise DigestError(msg) from exc
    if stat.S_ISLNK(mode):
        msg = f"{name} is a symlink"
        raise DigestError(msg)
    return mode


def _files(root: Path) -> list[str]:
    """Return the `/`-separated names of every regular file under root, refusing anything else."""
    found: list[str] = []
    # An explicit stack, so directory depth cannot exhaust the Python call stack.
    pending: list[tuple[Path, str]] = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            msg = f"cannot list {prefix or '.'}: {exc.strerror}"
            raise DigestError(msg) from exc
        for entry in entries:
            if not prefix and entry.name == _SKIPPED_AT_ROOT:
                continue
            name = _entry_name(prefix, entry)
            mode = _entry_mode(entry, name)
            if stat.S_ISDIR(mode):
                pending.append((directory / entry.name, f"{name}/"))
            elif stat.S_ISREG(mode):
                found.append(name)
            else:
                msg = f"{name} is not a regular file or directory"
                raise DigestError(msg)
    return found


def _file_sha256(path: Path, name: str) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        msg = f"cannot read {name}: {exc.strerror}"
        raise DigestError(msg) from exc
    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, "rb") as handle:
            while chunk := handle.read(_CHUNK):
                digest.update(chunk)
    except OSError as exc:
        msg = f"cannot read {name}: {exc.strerror}"
        raise DigestError(msg) from exc
    return digest.hexdigest()


def artifact_digest(directory: Path) -> str:
    """Return the version 1 digest of an artifact directory, or raise DigestError."""
    if directory.is_symlink():
        msg = "the artifact directory is a symlink"
        raise DigestError(msg)
    names = sorted((n for n in _files(directory) if n != RECORD_NAME), key=lambda n: n.encode("utf-8"))
    summary = hashlib.sha256()
    for name in names:
        summary.update(f"{_file_sha256(directory / name, name)}  {name}\n".encode())
    return DIGEST_PREFIX + base64.b64encode(summary.digest()).decode("ascii")
