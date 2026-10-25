"""Provenance records and the artifact digest shared by the ACB-PROV controls.

The digest is version 1 of docs/artifact-digest.md: Go's dirhash `h1:` over the artifact directory.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import stat
from typing import TYPE_CHECKING

import yaml

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


class DigestError(Exception):
    """The artifact digest cannot be computed for this directory."""


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


def _files(directory: Path, prefix: str, found: list[str]) -> None:
    """Append the `/`-separated names of every regular file under directory, refusing anything else."""
    try:
        entries = list(os.scandir(directory))
    except OSError as exc:
        msg = f"cannot list {prefix or '.'}: {exc.strerror}"
        raise DigestError(msg) from exc
    for entry in entries:
        if not prefix and entry.name == _SKIPPED_AT_ROOT:
            continue
        name = f"{prefix}{entry.name}"
        try:
            name.encode("utf-8")
        except UnicodeEncodeError:
            msg = f"name {name!r} is not valid UTF-8"
            raise DigestError(msg) from None
        if "\n" in name:
            msg = f"name {name!r} contains a newline"
            raise DigestError(msg)
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
        except OSError as exc:
            msg = f"cannot inspect {name}: {exc.strerror}"
            raise DigestError(msg) from exc
        if stat.S_ISLNK(mode):
            msg = f"{name} is a symlink"
            raise DigestError(msg)
        if stat.S_ISDIR(mode):
            _files(directory / entry.name, f"{name}/", found)
        elif stat.S_ISREG(mode):
            found.append(name)
        else:
            msg = f"{name} is not a regular file or directory"
            raise DigestError(msg)


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
    names: list[str] = []
    _files(directory, "", names)
    names = sorted((n for n in names if n != RECORD_NAME), key=lambda n: n.encode("utf-8"))
    summary = hashlib.sha256()
    for name in names:
        summary.update(f"{_file_sha256(directory / name, name)}  {name}\n".encode())
    return DIGEST_PREFIX + base64.b64encode(summary.digest()).decode("ascii")
