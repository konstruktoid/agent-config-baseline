"""ACB-PROV-001: Skills and extension packages carry a provenance record."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

import yaml

from acb.model import Finding, Outcome
from acb.scan import safe_read_text
from acb.yamlsafe import safe_load_strict

if TYPE_CHECKING:
    from pathlib import Path

    from acb.controls import CheckContext

CONTROL_ID = "ACB-PROV-001"
RECORD_NAME = ".acb-provenance.yaml"

_COMMIT_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")

_MISSING = "does not exist"
_NOT_READABLE = "could not be read (not valid UTF-8 text, or is a symlink); cannot verify"


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


def _artifacts(ctx: CheckContext) -> dict[str, Path]:
    """Return every skill directory and extension package root, keyed by its root-relative path."""
    directories = {ctx.relative(skill.directory): skill.directory for skill in ctx.inventory.skills}
    directories.update({ctx.relative(package.root): package.root for package in ctx.inventory.extension_packages})
    return dict(sorted(directories.items()))


def _record_path(relative: str) -> str:
    return RECORD_NAME if relative in ("", ".") else f"{relative}/{RECORD_NAME}"


def _load_record(directory: Path) -> tuple[object, str | None]:
    """Return the parsed record and a problem, where a missing file is a problem and not an exception."""
    path = directory / RECORD_NAME
    if not path.is_file() and not path.is_symlink():
        return None, _MISSING
    text = safe_read_text(path)
    if text is None:
        return None, _NOT_READABLE
    try:
        return safe_load_strict(text), None
    except (yaml.YAMLError, ValueError, TypeError, RecursionError) as exc:
        return None, f"does not parse as YAML: {exc}"


def _check_record_present(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for relative, directory in _artifacts(ctx).items():
        path = directory / RECORD_NAME
        if path.is_symlink():
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="record-present",
                    outcome=Outcome.NOT_EVALUATED,
                    message=f"{RECORD_NAME} {_NOT_READABLE}",
                    path=_record_path(relative),
                )
            )
        elif not path.is_file():
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="record-present",
                    outcome=Outcome.FAIL,
                    message=f"{RECORD_NAME} {_MISSING} in the artifact directory",
                    path=relative,
                )
            )
    return findings


def _record_problems(data: object) -> list[str]:
    if not isinstance(data, dict):
        return [f"{RECORD_NAME} is not a mapping"]
    problems = []
    if not _valid_source(data.get("source")):
        problems.append("`source` is not an https:// URL with a hostname and a repository path")
    if not isinstance(data.get("commit"), str) or not _COMMIT_RE.fullmatch(data["commit"]):
        problems.append("`commit` is not a full lowercase hexadecimal commit hash")
    if not isinstance(data.get("digest"), str) or not _DIGEST_RE.fullmatch(data["digest"]):
        problems.append("`digest` is not `sha256:` followed by 64 lowercase hexadecimal characters")
    return problems


def _check_record_fields(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for relative, directory in _artifacts(ctx).items():
        data, problem = _load_record(directory)
        if problem == _MISSING:
            continue
        if problem is not None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="record-fields",
                    outcome=Outcome.NOT_EVALUATED if problem == _NOT_READABLE else Outcome.FAIL,
                    message=f"{RECORD_NAME} {problem}",
                    path=_record_path(relative),
                )
            )
            continue
        findings.extend(
            Finding(
                control_id=CONTROL_ID,
                audit_id="record-fields",
                outcome=Outcome.FAIL,
                message=problem,
                path=_record_path(relative),
            )
            for problem in _record_problems(data)
        )
    return findings


AUDITS = {
    "record-present": _check_record_present,
    "record-fields": _check_record_fields,
}
