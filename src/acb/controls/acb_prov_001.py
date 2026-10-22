"""ACB-PROV-001: Skills and extension packages carry a provenance record."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import yaml

from acb.model import Finding, Outcome
from acb.scan import safe_read_text
from acb.yamlsafe import safe_load_strict

if TYPE_CHECKING:
    from pathlib import Path

    from acb.controls import CheckContext

CONTROL_ID = "ACB-PROV-001"
RECORD_NAME = ".acb-provenance.yaml"

_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_RE = re.compile(r"^https://[^\s/]+/\S+$")

_NOT_READABLE = "could not be read (not valid UTF-8 text, or is a symlink); cannot verify"


def _artifact_paths(ctx: CheckContext) -> list[str]:
    skills = (ctx.relative(skill.directory) for skill in ctx.inventory.skills)
    packages = (ctx.relative(package.root) for package in ctx.inventory.extension_packages)
    return sorted({*skills, *packages})


def _load_record(ctx: CheckContext) -> tuple[object, str | None]:
    """Return the parsed record and a problem, where a missing file is a problem and not an exception."""
    path: Path = ctx.root / RECORD_NAME
    if not path.is_file() and not path.is_symlink():
        return None, "does not exist"
    text = safe_read_text(path)
    if text is None:
        return None, _NOT_READABLE
    try:
        return safe_load_strict(text), None
    except (yaml.YAMLError, ValueError, TypeError, RecursionError) as exc:
        return None, f"does not parse as YAML: {exc}"


def _entries(data: object) -> list[object] | None:
    if not isinstance(data, dict):
        return None
    artifacts = data.get("artifacts")
    return artifacts if isinstance(artifacts, list) else None


def _check_record_present(ctx: CheckContext) -> list[Finding]:
    paths = _artifact_paths(ctx)
    if not paths:
        return []
    data, problem = _load_record(ctx)
    if problem is not None and problem != "does not exist":
        return [
            Finding(
                control_id=CONTROL_ID,
                audit_id="record-present",
                outcome=Outcome.NOT_EVALUATED,
                message=f"{RECORD_NAME} {problem}",
                path=RECORD_NAME,
            )
        ]
    entries = _entries(data) or []
    listed = {entry.get("path") for entry in entries if isinstance(entry, dict)}
    missing_file = problem is not None
    return [
        Finding(
            control_id=CONTROL_ID,
            audit_id="record-present",
            outcome=Outcome.FAIL,
            message=f"{RECORD_NAME} does not exist" if missing_file else f"no entry for {path!r} in {RECORD_NAME}",
            path=path,
        )
        for path in paths
        if missing_file or path not in listed
    ]


def _entry_problems(entry: object) -> list[str]:
    if not isinstance(entry, dict):
        return ["entry is not a mapping"]
    problems = []
    if not isinstance(entry.get("path"), str) or not entry["path"]:
        problems.append("`path` is missing or not a string")
    if not isinstance(entry.get("source"), str) or not _SOURCE_RE.match(entry["source"]):
        problems.append("`source` is not an https:// URL")
    if not isinstance(entry.get("commit"), str) or not _COMMIT_RE.match(entry["commit"]):
        problems.append("`commit` is not a full lowercase hexadecimal commit hash")
    if not isinstance(entry.get("digest"), str) or not _DIGEST_RE.match(entry["digest"]):
        problems.append("`digest` is not `sha256:` followed by 64 lowercase hexadecimal characters")
    return problems


def _check_record_fields(ctx: CheckContext) -> list[Finding]:
    if not (ctx.root / RECORD_NAME).exists() and not (ctx.root / RECORD_NAME).is_symlink():
        return []
    data, problem = _load_record(ctx)
    if problem is not None:
        outcome = Outcome.NOT_EVALUATED if problem == _NOT_READABLE else Outcome.FAIL
        return [
            Finding(
                control_id=CONTROL_ID,
                audit_id="record-fields",
                outcome=outcome,
                message=f"{RECORD_NAME} {problem}",
                path=RECORD_NAME,
            )
        ]
    entries = _entries(data)
    if entries is None:
        return [
            Finding(
                control_id=CONTROL_ID,
                audit_id="record-fields",
                outcome=Outcome.FAIL,
                message=f"{RECORD_NAME} is not a mapping with an `artifacts` list",
                path=RECORD_NAME,
            )
        ]
    findings: list[Finding] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        label = entry.get("path") if isinstance(entry, dict) and isinstance(entry.get("path"), str) else f"#{index}"
        findings.extend(
            Finding(
                control_id=CONTROL_ID,
                audit_id="record-fields",
                outcome=Outcome.FAIL,
                message=f"artifacts entry {label!r}: {problem}",
                path=RECORD_NAME,
            )
            for problem in _entry_problems(entry)
        )
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            if entry["path"] in seen:
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="record-fields",
                        outcome=Outcome.FAIL,
                        message=f"artifacts entry {label!r}: `path` appears more than once",
                        path=RECORD_NAME,
                    )
                )
            seen.add(entry["path"])
    return findings


AUDITS = {
    "record-present": _check_record_present,
    "record-fields": _check_record_fields,
}
