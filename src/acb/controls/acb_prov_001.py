"""ACB-PROV-001: Skills and extension packages carry a provenance record."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from acb.model import Finding, Outcome
from acb.provenance import MISSING, NOT_READABLE, RECORD_NAME, artifacts, is_digest, load_record, record_path

if TYPE_CHECKING:
    from acb.controls import CheckContext

CONTROL_ID = "ACB-PROV-001"

_COMMIT_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


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


def _check_record_present(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for relative, directory in artifacts(ctx).items():
        path = directory / RECORD_NAME
        if path.is_symlink():
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="record-present",
                    outcome=Outcome.NOT_EVALUATED,
                    message=f"{RECORD_NAME} {NOT_READABLE}",
                    path=record_path(relative),
                )
            )
        elif not path.is_file():
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="record-present",
                    outcome=Outcome.FAIL,
                    message=f"{RECORD_NAME} {MISSING} in the artifact directory",
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
    if not is_digest(data.get("digest")):
        problems.append("`digest` is not `h1:` followed by a base64 SHA-256, as docs/artifact-digest.md defines")
    return problems


def _check_record_fields(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for relative, directory in artifacts(ctx).items():
        data, problem = load_record(directory)
        if problem == MISSING:
            continue
        if problem is not None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="record-fields",
                    outcome=Outcome.NOT_EVALUATED if problem == NOT_READABLE else Outcome.FAIL,
                    message=f"{RECORD_NAME} {problem}",
                    path=record_path(relative),
                )
            )
            continue
        findings.extend(
            Finding(
                control_id=CONTROL_ID,
                audit_id="record-fields",
                outcome=Outcome.FAIL,
                message=problem,
                path=record_path(relative),
            )
            for problem in _record_problems(data)
        )
    return findings


AUDITS = {
    "record-present": _check_record_present,
    "record-fields": _check_record_fields,
}
