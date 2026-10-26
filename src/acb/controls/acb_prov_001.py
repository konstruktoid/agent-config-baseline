"""ACB-PROV-001: Skills and extension packages carry a provenance record."""

from __future__ import annotations

from typing import TYPE_CHECKING

from acb.model import Finding, Outcome
from acb.provenance import MISSING, NOT_READABLE, RECORD_NAME, artifacts, field_problems, load_record, record_path

if TYPE_CHECKING:
    from acb.controls import CheckContext

CONTROL_ID = "ACB-PROV-001"


def _check_record_present(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for relative, directory in artifacts(ctx).items():
        path = directory / RECORD_NAME
        if relative in ctx.provenance_records.records:
            continue
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
    return field_problems(data)


def _check_record_fields(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for relative, directory in artifacts(ctx).items():
        # The operator's record was validated when its file was loaded.
        if relative in ctx.provenance_records.records:
            continue
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
