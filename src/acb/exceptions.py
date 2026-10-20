"""The single reviewed exceptions file.

Read from --exceptions FILE, by default ./.acb-exceptions.yaml relative to
the current working directory, never from inside the scanned PATH. Format
(schema/exceptions.schema.json):

    - control: ACB-GEN-002
      path: "mcp/legacy-server.json"
      justification: "Vendor has no hashed release yet; tracked in TICKET-123."
      approver: "jane.doe"
      expires: "2026-12-31"

`path` is a pattern relative to PATH (see acb.paths); it matches a finding's
file, not its directories, so waiving a directory needs an explicit `dir/**`.
There is no inline suppression syntax anywhere else. An expired entry waives
nothing and is itself a failure. A control with `exceptions: not-permitted`
ignores any entry naming it and reports the attempt as a failure.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path

import yaml

from acb.loader import schema_errors
from acb.model import Control, Finding, Outcome
from acb.paths import PatternError, matches, validate_pattern
from acb.yamlsafe import safe_load_strict

EXCEPTIONS_FILENAME = ".acb-exceptions.yaml"


class ExceptionsFileError(Exception):
    pass


@dataclass(frozen=True)
class ExceptionEntry:
    index: int
    control: str
    path: str
    justification: str
    approver: str
    expires: date


@dataclass(frozen=True)
class ExceptionsResult:
    findings: list[Finding]
    stale: tuple[ExceptionEntry, ...]


def load_exceptions(path: Path | None, known_control_ids: set[str]) -> list[ExceptionEntry]:
    if path is None:
        return []
    try:
        data = safe_load_strict(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise ExceptionsFileError(f"{path}: cannot be read: {exc}") from exc
    except (yaml.YAMLError, RecursionError, TypeError, ValueError) as exc:
        # ValueError: PyYAML rejects an unquoted impossible date such as 2999-02-30 itself.
        raise ExceptionsFileError(f"{path}: not valid YAML (invalid expires date?): {exc}") from exc
    if data is None:
        data = []

    # YAML resolves an unquoted 2026-12-31 to a date; the schema expects text.
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and isinstance(item.get("expires"), date):
                item["expires"] = item["expires"].isoformat()

    errors = schema_errors("exceptions.schema.json", data)
    if errors:
        raise ExceptionsFileError(f"{path}: " + "; ".join(errors))

    entries: list[ExceptionEntry] = []
    for index, item in enumerate(data):
        if item["control"] not in known_control_ids:
            raise ExceptionsFileError(f"{path}: entry {index} names unknown control {item['control']!r}")
        try:
            expires = date.fromisoformat(item["expires"])
        except ValueError as exc:
            raise ExceptionsFileError(f"{path}: entry {index} has an invalid expires date: {exc}") from exc
        try:
            pattern = validate_pattern(item["path"])
        except PatternError as exc:
            raise ExceptionsFileError(f"{path}: entry {index}: {exc}") from exc
        entries.append(
            ExceptionEntry(
                index=index,
                control=item["control"],
                path=pattern,
                justification=item["justification"],
                approver=item["approver"],
                expires=expires,
            )
        )
    return entries


def apply_exceptions(
    findings: list[Finding],
    entries: list[ExceptionEntry],
    controls_by_id: dict[str, Control],
    exceptions_file: str | None = None,
    today: date | None = None,
) -> ExceptionsResult:
    """Waive FAIL findings covered by a valid entry; fail on invalid entries.

    A waived finding keeps its location and gains the entry's justification
    (reported, e.g. as a SARIF suppression), with outcome EXCEPTION. Only
    FAIL findings anchored to a file can be waived; NOT_EVALUATED cannot.
    """
    today = today or date.today()
    used: set[int] = set()
    result: list[Finding] = []

    for finding in findings:
        if finding.outcome != Outcome.FAIL or finding.path is None:
            result.append(finding)
            continue
        control = controls_by_id.get(finding.control_id)
        waiver = None
        if control is not None and control.exceptions == "permitted":
            for entry in entries:
                if entry.control == finding.control_id and entry.expires >= today and matches(finding.path, entry.path):
                    waiver = entry
                    break
        if waiver is None:
            result.append(finding)
        else:
            used.add(waiver.index)
            result.append(
                replace(
                    finding,
                    outcome=Outcome.EXCEPTION,
                    justification=f"{waiver.justification} (approved by {waiver.approver}, expires {waiver.expires.isoformat()})",
                )
            )

    for entry in entries:
        control = controls_by_id.get(entry.control)
        if control is not None and control.exceptions == "not-permitted":
            used.add(entry.index)
            result.append(
                Finding(
                    control_id=entry.control,
                    audit_id="exception-not-permitted",
                    outcome=Outcome.FAIL,
                    message=f"exception entry {entry.index} for {entry.path!r} ignored: {entry.control} does not permit exceptions",
                    path=exceptions_file,
                )
            )
        elif entry.expires < today:
            used.add(entry.index)
            result.append(
                Finding(
                    control_id=entry.control,
                    audit_id="exception-expired",
                    outcome=Outcome.FAIL,
                    message=f"exception entry {entry.index} for {entry.path!r} expired on {entry.expires.isoformat()}",
                    path=exceptions_file,
                )
            )

    stale = tuple(e for e in entries if e.index not in used)
    return ExceptionsResult(findings=result, stale=stale)
