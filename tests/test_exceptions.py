from datetime import date
from pathlib import Path

import pytest

from acb.exceptions import (
    ExceptionEntry,
    ExceptionsFileError,
    apply_exceptions,
    load_exceptions,
)
from acb.model import Control, Finding, Outcome, Severity

KNOWN = {"ACB-GEN-002", "ACB-GEN-003"}


def _control(control_id: str, exceptions: str) -> Control:
    return Control(
        id=control_id,
        title="Test control",
        status="active",
        profiles=("strict-general",),
        applies_to=("skill",),
        check_type="static",
        severity=Severity.HIGH,
        description="x" * 20,
        rationale="x" * 20,
        audit=(),
        remediation="x" * 20,
        exceptions=exceptions,
        references={},
        deprecated_by=None,
        source_path=Path("controls/TEST.yaml"),
        raw={},
    )


def _entry(control: str, path: str, expires: date, index: int = 0) -> ExceptionEntry:
    return ExceptionEntry(
        index=index, control=control, path=path, justification="tracked", approver="reviewer", expires=expires
    )


def _fail(control_id: str, path: str) -> Finding:
    return Finding(control_id=control_id, audit_id="a1", outcome=Outcome.FAIL, message="bad", path=path)


TODAY = date(2026, 1, 1)
PERMITTED = {"ACB-GEN-002": _control("ACB-GEN-002", "permitted")}


def test_matching_unexpired_exception_waives_the_finding_with_justification() -> None:
    result = apply_exceptions(
        [_fail("ACB-GEN-002", "mcp/legacy.json")],
        [_entry("ACB-GEN-002", "mcp/legacy.json", date(2999, 1, 1))],
        PERMITTED,
        today=TODAY,
    )
    assert [f.outcome for f in result.findings] == [Outcome.EXCEPTION]
    assert "tracked" in (result.findings[0].justification or "")
    assert result.stale == ()


def test_expired_exception_does_not_waive_and_points_at_the_exceptions_file() -> None:
    result = apply_exceptions(
        [_fail("ACB-GEN-002", "mcp/legacy.json")],
        [_entry("ACB-GEN-002", "mcp/legacy.json", date(2020, 1, 1))],
        PERMITTED,
        exceptions_file=".acb-exceptions.yaml",
        today=TODAY,
    )
    assert Outcome.EXCEPTION not in {f.outcome for f in result.findings}
    expired = [f for f in result.findings if f.audit_id == "exception-expired"]
    assert expired
    assert expired[0].path == ".acb-exceptions.yaml"


def test_not_permitted_control_ignores_exception_and_reports_attempt() -> None:
    controls = {"ACB-GEN-003": _control("ACB-GEN-003", "not-permitted")}
    result = apply_exceptions(
        [_fail("ACB-GEN-003", "secrets.json")],
        [_entry("ACB-GEN-003", "secrets.json", date(2999, 1, 1))],
        controls,
        today=TODAY,
    )
    assert [f.outcome for f in result.findings if f.audit_id == "a1"] == [Outcome.FAIL]
    assert any(f.audit_id == "exception-not-permitted" for f in result.findings)


def test_star_matches_one_segment_only() -> None:
    result = apply_exceptions(
        [_fail("ACB-GEN-002", "skills/x/run.sh")],
        [_entry("ACB-GEN-002", "*.sh", date(2999, 1, 1))],
        PERMITTED,
        today=TODAY,
    )
    assert result.findings[0].outcome == Outcome.FAIL
    assert len(result.stale) == 1


def test_entry_matching_nothing_is_reported_stale() -> None:
    result = apply_exceptions([], [_entry("ACB-GEN-002", "gone.json", date(2999, 1, 1))], PERMITTED, today=TODAY)
    assert [e.path for e in result.stale] == ["gone.json"]


def test_not_evaluated_findings_cannot_be_waived() -> None:
    finding = Finding(
        control_id="ACB-GEN-002", audit_id="a1", outcome=Outcome.NOT_EVALUATED, message="x", path="a.json"
    )
    result = apply_exceptions([finding], [_entry("ACB-GEN-002", "a.json", date(2999, 1, 1))], PERMITTED, today=TODAY)
    assert result.findings == [finding]


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / ".acb-exceptions.yaml"
    path.write_text(text)
    return path


VALID = (
    "- control: ACB-GEN-002\n  path: mcp/legacy.json\n  justification: tracked in TICKET-1\n"
    "  approver: reviewer\n  expires: {expires}\n"
)


def test_load_none_returns_empty() -> None:
    assert load_exceptions(None, KNOWN) == []


@pytest.mark.parametrize("expires", ["2999-01-01", "'2999-01-01'"])
def test_load_parses_quoted_and_unquoted_dates(tmp_path: Path, expires: str) -> None:
    entries = load_exceptions(_write(tmp_path, VALID.format(expires=expires)), KNOWN)
    assert entries[0].expires == date(2999, 1, 1)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("- control: ACB-GEN-002\n  path: x\n", "required property"),
        (VALID.format(expires="tomorrow"), "expires"),
        (VALID.format(expires="2999-02-30"), "invalid expires date"),
        (VALID.format(expires="2999-01-01").replace("ACB-GEN-002", "ACB-GEN-999"), "unknown control"),
        (VALID.format(expires="2999-01-01").replace("tracked in TICKET-1", "''"), "justification"),
        (VALID.format(expires="2999-01-01").replace("approver: reviewer", "approver: ''"), "approver"),
        (VALID.format(expires="2999-01-01").replace("mcp/legacy.json", "'*'"), "no literal characters"),
        (VALID.format(expires="2999-01-01").replace("mcp/legacy.json", "'**'"), "no literal characters"),
        (VALID.format(expires="2999-01-01") + "  extra: 1\n", "Additional properties"),
        ("control: ACB-GEN-002\n", "is not of type 'array'"),
        ("- [a\n", "not valid YAML"),
    ],
)
def test_load_rejects_invalid_files(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(ExceptionsFileError, match=message):
        load_exceptions(_write(tmp_path, text), KNOWN)


def test_unreadable_file_finding_cannot_be_waived() -> None:
    finding = Finding(
        control_id="ACB-GEN-002",
        audit_id="a1",
        outcome=Outcome.NOT_EVALUATED,
        message="file could not be read",
        path="skills/a.bin",
    )
    entry = _entry("ACB-GEN-002", "skills/**", date(2999, 1, 1))
    result = apply_exceptions([finding], [entry], PERMITTED, today=TODAY)
    assert result.findings == [finding]
    assert len(result.stale) == 1
