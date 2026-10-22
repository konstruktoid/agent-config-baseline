"""Core data model shared by discovery, control checks, the runner and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path


class Severity(StrEnum):
    """Severity of a control."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Outcome(StrEnum):
    """Result of an audit or a control."""

    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    NOT_EVALUATED = "not-evaluated"
    EXCEPTION = "exception"
    NOT_APPLICABLE = "not-applicable"


@dataclass(frozen=True)
class Finding:
    """A single result for one audit procedure against one location.

    ``path``/``line`` are ``None`` for a control-wide or audit-wide result
    that is not anchored to a specific file (for example a NOT_EVALUATED
    procedure, or an exceptions-file problem).
    """

    control_id: str
    audit_id: str
    outcome: Outcome
    message: str
    path: str | None = None
    line: int | None = None
    justification: str | None = None


@dataclass(frozen=True)
class AuditProcedure:
    """One audit procedure of a control."""

    id: str
    method: str
    procedure: str
    indicators: tuple[str, ...] = ()


@dataclass(frozen=True)
class Control:
    """A security control loaded from a control file."""

    id: str
    title: str
    status: str
    profiles: tuple[str, ...]
    applies_to: tuple[str, ...]
    check_type: str
    severity: Severity
    description: str
    rationale: str
    audit: tuple[AuditProcedure, ...]
    remediation: str
    exceptions: str
    references: dict[str, Any]
    deprecated_by: str | None
    source_path: Path
    raw: dict[str, Any] = field(repr=False)

    @property
    def audit_ids(self) -> tuple[str, ...]:
        """Return the identifiers of the control's audit procedures."""
        return tuple(a.id for a in self.audit)

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: Path) -> Control:
        """Build a control from parsed control data."""
        audits = tuple(
            AuditProcedure(
                id=a["id"],
                method=a["method"],
                procedure=a["procedure"],
                indicators=tuple(a.get("indicators", [])),
            )
            for a in data["audit"]
        )
        return cls(
            id=data["id"],
            title=data["title"],
            status=data["status"],
            profiles=tuple(data["profiles"]),
            applies_to=tuple(data["applies_to"]),
            check_type=data["check_type"],
            severity=Severity(data["severity"]),
            description=data["description"],
            rationale=data["rationale"],
            audit=audits,
            remediation=data["remediation"],
            exceptions=data.get("exceptions", "permitted"),
            references=data.get("references", {}),
            deprecated_by=data.get("deprecated_by"),
            source_path=source_path,
            raw=data,
        )
