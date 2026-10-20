"""Core data model shared by discovery, control checks, the runner and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Outcome(str, Enum):
    PASS = "pass"
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
    id: str
    method: str
    procedure: str
    indicators: tuple[str, ...] = ()


@dataclass(frozen=True)
class Control:
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
        return tuple(a.id for a in self.audit)

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: Path) -> "Control":
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
