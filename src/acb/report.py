"""Format findings as text, JSON, or SARIF 2.1.0.

Every format states where its configuration came from (operator config,
exclusions and their reasons, exceptions file, client data) and what was
not scanned, so a clean result can be traced to what made it clean.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import quote
from dataclasses import dataclass
from typing import Any

from acb.clients import ClientData
from acb.config import CheckerConfig
from acb.discovery import Inventory
from acb.exceptions import ExceptionEntry
from acb.model import Control, Finding, Outcome, Severity
from acb.runner import control_outcome

DOCS_BASE_URL = "https://github.com/konstruktoid/agent-config-baseline/blob/main/docs/controls"
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

_SARIF_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


@dataclass(frozen=True)
class RunInfo:
    version: str
    target: str
    config: CheckerConfig
    exceptions_file: str | None
    exception_count: int
    stale_exceptions: tuple[ExceptionEntry, ...]
    clients: ClientData
    inventory: Inventory
    uri_prefix: str = ""
    operator_files_inside_path: tuple[str, ...] = ()


def _run_dict(info: RunInfo) -> dict[str, Any]:
    inventory = info.inventory
    return {
        "acb_version": info.version,
        "target": info.target,
        "inventory": {
            "skills": len(inventory.skills),
            "instruction_files": len(inventory.instruction_files),
            "mcp_declarations": len(inventory.mcp_declarations),
        },
        "config": str(info.config.source) if info.config.source else None,
        "exclusions": [
            {"path": e.pattern, "reason": e.reason, "excluded_entries": inventory.excluded.get(e.pattern, 0)}
            for e in info.config.exclude
        ],
        "exceptions_file": info.exceptions_file,
        "exception_entries": info.exception_count,
        "stale_exceptions": [
            {"entry": e.index, "control": e.control, "path": e.path} for e in info.stale_exceptions
        ],
        "client_data": str(info.clients.source) if info.clients.source else None,
        "clients": list(info.clients.clients),
        "unscanned": [{"path": u.path, "reason": u.reason} for u in inventory.unscanned],
        "notes": list(inventory.notes),
        "operator_files_inside_path": list(info.operator_files_inside_path),
    }


def _counts(controls: list[Control], findings: list[Finding], inventory: Inventory) -> dict[Outcome, int]:
    counts = {o: 0 for o in (Outcome.PASS, Outcome.FAIL, Outcome.NOT_EVALUATED, Outcome.NOT_APPLICABLE)}
    for control in controls:
        counts[control_outcome(control, findings, inventory)] += 1
    return counts


def format_text(controls: list[Control], findings: list[Finding], info: RunInfo) -> str:
    run = _run_dict(info)
    inv = run["inventory"]
    lines = [
        f"acb {info.version} (strict-general) PATH: {info.target}",
        f"inventory: {inv['skills']} skill(s), {inv['instruction_files']} instruction file(s), "
        f"{inv['mcp_declarations']} MCP declaration(s)",
        f"config: {run['config'] or 'none'}",
    ]
    for exclusion in run["exclusions"]:
        lines.append(
            f"  excluded: {exclusion['path']} ({exclusion['excluded_entries']} entries): {exclusion['reason']}"
        )
    exceptions = f"{run['exceptions_file']} ({run['exception_entries']} entries)" if run["exceptions_file"] else "none"
    lines.append(f"exceptions: {exceptions}")
    for stale in run["stale_exceptions"]:
        lines.append(f"  stale: entry {stale['entry']} ({stale['control']} {stale['path']}) matched no finding")
    clients = ", ".join(run["clients"]) or "no clients declared"
    lines.append(f"client data: {run['client_data'] or 'none'} ({clients})")
    for unscanned in run["unscanned"]:
        lines.append(f"unscanned: {unscanned['path']}: {unscanned['reason']}")
    for note in run["notes"]:
        lines.append(f"note: {note}")
    for inside in run["operator_files_inside_path"]:
        lines.append(
            f"warning: operator file {inside} is inside the scanned PATH, so the content being checked can "
            "change how it is checked; protect that file with review"
        )
    lines.append("")

    by_control: dict[str, list[Finding]] = {}
    for f in findings:
        by_control.setdefault(f.control_id, []).append(f)

    for control in controls:
        outcome = control_outcome(control, findings, info.inventory)
        lines.append(f"[{outcome.value.upper():^14}] {control.id}  {control.title}")
        for f in by_control.get(control.id, []):
            location = ""
            if f.path:
                location = f" {f.path}" + (f":{f.line}" if f.line else "")
            prefix = "waived " if f.outcome == Outcome.EXCEPTION else ""
            lines.append(f"            - {prefix}({f.audit_id}){location}: {f.message}")
            if f.justification:
                lines.append(f"              justification: {f.justification}")

    counts = _counts(controls, findings, info.inventory)
    lines.append("")
    lines.append(
        f"{counts[Outcome.PASS]} passed, {counts[Outcome.FAIL]} failed, "
        f"{counts[Outcome.NOT_EVALUATED]} not evaluated, {counts[Outcome.NOT_APPLICABLE]} not applicable "
        f"(of {len(controls)} controls)"
    )
    return "\n".join(lines)


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "control_id": f.control_id,
        "audit_id": f.audit_id,
        "outcome": f.outcome.value,
        "message": f.message,
        "path": f.path,
        "line": f.line,
        "justification": f.justification,
    }


def format_json(controls: list[Control], findings: list[Finding], info: RunInfo) -> str:
    summary = {c.id: control_outcome(c, findings, info.inventory).value for c in controls}
    payload = {
        "run": _run_dict(info),
        "summary": summary,
        "findings": [_finding_dict(f) for f in findings],
        "passed": all(v in (Outcome.PASS.value, Outcome.NOT_APPLICABLE.value) for v in summary.values()),
    }
    return json.dumps(payload, indent=2)


def _rule_name(title: str) -> str:
    return "".join(word[:1].upper() + word[1:] for word in re.findall(r"[A-Za-z0-9]+", title))


def _uri(f: Finding, info: RunInfo) -> str:
    # Exceptions-file findings are already relative to the working directory.
    if f.audit_id.startswith("exception-"):
        return quote(Path(f.path).name if f.path else ".")
    return quote(f"{info.uri_prefix}/{f.path}" if info.uri_prefix else (f.path or "."))


def format_sarif(controls: list[Control], findings: list[Finding], info: RunInfo) -> str:
    rules = [
        {
            "id": c.id,
            "name": _rule_name(c.title),
            "shortDescription": {"text": c.title},
            "fullDescription": {"text": c.description},
            "helpUri": f"{DOCS_BASE_URL}/{c.id}.md",
            "defaultConfiguration": {"level": _SARIF_LEVEL[c.severity]},
            "properties": {"severity": c.severity.value},
        }
        for c in controls
    ]
    rule_index = {c.id: i for i, c in enumerate(controls)}
    controls_by_id = {c.id: c for c in controls}

    results: list[dict[str, Any]] = []
    notifications: list[dict[str, Any]] = []
    for f in findings:
        control = controls_by_id.get(f.control_id)
        level = _SARIF_LEVEL[control.severity] if control else "warning"
        if f.outcome == Outcome.NOT_EVALUATED or (f.outcome == Outcome.FAIL and not f.path):
            notifications.append(
                {
                    "level": "error",
                    "message": {"text": f"{f.control_id} ({f.audit_id}) {f.outcome.value}: {f.message}"},
                    "associatedRule": {"id": f.control_id},
                }
            )
            continue
        if f.outcome not in (Outcome.FAIL, Outcome.EXCEPTION):
            continue
        result: dict[str, Any] = {
            "ruleId": f.control_id,
            "ruleIndex": rule_index.get(f.control_id, -1),
            "level": level,
            "message": {"text": f"({f.audit_id}) {f.message}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _uri(f, info)},
                        **({"region": {"startLine": f.line}} if f.line else {}),
                    }
                }
            ],
        }
        if f.outcome == Outcome.EXCEPTION:
            result["suppressions"] = [{"kind": "external", "status": "accepted", "justification": f.justification}]
        results.append(result)

    for unscanned in info.inventory.unscanned:
        notifications.append({"level": "error", "message": {"text": f"unscanned {unscanned.path}: {unscanned.reason}"}})
    for f in findings:
        if f.outcome == Outcome.NOT_APPLICABLE:
            notifications.append({"level": "note", "message": {"text": f"{f.control_id} ({f.audit_id}) not applicable: {f.message}"}})
    unchecked = bool(info.inventory.unscanned) or any(f.outcome == Outcome.NOT_EVALUATED for f in findings)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "acb",
                        "version": info.version,
                        "semanticVersion": info.version,
                        "informationUri": "https://github.com/konstruktoid/agent-config-baseline",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"acb/strict-general/{info.uri_prefix or '.'}/"},
                "invocations": [{"executionSuccessful": not unchecked, "toolExecutionNotifications": notifications}],
                "results": results,
                "properties": {"acb": _run_dict(info)},
            }
        ],
    }
    return json.dumps(sarif, indent=2)


FORMATTERS = {
    "text": format_text,
    "json": format_json,
    "sarif": format_sarif,
}
