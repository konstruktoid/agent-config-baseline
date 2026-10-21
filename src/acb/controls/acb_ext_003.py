"""ACB-EXT-003: Extension capabilities are recorded and high-risk ones are justified."""

from __future__ import annotations

from typing import TYPE_CHECKING

from acb.extensions import (
    CAPABILITY_RECORD,
    analyse_package,
    mentions,
    module_capabilities,
    parse_capability_lines,
    readme_text,
    run_validator,
)
from acb.model import Finding, Outcome
from acb.scan import safe_read_text

if TYPE_CHECKING:
    from collections.abc import Iterator

    from acb.controls import CheckContext
    from acb.discovery import ExtensionPackage
    from acb.extensions import PackageAnalysis

CONTROL_ID = "ACB-EXT-003"


def _finding(audit: str, outcome: Outcome, message: str, path: str | None) -> Finding:
    return Finding(control_id=CONTROL_ID, audit_id=audit, outcome=outcome, message=message, path=path)


def _packages_with_modules(ctx: CheckContext) -> Iterator[tuple[ExtensionPackage, dict, PackageAnalysis]]:
    for package in ctx.inventory.extension_packages:
        profile = ctx.clients.profile(package.client)
        analysis = analyse_package(package, profile)
        if analysis.modules:
            yield package, profile, analysis


def _check_record_present(ctx: CheckContext) -> list[Finding]:
    audit = "record-present"
    findings: list[Finding] = []
    for package, profile, analysis in _packages_with_modules(ctx):
        record = package.root / CAPABILITY_RECORD
        rel = ctx.relative(record)
        if not record.exists():
            findings.append(
                _finding(audit, Outcome.FAIL, f"package ships in-process modules but has no {CAPABILITY_RECORD}", rel)
            )
            continue
        text = safe_read_text(record)
        if text is None:
            findings.append(_finding(audit, Outcome.NOT_EVALUATED, f"{CAPABILITY_RECORD} could not be read", rel))
            continue
        recorded_modules = {module for module, _kind, _items in parse_capability_lines(text, profile)}
        findings.extend(
            _finding(
                audit,
                Outcome.FAIL,
                f"{CAPABILITY_RECORD} does not record module {module.name}",
                ctx.relative(module),
            )
            for module in analysis.modules
            if module.name not in recorded_modules
        )
    return findings


def _check_high_risk_documented(ctx: CheckContext) -> list[Finding]:
    audit = "high-risk-documented"
    findings: list[Finding] = []
    for package, profile, analysis in _packages_with_modules(ctx):
        high_risk = set(profile.get("extension_packages", {}).get("high_risk_capabilities", []))
        readme = readme_text(package)
        if readme is None:
            findings.append(
                _finding(audit, Outcome.NOT_EVALUATED, "package README could not be read", ctx.relative(package.root))
            )
            continue
        for module in analysis.modules:
            capabilities = module_capabilities(module, profile)
            if capabilities is None:
                findings.append(
                    _finding(audit, Outcome.NOT_EVALUATED, "module could not be read", ctx.relative(module))
                )
                continue
            events, calls = capabilities
            findings.extend(
                _finding(
                    audit,
                    Outcome.FAIL,
                    f"module uses high-risk capability {capability}, which the package README does not name",
                    ctx.relative(module),
                )
                for capability in sorted((events | calls) & high_risk)
                if not mentions(readme, capability)
            )
    return findings


def _check_record_current(ctx: CheckContext) -> list[Finding]:
    audit = "record-current"
    findings: list[Finding] = []
    for package, profile, _analysis in _packages_with_modules(ctx):
        rel = ctx.relative(package.root / CAPABILITY_RECORD)
        if not ctx.run_validators:
            findings.append(
                _finding(audit, Outcome.NOT_EVALUATED, "validators are not enabled (--run-validators)", rel)
            )
            continue
        result = run_validator(package, profile)
        if result.lines is None:
            findings.append(
                _finding(audit, Outcome.NOT_EVALUATED, result.problem or "validator produced no result", rel)
            )
            continue
        text = safe_read_text(package.root / CAPABILITY_RECORD)
        if text is None:
            findings.append(
                _finding(audit, Outcome.FAIL, f"no readable {CAPABILITY_RECORD} to compare with the validator", rel)
            )
            continue
        recorded = parse_capability_lines(text, profile)
        for module, kind, items in sorted(result.lines - recorded):
            findings.append(
                _finding(
                    audit,
                    Outcome.FAIL,
                    f"validator reports {module} {kind}: {', '.join(items)}; not in the record",
                    rel,
                )
            )
        for module, kind, items in sorted(recorded - result.lines):
            findings.append(
                _finding(
                    audit, Outcome.FAIL, f"record lists {module} {kind}: {', '.join(items)}; validator does not", rel
                )
            )
    return findings


AUDITS = {
    "record-present": _check_record_present,
    "high-risk-documented": _check_high_risk_documented,
    "record-current": _check_record_current,
}
