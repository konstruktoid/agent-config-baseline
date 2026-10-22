"""ACB-EXT-004: Blocking guards have tests that prove they deny."""

from __future__ import annotations

from typing import TYPE_CHECKING

from acb.extensions import (
    analyse_package,
    blocking_hooks,
    hook_script_files,
    mentions,
    module_capabilities,
)
from acb.model import Finding, Outcome
from acb.scan import safe_read_text

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from acb.controls import CheckContext
    from acb.discovery import ExtensionPackage
    from acb.extensions import PackageAnalysis

CONTROL_ID = "ACB-EXT-004"
_AUDIT = "guards-have-tests"
# A tests/ directory also holds notes and data; only code can exercise a guard.
_NON_CODE_SUFFIXES = {".md", ".rst", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".csv"}


def _finding(outcome: Outcome, message: str, path: str | None) -> Finding:
    return Finding(control_id=CONTROL_ID, audit_id=_AUDIT, outcome=outcome, message=message, path=path)


def _variables(profile: dict, project: Path, package: Path | None) -> dict[str, Path]:
    bases = {"project": project, "package": package}
    variables = profile.get("agent_settings", {}).get("hook_path_variables", {})
    return {name: base for name, kind in variables.items() if (base := bases.get(kind)) is not None}


def _module_test_findings(
    ctx: CheckContext, package: ExtensionPackage, profile: dict, analysis: PackageAnalysis
) -> list[Finding]:
    """Check that each guard module in a package is referenced by a module test file."""
    findings: list[Finding] = []
    guard_events = set(profile.get("extension_packages", {}).get("guard_events", []))
    test_suffixes = tuple(profile.get("extension_packages", {}).get("module_test_suffixes", []))
    module_tests = [
        p for p in package.root.rglob("*") if test_suffixes and p.is_file() and p.name.endswith(test_suffixes)
    ]
    for module in analysis.modules:
        capabilities = module_capabilities(module, profile)
        if capabilities is None:
            findings.append(_finding(Outcome.NOT_EVALUATED, "module could not be read", ctx.relative(module)))
            continue
        guarded = sorted(capabilities[0] & guard_events)
        stem = module.name.rsplit(".", 1)[0]
        tested = any(
            (text := safe_read_text(t)) is not None
            and (mentions(text, module.name, after_directory=True) or mentions(text, stem, after_directory=True))
            for t in module_tests
        )
        if guarded and not tested:
            findings.append(
                _finding(
                    Outcome.FAIL,
                    f"module guards {', '.join(guarded)} but no module test file in the package references it",
                    ctx.relative(module),
                )
            )
    return findings


def _hook_script_findings(
    ctx: CheckContext, sources: list[tuple], referenced_by_a_test: Callable[[Path], bool]
) -> list[Finding]:
    """Check that each script a blocking hook runs is referenced by a test."""
    findings: list[Finding] = []
    for config, where, project, package_root, profile in sources:
        variables = _variables(profile, project, package_root)
        for hook in blocking_hooks(config, where, profile):
            scripts = hook_script_files(hook.handler, variables, ctx.root)
            if not scripts:
                findings.append(
                    _finding(Outcome.FAIL, f"blocking {hook.event} hook runs no script file a test can exercise", where)
                )
                continue
            findings.extend(
                _finding(
                    Outcome.FAIL,
                    f"blocking {hook.event} hook script {script.name} (from {where}) is not referenced by any test",
                    ctx.relative(script),
                )
                for script in scripts
                if not referenced_by_a_test(script)
            )
    return findings


def _check_guards_have_tests(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    test_texts: dict[Path, str | None] = {}

    def referenced_by_a_test(script: Path) -> bool:
        for test in ctx.inventory.test_files:
            if test == script or test.suffix.lower() in _NON_CODE_SUFFIXES:
                continue
            if test not in test_texts:
                test_texts[test] = safe_read_text(test)
            text = test_texts[test]
            if text is not None and mentions(text, script.name, after_directory=True):
                return True
        return False

    # (hooks mapping, where it came from, project root, package root, client profile)
    sources = []
    sources.extend(
        (settings.data, ctx.relative(settings.path), ctx.root, None, ctx.clients.profile(settings.client))
        for settings in ctx.inventory.agent_settings
    )
    for package in ctx.inventory.extension_packages:
        profile = ctx.clients.profile(package.client)
        analysis = analyse_package(package, profile)
        findings.extend(
            _finding(
                Outcome.NOT_EVALUATED,
                f"hook configuration {rel} could not be read or parsed",
                ctx.relative(package.manifest),
            )
            for rel in analysis.unreadable
        )
        for origin, config in analysis.hook_configs:
            where = ctx.relative(package.manifest if origin == "manifest" else package.root / origin)
            sources.append((config, where, ctx.root, package.root, profile))
        findings.extend(_module_test_findings(ctx, package, profile, analysis))

    findings.extend(_hook_script_findings(ctx, sources, referenced_by_a_test))
    return findings


AUDITS = {
    _AUDIT: _check_guards_have_tests,
}
