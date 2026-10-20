"""ACB-EXT-004: Blocking guards have tests that prove they deny."""

from __future__ import annotations

from pathlib import Path

from acb.extensions import analyse_package, blocking_hooks, hook_script_files, module_capabilities
from acb.model import Finding, Outcome
from acb.scan import safe_read_text

CONTROL_ID = "ACB-EXT-004"
_AUDIT = "guards-have-tests"


def _finding(outcome: Outcome, message: str, path: str | None) -> Finding:
    return Finding(control_id=CONTROL_ID, audit_id=_AUDIT, outcome=outcome, message=message, path=path)


def _variables(profile: dict, project: Path, package: Path | None) -> dict[str, Path]:
    bases = {"project": project, "package": package}
    variables = profile.get("agent_settings", {}).get("hook_path_variables", {})
    return {name: bases[kind] for name, kind in variables.items() if bases.get(kind) is not None}


def _check_guards_have_tests(ctx) -> list[Finding]:
    findings: list[Finding] = []
    test_texts: dict[Path, str | None] = {}

    def referenced_by_a_test(script: Path) -> bool:
        for test in ctx.inventory.test_files:
            if test == script:
                continue
            if test not in test_texts:
                test_texts[test] = safe_read_text(test)
            text = test_texts[test]
            if text is not None and script.name in text:
                return True
        return False

    # (hooks mapping, where it came from, project root, package root, client profile)
    sources = []
    for settings in ctx.inventory.agent_settings:
        sources.append((settings.data, ctx.relative(settings.path), ctx.root, None, ctx.clients.profile(settings.client)))
    for package in ctx.inventory.extension_packages:
        profile = ctx.clients.profile(package.client)
        analysis = analyse_package(package, profile)
        for rel in analysis.unreadable:
            findings.append(_finding(Outcome.NOT_EVALUATED, f"hook configuration {rel} could not be read or parsed", ctx.relative(package.manifest)))
        for origin, config in analysis.hook_configs:
            where = ctx.relative(package.manifest if origin == "manifest" else package.root / origin)
            sources.append((config, where, ctx.root, package.root, profile))

        guard_events = set(profile.get("extension_packages", {}).get("guard_events", []))
        test_suffixes = tuple(profile.get("extension_packages", {}).get("module_test_suffixes", []))
        has_module_test = bool(test_suffixes) and any(
            p.is_file() and p.name.endswith(test_suffixes) for p in package.root.rglob("*")
        )
        for module in analysis.modules:
            capabilities = module_capabilities(module, profile)
            if capabilities is None:
                findings.append(_finding(Outcome.NOT_EVALUATED, "module could not be read", ctx.relative(module)))
                continue
            guarded = sorted(capabilities[0] & guard_events)
            if guarded and not has_module_test:
                findings.append(
                    _finding(
                        Outcome.FAIL,
                        f"module guards {', '.join(guarded)} but the package has no module test file",
                        ctx.relative(module),
                    )
                )

    for config, where, project, package_root, profile in sources:
        variables = _variables(profile, project, package_root)
        for hook in blocking_hooks(config, where, profile):
            scripts = hook_script_files(hook.handler, variables, ctx.root)
            if not scripts:
                findings.append(
                    _finding(Outcome.FAIL, f"blocking {hook.event} hook runs no script file a test can exercise", where)
                )
                continue
            for script in scripts:
                if not referenced_by_a_test(script):
                    findings.append(
                        _finding(
                            Outcome.FAIL,
                            f"blocking {hook.event} hook script {script.name} (from {where}) is not referenced by any test",
                            ctx.relative(script),
                        )
                    )
    return findings


AUDITS = {
    _AUDIT: _check_guards_have_tests,
}
