"""ACB-EXT-001: In-process extension code is declared in package documentation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from acb.extensions import analyse_package, mentions, readme_text
from acb.model import Finding, Outcome

if TYPE_CHECKING:
    from acb.controls import CheckContext

CONTROL_ID = "ACB-EXT-001"
_AUDIT = "modules-documented"


def _finding(outcome: Outcome, message: str, path: str | None) -> Finding:
    return Finding(control_id=CONTROL_ID, audit_id=_AUDIT, outcome=outcome, message=message, path=path)


def _check_modules_documented(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for package in ctx.inventory.extension_packages:
        analysis = analyse_package(package, ctx.clients.profile(package.client))
        findings.extend(
            _finding(
                Outcome.NOT_EVALUATED,
                f"hook configuration {rel} could not be read or parsed",
                ctx.relative(package.manifest),
            )
            for rel in analysis.unreadable
        )
        if not analysis.modules:
            continue
        readme = readme_text(package)
        if readme is None:
            findings.append(
                _finding(Outcome.NOT_EVALUATED, "package README could not be read", ctx.relative(package.root))
            )
            continue
        for module in analysis.modules:
            name = module.relative_to(package.root).as_posix()
            if not mentions(readme, name):
                where = "the package has no README" if readme == "" else "the package README does not name it"
                findings.append(
                    _finding(Outcome.FAIL, f"in-process module {name} is undeclared: {where}", ctx.relative(module))
                )
    return findings


AUDITS = {
    _AUDIT: _check_modules_documented,
}
