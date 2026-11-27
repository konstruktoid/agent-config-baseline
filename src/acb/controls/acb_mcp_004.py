"""ACB-MCP-004: The mcp-remote proxy is not pinned to a known-vulnerable version."""

from __future__ import annotations

from typing import TYPE_CHECKING

from acb.controls._mcp_proxy import exact_version, proxy_launch
from acb.model import Finding, Outcome

if TYPE_CHECKING:
    from acb.controls import CheckContext

CONTROL_ID = "ACB-MCP-004"

# CVE-2025-6514, inclusive bounds.
_FIRST_AFFECTED = (0, 0, 5)
_LAST_AFFECTED = (0, 1, 15)


def _affected(version: str | None) -> bool:
    numbers = exact_version(version)
    return numbers is not None and _FIRST_AFFECTED <= numbers <= _LAST_AFFECTED


def _check_not_vulnerable(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for decl in ctx.inventory.mcp_declarations:
        for name, server in decl.servers.items():
            launch = proxy_launch(server)
            if launch and launch.package == "mcp-remote" and _affected(launch.version):
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="mcp-remote-not-vulnerable",
                        outcome=Outcome.FAIL,
                        message=f"server {name!r} launches mcp-remote {launch.version}, affected by CVE-2025-6514",
                        path=ctx.relative(decl.path),
                    )
                )
    return findings


AUDITS = {"mcp-remote-not-vulnerable": _check_not_vulnerable}
