"""ACB-MCP-003: MCP server environment does not set process-startup hijack variables."""

from __future__ import annotations

import re

from acb.model import Finding, Outcome

CONTROL_ID = "ACB-MCP-003"

_ENV_KEYS = ("env", "environment")
_ALWAYS_HIJACK = {"LD_PRELOAD", "BASH_ENV"}
_NODE_LOADING_OPTION_RE = re.compile(r"(?:^|\s)(?:--require|-r|--import|--loader|--experimental-loader)(?:[\s=]|$)")


def _env_pairs(env: object) -> list[tuple[str, str]]:
    if isinstance(env, dict):
        return [(str(name), str(value)) for name, value in env.items() if value is not None]
    if isinstance(env, list):
        return [
            (str(item["name"]), str(item.get("value", "")))
            for item in env
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        ]
    return []


def _hijacks(name: str, value: str) -> bool:
    upper = name.upper()
    if upper in _ALWAYS_HIJACK:
        return bool(value.strip())
    return upper == "NODE_OPTIONS" and bool(_NODE_LOADING_OPTION_RE.search(value))


def _check_no_hijack_env(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for decl in ctx.inventory.mcp_declarations:
        for name, server in decl.servers.items():
            for key in _ENV_KEYS:
                for var, value in _env_pairs(server.get(key)):
                    if _hijacks(var, value):
                        findings.append(
                            Finding(
                                control_id=CONTROL_ID,
                                audit_id="no-hijack-env",
                                outcome=Outcome.FAIL,
                                message=f"server {name!r} sets process-startup hijack variable {var}",
                                path=ctx.relative(decl.path),
                            )
                        )
    return findings


AUDITS = {"no-hijack-env": _check_no_hijack_env}
