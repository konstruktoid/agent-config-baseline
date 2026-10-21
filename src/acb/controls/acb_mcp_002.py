"""ACB-MCP-002: MCP server launch commands are not interpreted by a shell."""

from __future__ import annotations

import re
from pathlib import PurePosixPath, PureWindowsPath

from acb.model import Finding, Outcome

CONTROL_ID = "ACB-MCP-002"

_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ash", "ksh", "fish", "csh", "tcsh", "cmd", "powershell", "pwsh"}
_EVAL_FLAGS = {"/c", "/k", "-command", "-encodedcommand"}
_POSIX_EVAL_FLAG_RE = re.compile(r"^-[a-z]*c$")
_SHELL_OPERATOR_RE = re.compile(r"[;&|<>$`\n]")


def _executable_name(command: str) -> str:
    name = PureWindowsPath(command).name if "\\" in command else PurePosixPath(command).name
    return name.lower().removesuffix(".exe")


def _evaluates_string(args: object) -> bool:
    if not isinstance(args, list):
        return False
    for arg in args:
        if not isinstance(arg, str):
            continue
        flag = arg.lower()
        if flag in _EVAL_FLAGS or _POSIX_EVAL_FLAG_RE.match(flag):
            return True
    return False


def _check_no_shell(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for decl in ctx.inventory.mcp_declarations:
        for name, server in decl.servers.items():
            command = server.get("command")
            if not isinstance(command, str):
                continue
            if _executable_name(command) in _INTERPRETERS and _evaluates_string(server.get("args")):
                message = f"server {name!r} runs {command!r} with a string-evaluation flag"
            elif _SHELL_OPERATOR_RE.search(command):
                message = f"server {name!r} command contains a shell operator"
            else:
                continue
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="no-shell-interpretation",
                    outcome=Outcome.FAIL,
                    message=message,
                    path=ctx.relative(decl.path),
                )
            )
    return findings


AUDITS = {"no-shell-interpretation": _check_no_shell}
