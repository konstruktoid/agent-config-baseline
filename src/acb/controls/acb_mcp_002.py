"""ACB-MCP-002: MCP server launch commands are not interpreted by a shell."""

from __future__ import annotations

import re
from pathlib import PurePosixPath, PureWindowsPath

from acb.model import Finding, Outcome

CONTROL_ID = "ACB-MCP-002"

_INTERPRETERS = {"sh", "bash", "zsh", "dash", "ash", "ksh", "fish", "csh", "tcsh", "cmd", "powershell", "pwsh"}
WRAPPERS = {
    "env",
    "sudo",
    "doas",
    "nohup",
    "nice",
    "ionice",
    "exec",
    "command",
    "busybox",
    "xargs",
    "timeout",
    "stdbuf",
    "setsid",
    "time",
}
_EVAL_FLAGS = {"/c", "/k", "-command", "-encodedcommand"}
# A cluster of short options that includes c, such as -c, -lc or -ce; -C (noclobber) is not one.
_POSIX_EVAL_FLAG_RE = re.compile(r"^-[a-zA-Z]*c[a-zA-Z]*$")
_SHELL_OPERATOR_RE = re.compile(r"[;&|<>$`\n]")


def _executable_name(command: str) -> str:
    name = PureWindowsPath(command).name if "\\" in command else PurePosixPath(command).name
    return name.lower().removesuffix(".exe")


def _interpreter_args(command: str, args: object) -> list | None:
    """The arguments the interpreter receives, or None if no interpreter is launched.

    A wrapper such as env or sudo launches the first interpreter named in its
    arguments, so the string-evaluation flag is looked for after that name.
    """
    if not isinstance(args, list):
        args = []
    name = _executable_name(command)
    if name in _INTERPRETERS:
        return args
    if name in WRAPPERS:
        for index, arg in enumerate(args):
            if isinstance(arg, str) and _executable_name(arg) in _INTERPRETERS:
                return args[index + 1 :]
    return None


def _evaluates_string(args: list) -> bool:
    for arg in args:
        if not isinstance(arg, str):
            continue
        if arg.lower() in _EVAL_FLAGS or _POSIX_EVAL_FLAG_RE.match(arg):
            return True
    return False


def _check_no_shell(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for decl in ctx.inventory.mcp_declarations:
        for name, server in decl.servers.items():
            command = server.get("command")
            if not isinstance(command, str):
                continue
            interpreter_args = _interpreter_args(command, server.get("args"))
            if interpreter_args is not None and _evaluates_string(interpreter_args):
                message = f"server {name!r} runs a shell through {command!r} with a string-evaluation flag"
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
