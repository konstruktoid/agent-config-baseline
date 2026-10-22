"""ACB-GEN-001: Remote content is never piped into an interpreter."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from acb.model import Finding, Outcome
from acb.scan import files_for, line_of

if TYPE_CHECKING:
    from collections.abc import Iterator

    from acb.controls import CheckContext
    from acb.scan import TextFile

CONTROL_ID = "ACB-GEN-001"

# Fetch-like calls: network clients plus the .NET WebClient download methods used
# from PowerShell (New-Object Net.WebClient).DownloadString(...) etc., which are
# themselves the "fetch" half of a download-then-eval pattern even with no pipe.
_FETCH = (
    r"(?:curl|wget|http|Invoke-WebRequest|iwr|irm|Invoke-RestMethod|"
    r"DownloadString|DownloadData|DownloadFile)"
)
_INTERP = (
    r"(?:sh|bash|zsh|ksh|dash|python3?|node|perl|ruby|iex|Invoke-Expression|pwsh|"
    r"powershell|cmd|fish|php|deno|source)"
)
# Wrapper commands that may sit between a pipe and the real interpreter:
# sudo/doas/env (with flags) and xargs (with flags, e.g. `xargs -I{} sh -c`).
_WRAPPER = r"(?:(?:sudo|doas|env)\s+(?:-\S+\s+)*|xargs\s+(?:-\S+\s+)*)*"
# The interpreter invoked by full or relative path (e.g. `/bin/bash`, `/usr/bin/env`
# isn't here since it's a wrapper, but `/bin/bash` itself is), not just a bare name.
_INTERP_PATH = rf"(?:\S*/)?{_INTERP}"

_CONTINUATION_RE = re.compile(r"\\\r?\n")

# Each pattern matches one way remote content can reach an interpreter: a pipe
# (plain or `|&`, optionally through sudo/doas/env/xargs), a process substitution,
# a command substitution (`$(...)` or backticks), a call-operator wrapper (bounded
# gap so `iex (New-Object ...).DownloadString(...)` matches too), a two-step
# download-then-exec, or a Python exec(urlopen(...).read()) one-liner.
#
# Gaps between the fetch call and the interpreter use a *bounded* quantifier
# (`{0,200}` on a negated character class, or `{0,200}?`) rather than an
# unbounded lazy `[^\n]*?`. An unbounded lazy scan means every occurrence of
# the fetch keyword re-scans forward across the rest of the (possibly huge)
# line looking for a pipe that may not exist, which is quadratic in pathological
# input (e.g. "curl " repeated thousands of times on one line). Bounding the
# gap caps the work per anchor to a constant, making the whole scan linear.
_PATTERNS = [
    re.compile(rf"\b{_FETCH}\b[^|\n]{{0,200}}\|&?\s*{_WRAPPER}{_INTERP_PATH}\b", re.IGNORECASE),
    re.compile(rf"(?<![\w./-]){_INTERP_PATH}\b\s*<\(\s*{_FETCH}\b", re.IGNORECASE),
    re.compile(rf"(?m)(?:^|[;&|]\s*)\.\s+<\(\s*{_FETCH}\b", re.IGNORECASE),
    re.compile(rf"\$\(\s*{_FETCH}\b[^)\n]{{0,200}}\)", re.IGNORECASE),
    # Backtick substitution only counts as one when an interpreter consumes it
    # (bash -c "`curl ...`"); an inline code span naming curl is documentation.
    re.compile(rf"(?<![\w./-]){_INTERP_PATH}\b[^\n`]{{0,60}}`\s*{_FETCH}\b[^`\n]{{0,200}}`", re.IGNORECASE),
    # eval/exec/source and a leading `.` run what a backtick span prints; so does a
    # span used as the whole command. Documentation names `curl` in spans too, so
    # these require a URL inside the span.
    re.compile(
        rf"(?:\b(?:eval|exec|source)\s+(?:[\"'])?|(?<![\w./-])\.\s+(?:[\"'])?|(?m:^)\s*)"
        rf"`\s*{_FETCH}\b[^`\n]{{0,200}}(?:https?|ftp)://[^`\n]*`",
        re.IGNORECASE,
    ),
    re.compile(rf"(?<![\w./-]){_INTERP_PATH}\b\s*\([^\n]{{0,200}}?{_FETCH}\b", re.IGNORECASE),
    re.compile(
        rf"\b{_FETCH}\b[^\n]{{0,200}}-o\s+(\S+)[^\n]{{0,200}}(?:&&|;)\s*{_WRAPPER}(?:{_INTERP_PATH}\s+)?\1\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"exec\(\s*(?:[\w.]+\.)?urlopen\([^)\n]{0,150}\)\s*\.\s*read\(\)",
        re.IGNORECASE,
    ),
]


def _dejoin_continuations(text: str) -> str:
    r"""Turn shell line-continuations (`\` + newline) into same-length whitespace.

    Keeps every character offset identical to the original text (2 chars in,
    2 spaces out; 3 in for CRLF, 3 spaces out) so `line_of` and substring
    slicing against the original text both still work, while letting the
    bounded `[^\n]`-based gaps above see a continued shell line as one line.
    """
    return _CONTINUATION_RE.sub(lambda m: " " * len(m.group(0)), text)


def _json_leaf_strings(data: object) -> Iterator[str]:
    if isinstance(data, str):
        yield data
    elif isinstance(data, dict):
        for value in data.values():
            yield from _json_leaf_strings(value)
    elif isinstance(data, list):
        for value in data:
            yield from _json_leaf_strings(value)


def _scan_json_strings(f: TextFile) -> list[Finding]:
    """Decode a .json file and scan each string leaf value with the same patterns.

    Belt-and-suspenders alongside the raw-text scan below: raw-text matching
    already catches a fetch-then-pipe pattern written as a plain JSON string
    value in the common case, but decoding and scanning the string values
    directly is robust to any JSON-escaping shape regardless of how the file
    was serialized, so it is done unconditionally for every .json file.
    """
    findings: list[Finding] = []
    if f.text is None or f.path.suffix != ".json":
        return findings
    try:
        data = json.loads(f.text)
    except json.JSONDecodeError:
        return findings
    for leaf in _json_leaf_strings(data):
        for pattern in _PATTERNS:
            for match in pattern.finditer(leaf):
                idx = f.text.find(match.group(0))
                line = line_of(f.text, idx) if idx != -1 else None
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="pipe-to-interpreter",
                        outcome=Outcome.FAIL,
                        message=(
                            "remote fetch piped or substituted into an interpreter "
                            f"(in a JSON string value): {match.group(0)!r}"
                        ),
                        path=f.relative,
                        line=line,
                    )
                )
    return findings


def _check_pipe_to_interpreter(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill", "instruction-file", "mcp-server-declaration")):
        if f.text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="pipe-to-interpreter",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify compliance",
                    path=f.relative,
                )
            )
            continue

        scan_text = _dejoin_continuations(f.text)
        for pattern in _PATTERNS:
            for match in pattern.finditer(scan_text):
                display = f.text[match.start() : match.end()]
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="pipe-to-interpreter",
                        outcome=Outcome.FAIL,
                        message=f"remote fetch piped or substituted into an interpreter: {display!r}",
                        path=f.relative,
                        line=line_of(f.text, match.start()),
                    )
                )
        findings.extend(_scan_json_strings(f))
    return findings


AUDITS = {
    "pipe-to-interpreter": _check_pipe_to_interpreter,
}
