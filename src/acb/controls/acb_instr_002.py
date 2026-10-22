"""ACB-INSTR-002: Instructions do not modify agent configuration or instruction files."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from acb.model import Finding, Outcome
from acb.scan import files_for, line_of

if TYPE_CHECKING:
    from collections.abc import Iterator

    from acb.controls import CheckContext
    from acb.scan import TextFile

CONTROL_ID = "ACB-INSTR-002"

_NAME_END = r"(?![\w-])"


def _instruction_names(ctx: CheckContext) -> list[str]:
    """Return the instruction-file names to look for.

    That is the AGENTS.md convention plus whatever client data declares. No product's file name is built in.
    """
    return sorted({"AGENTS.md", *ctx.clients.instruction_file_names}, key=str.lower)


_CONFIG_WRITE_PATTERNS = (
    re.compile(r"\binstall\b[\s\S]{0,40}\bskill\b[\s\S]{0,40}\bglobally\b", re.IGNORECASE),
    re.compile(r"\balways available\b", re.IGNORECASE),
    re.compile(r"\bregister\b[\s\S]{0,60}\bmcp server\b", re.IGNORECASE),
    # "Insert this server into .mcp.json" -- a write-shaped verb targeting
    # the MCP server declaration file directly, by name.
    re.compile(r"\b(?:insert|add|write|register)\b[\s\S]{0,60}\.mcp\.json\b", re.IGNORECASE),
    re.compile(
        r"\b(modify|append|write)\b[\s\S]{0,40}\b(settings|hooks|config|configuration)\b",
        re.IGNORECASE,
    ),
    # A shell command copying/writing into a path that looks like a skill
    # or agent-config install location, e.g. "cp -r . ~/.acme/skills/foo"
    # or "cp bundle ~/.config/acme/skills/foo". Expressed as generic path
    # shapes (~/.config/*/skills/, ~/.*/skills/) rather than one vendor's
    # concrete directory.
    re.compile(
        r"\b(?:cp|mv|rsync|install|tee)\b[^\n]{0,40}?~/(?:\.config/[^/\s]+/skills/|\.[^/\s]+/skills/)",
        re.IGNORECASE,
    ),
)

# Simple write-like markers used to decide whether text near a config-write
# path is actually performing a write, rather than merely mentioning it.
_WRITE_MARKER_SUBSTRINGS = ("cp ", "mv ", "Set-Content", "open(", ".write(", "WriteAllText", "echo ")
_WRITE_MARKER_WORD_RE = re.compile(r"\btee\b", re.IGNORECASE)
# A bare '>' or '>>' only counts as shell redirection when it is plausibly
# one: preceded by whitespace, not part of "->" or "=>" (those never have a
# space directly before the '>').
_REDIRECT_RE = re.compile(r"(?<=\s)>{1,2}(?!>)")

_WINDOW = 80


def _looks_like_write(window: str) -> bool:
    if any(marker in window for marker in _WRITE_MARKER_SUBSTRINGS):
        return True
    if _WRITE_MARKER_WORD_RE.search(window):
        return True
    return bool(_REDIRECT_RE.search(window))


def _path_variants(path_str: str) -> list[str]:
    """Equivalent spellings of a declared path worth searching for.

    A declared path starting with "~/" is also matched in its env-var
    expanded form ("$HOME/..." / "${HOME}/..."), since scripts commonly use
    either spelling.
    """
    variants = [path_str]
    if path_str.startswith("~/"):
        rest = path_str[2:]
        variants.append(f"$HOME/{rest}")
        variants.append(f"${{HOME}}/{rest}")
    return variants


def _iter_occurrences(text: str, needle: str) -> Iterator[int]:
    """Yield the start index of every (non-overlapping) occurrence of needle."""
    start = 0
    while True:
        idx = text.find(needle, start)
        if idx == -1:
            return
        yield idx
        start = idx + len(needle)


def _directive_patterns(ctx: CheckContext) -> list[re.Pattern[str]]:
    # "Update AGENTS.md to include...", "Save the following rules into AGENTS.md":
    # a write-shaped verb followed by an instruction-file name.
    alternatives = "|".join(re.escape(n) for n in _instruction_names(ctx))
    verbs = r"\b(?:add|append|write|edit|update|insert|modify|save|put|place|copy|overwrite|replace)\b"
    named = re.compile(rf"{verbs}[\s\S]{{0,60}}(?<![\w.-])(?:{alternatives}){_NAME_END}", re.IGNORECASE)
    return [named, *_CONFIG_WRITE_PATTERNS]


def _check_config_write_directives(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    patterns = _directive_patterns(ctx)
    for f in files_for(ctx, ("skill", "instruction-file")):
        if f.text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="config-write-directives",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify compliance",
                    path=f.relative,
                )
            )
            continue
        for pattern in patterns:
            match = pattern.search(f.text)
            if match:
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="config-write-directives",
                        outcome=Outcome.FAIL,
                        message=f"instruction directs writing to agent configuration: {match.group(0)!r}",
                        path=f.relative,
                        line=line_of(f.text, match.start()),
                    )
                )
    return findings


_SCRIPT_SUFFIXES = {
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".psm1",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".rb",
    ".pl",
    ".php",
    ".mk",
}


def _is_script(f: TextFile, text: str) -> bool:
    parts = f.relative.lower().split("/")
    return (
        "scripts" in parts[:-1]
        or f.path.suffix.lower() in _SCRIPT_SUFFIXES
        or f.path.name.lower() in {"makefile", "justfile"}
        or (f.path.suffix == "" and text.startswith("#!"))
        or text.startswith("#!")
    )


def _instruction_write_res(ctx: CheckContext) -> list[re.Pattern[str]]:
    names = sorted({*_instruction_names(ctx), "SKILL.md"}, key=str.lower)
    name = r"[^\s\"'>|;&]*(?:" + "|".join(re.escape(n) for n in names) + rf"){_NAME_END}"
    end = r"[\"']?\s*(?:$|[;&|)])"
    return [
        re.compile(rf">{{1,2}}\s*[\"']?{name}", re.IGNORECASE),
        re.compile(rf"\btee\b[^\n;|]*?{name}", re.IGNORECASE),
        re.compile(rf"\b(?:cp|mv|install|rsync|ln)\b[^\n;|]*\s[\"']?{name}{end}", re.IGNORECASE | re.MULTILINE),
        re.compile(rf"\bsed\b[^\n;|]*\s-i\b[^\n;|]*{name}", re.IGNORECASE),
        re.compile(rf"\b(?:Set-Content|Add-Content|Out-File)\b[^\n;|]*{name}", re.IGNORECASE),
        re.compile(rf"\bopen\([^)\n]*{name}[^)\n]*,\s*[\"'][wax]", re.IGNORECASE),
        re.compile(rf"{name}[\"']?\)?\.(?:write_text|write_bytes)\(", re.IGNORECASE),
        re.compile(rf"\bdd\b[^\n;|]*\bof={name}", re.IGNORECASE),
        re.compile(rf"\b(?:perl|ruby)\b[^\n;|]*\s-pi\b[^\n;|]*{name}", re.IGNORECASE),
        re.compile(rf"\bCopy-Item\b[^\n;|]*{name}", re.IGNORECASE),
        re.compile(rf"\bshutil\.(?:copy|copy2|copyfile|move)\([^)\n]*{name}", re.IGNORECASE),
        re.compile(
            rf"\bfs\.(?:promises\.)?(?:writeFile|writeFileSync|appendFile|appendFileSync)\([^)\n]*{name}", re.IGNORECASE
        ),
        re.compile(rf"\bFile\.(?:write|open)\([^)\n]*{name}", re.IGNORECASE),
        re.compile(rf"\[IO\.File\]::\w+\([^)\n]*{name}", re.IGNORECASE),
        re.compile(rf"\bopen\([^)\n]*{name}[^)\n]*,\s*(?:mode\s*=\s*)?[\"'][wax]", re.IGNORECASE),
    ]


def _instruction_file_writes(ctx: CheckContext) -> list[Finding]:
    """Fail if a bundled script writes to a file named like an agent instruction file or skill.

    This is the client-independent half of the procedure.
    """
    patterns = _instruction_write_res(ctx)
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill",)):
        if f.text is None:
            # A script that cannot be read could be writing anything.
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="config-write-scripts",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify",
                    path=f.relative,
                )
            )
            continue
        if not _is_script(f, f.text):
            continue
        for pattern in patterns:
            findings.extend(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="config-write-scripts",
                    outcome=Outcome.FAIL,
                    message=f"script writes to an agent instruction file: {match.group(0).strip()!r}",
                    path=f.relative,
                    line=line_of(f.text, match.start()),
                )
                for match in pattern.finditer(f.text)
            )
    return findings


def _check_config_write_scripts(ctx: CheckContext) -> list[Finding]:
    """Fail if a bundled script writes to an instruction-file name or a client-declared location.

    Instruction-file names are always checked.

    The location list is per-client data (``ctx.clients.config_write_paths``).
    With none loaded, that half has no scope and is reported as
    NOT_APPLICABLE rather than PASS.
    """
    findings = _instruction_file_writes(ctx)
    paths = ctx.clients.config_write_paths
    if not paths:
        findings.append(
            Finding(
                control_id=CONTROL_ID,
                audit_id="config-write-scripts",
                outcome=Outcome.NOT_APPLICABLE,
                message=(
                    "no client-declared configuration locations in scope (none in the loaded client data); "
                    "writes to instruction-file names were checked"
                ),
            )
        )
        return findings
    for f in files_for(ctx, ("skill", "instruction-file")):
        if f.text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="config-write-scripts",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify compliance",
                    path=f.relative,
                )
            )
            continue
        for path_str in paths:
            for variant in _path_variants(path_str):
                for idx in _iter_occurrences(f.text, variant):
                    window = f.text[max(0, idx - _WINDOW) : idx + _WINDOW + len(variant)]
                    if _looks_like_write(window):
                        findings.append(
                            Finding(
                                control_id=CONTROL_ID,
                                audit_id="config-write-scripts",
                                outcome=Outcome.FAIL,
                                message=f"script appears to write to known configuration path {path_str!r}",
                                path=f.relative,
                                line=line_of(f.text, idx),
                            )
                        )
    return findings


AUDITS = {
    "config-write-directives": _check_config_write_directives,
    "config-write-scripts": _check_config_write_scripts,
}
