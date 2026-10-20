"""ACB-GEN-004: Artifacts contain no invisible or bidirectional control characters."""

from __future__ import annotations

import re
import unicodedata

from acb.model import Finding, Outcome
from acb.scan import files_for, line_of

CONTROL_ID = "ACB-GEN-004"

_FORBIDDEN_RANGES = [
    (0x200B, 0x200F),  # zero-width space .. right-to-left mark
    (0x202A, 0x202E),  # bidi embedding/override controls
    (0x2060, 0x2064),  # word joiner .. invisible plus
    (0x2066, 0x2069),  # bidi isolate controls
    (0xFE00, 0xFE0F),  # variation selectors (byte-smuggling)
    (0xE0000, 0xE007F),  # Unicode tag characters
    (0xE0100, 0xE01EF),  # supplementary variation selectors (byte-smuggling)
    (0xE000, 0xF8FF),  # private use area
    (0xF0000, 0xFFFFD),  # supplementary private use area-A
    (0x100000, 0x10FFFD),  # supplementary private use area-B
]
_FORBIDDEN_SINGLE = {
    0x00AD,  # soft hyphen
    0x180E,  # Mongolian vowel separator
    0x034F,  # combining grapheme joiner
    0x061C,  # Arabic letter mark (bidi)
    0x3164,  # Hangul filler
    0x2800,  # braille blank
    0xFFF9,  # interlinear annotation anchor
}

_FENCE_BACKTICK_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_FENCE_TILDE_RE = re.compile(r"~~~[^\n]*\n(.*?)~~~", re.DOTALL)
_INDENTED_LINE_RE = re.compile(r"(?m)^(?:[ ]{4,}|\t)(\S.*)$")
_INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")


def _LOOKS_LIKE_ASCII_SYMBOL(c: str) -> bool:
    """Non-ASCII characters that render like, or stand in for, an ASCII
    separator, dash, slash or space: they change what a reviewer sees in a
    command without changing the letters. Curly quotes and the ellipsis are
    typographic punctuation and stay exempt."""
    code = ord(c)
    return (
        0x2010 <= code <= 0x2015
        or code in (0x2044, 0x2212, 0x2215, 0x2216, 0x29F8)
        or 0xFF01 <= code <= 0xFF5E
        or unicodedata.category(c) == "Zs"
    )


def _has_non_ascii_letter(token: str) -> bool:
    """True for a letter, mark or digit outside ASCII: the characters that can
    stand in for an ASCII one. Typographic punctuation such as an ellipsis or a
    curly quote is not a look-alike for a command name and is not flagged."""
    return any(ord(c) > 127 and (unicodedata.category(c)[0] in "LMN" or _LOOKS_LIKE_ASCII_SYMBOL(c)) for c in token)


def _is_forbidden(code_point: int, index: int) -> bool:
    if code_point == 0xFEFF:
        return index != 0  # permitted only as a byte-order mark at file start
    if code_point in _FORBIDDEN_SINGLE:
        return True
    return any(lo <= code_point <= hi for lo, hi in _FORBIDDEN_RANGES)


def _check_forbidden_code_points(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill", "instruction-file", "mcp-server-declaration")):
        if f.text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="forbidden-code-points",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify compliance",
                    path=f.relative,
                )
            )
            continue
        for index, ch in enumerate(f.text):
            if _is_forbidden(ord(ch), index):
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="forbidden-code-points",
                        outcome=Outcome.FAIL,
                        message=f"forbidden code point U+{ord(ch):04X} found",
                        path=f.relative,
                        line=line_of(f.text, index),
                    )
                )
    return findings


def _mask_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """Blank out the given (start, end) spans, preserving length and newlines.

    Used so that once a fenced code block's body has been pulled out and
    checked on its own, the indented-block and inline-code scans below don't
    also see (and double-report) the same content inside the fence.
    """
    if not spans:
        return text
    chars = list(text)
    for start, end in spans:
        for i in range(start, end):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def _iter_code_line_regions(text: str):
    """Yield (line_text, absolute_offset) for every code-shaped line: fenced
    (``` or ~~~) bodies, 4-space/tab indented blocks, and inline `code` spans.
    """
    fence_spans: list[tuple[int, int]] = []
    for fence_re in (_FENCE_BACKTICK_RE, _FENCE_TILDE_RE):
        for match in fence_re.finditer(text):
            fence_spans.append((match.start(1), match.end(1)))

    for start, end in fence_spans:
        body = text[start:end]
        offset = 0
        for line in body.splitlines(keepends=True):
            stripped = line.rstrip("\n")
            if stripped.strip():
                yield stripped, start + offset
            offset += len(line)

    masked = _mask_spans(text, fence_spans)
    for match in _INDENTED_LINE_RE.finditer(masked):
        yield match.group(1), match.start(1)
    for match in _INLINE_CODE_RE.finditer(masked):
        yield match.group(1), match.start(1)


def _check_confusable_identifiers(ctx) -> list[Finding]:
    findings: list[Finding] = []

    for skill in ctx.inventory.skills:
        if not skill.directory.name.isascii():
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="confusable-identifiers",
                    outcome=Outcome.FAIL,
                    message=f"skill directory name {skill.directory.name!r} is not ASCII",
                    path=ctx.relative(skill.directory),
                )
            )
        for path in sorted(skill.directory.rglob("*")):
            if path.is_file() and not path.name.isascii():
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="confusable-identifiers",
                        outcome=Outcome.FAIL,
                        message=f"file name {path.name!r} is not ASCII",
                        path=ctx.relative(path),
                    )
                )

    for f in files_for(ctx, ("skill", "instruction-file", "mcp-server-declaration")):
        if f.text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="confusable-identifiers",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify compliance",
                    path=f.relative,
                )
            )
            continue

        for line_text, offset in _iter_code_line_regions(f.text):
            for tok_match in re.finditer(r"\S+", line_text):
                token = tok_match.group(0)
                if _has_non_ascii_letter(token):
                    abs_pos = offset + tok_match.start()
                    findings.append(
                        Finding(
                            control_id=CONTROL_ID,
                            audit_id="confusable-identifiers",
                            outcome=Outcome.FAIL,
                            message=f"non-ASCII token {token!r} in code block",
                            path=f.relative,
                            line=line_of(f.text, abs_pos),
                        )
                    )

    for decl in ctx.inventory.mcp_declarations:
        for name, server in decl.servers.items():
            if not isinstance(server, dict):
                continue
            command = server.get("command")
            if isinstance(command, str) and not command.isascii():
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="confusable-identifiers",
                        outcome=Outcome.FAIL,
                        message=f"server {name!r} command {command!r} is not ASCII",
                        path=ctx.relative(decl.path),
                    )
                )
            args = server.get("args")
            if isinstance(args, list):
                for arg in args:
                    if isinstance(arg, str) and not arg.isascii():
                        findings.append(
                            Finding(
                                control_id=CONTROL_ID,
                                audit_id="confusable-identifiers",
                                outcome=Outcome.FAIL,
                                message=f"server {name!r} arg {arg!r} is not ASCII",
                                path=ctx.relative(decl.path),
                            )
                        )

    return findings


AUDITS = {
    "forbidden-code-points": _check_forbidden_code_points,
    "confusable-identifiers": _check_confusable_identifiers,
}
