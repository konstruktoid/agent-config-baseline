"""Shared helpers for control-check modules.

Every control module walks the same three artifact shapes (skill
directories, instruction files, MCP declarations); this module centralizes
that walk so each control's AUDITS functions only implement the actual
check.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ApplesTo = tuple[str, ...]

# Curly/typographic punctuation normalized to its straight-ASCII equivalent
# before phrase matching, so a smart-quote variant of a trigger phrase
# (e.g. "Don’t ask") is not missed.
_TYPOGRAPHIC_PUNCT = {
    "‘": "'",
    "’": "'",
    "‚": "'",
    "“": '"',
    "”": '"',
    "„": '"',
}


def normalize_for_matching(text: str) -> tuple[str, list[int]]:
    """Return (normalized, index_map) for phrase matching that is robust to
    whitespace and typographic-punctuation variance.

    Runs of whitespace (including newlines) collapse to a single space, and
    common curly quotes/apostrophes map to their straight-ASCII equivalent.
    ``index_map[i]`` is the offset into the original ``text`` of
    ``normalized[i]``, so a match found in the normalized string can still be
    reported against the original file's line numbers via ``line_of``.
    """
    out_chars: list[str] = []
    index_map: list[int] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            out_chars.append(" ")
            index_map.append(i)
            while i < n and text[i].isspace():
                i += 1
            continue
        out_chars.append(_TYPOGRAPHIC_PUNCT.get(ch, ch))
        index_map.append(i)
        i += 1
    return "".join(out_chars), index_map


@dataclass(frozen=True)
class TextFile:
    path: Path
    relative: str
    text: str | None  # None when the file is not valid UTF-8 text


def safe_read_text(path: Path) -> str | None:
    """Read `path` as UTF-8 text, or None if that is not possible or not safe.

    Refuses to dereference a symlink: a scanned artifact that is a symlink
    could point anywhere readable by the checker process (e.g.
    /proc/self/environ), and a naive read would echo that target's
    content verbatim into a finding message. Every content read for
    pattern/structure checking goes through this function rather than
    calling Path.read_text()/read_bytes() directly, so a symlinked
    artifact is treated the same as an undecodable one: visible to
    discovery, but not read, and callers that need "could this be
    evaluated at all" treat None as fail-closed rather than skip.
    """
    if path.is_symlink():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def safe_read_bytes(path: Path) -> bytes | None:
    """Byte-level counterpart to safe_read_text, for binary sniffing (e.g. image magic)."""
    if path.is_symlink():
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def _read(ctx, path: Path) -> TextFile:
    return TextFile(path=path, relative=ctx.relative(path), text=safe_read_text(path))


def skill_files(ctx) -> list[TextFile]:
    """Every regular file under every discovered skill directory, recursively."""
    out: list[TextFile] = []
    for skill in ctx.inventory.skills:
        for path in sorted(skill.directory.rglob("*")):
            if path.is_file():
                out.append(_read(ctx, path))
    return out


def instruction_files(ctx) -> list[TextFile]:
    return [_read(ctx, f.path) for f in ctx.inventory.instruction_files]


def mcp_files(ctx) -> list[TextFile]:
    return [_read(ctx, d.path) for d in ctx.inventory.mcp_declarations]


def files_for(ctx, applies_to: ApplesTo) -> list[TextFile]:
    out: list[TextFile] = []
    if "skill" in applies_to:
        out.extend(skill_files(ctx))
    if "instruction-file" in applies_to:
        out.extend(instruction_files(ctx))
    if "mcp-server-declaration" in applies_to:
        out.extend(mcp_files(ctx))
    return out


def line_of(text: str, index: int) -> int:
    """1-based line number of a character offset, for pattern-match findings."""
    return text.count("\n", 0, index) + 1


def split_frontmatter(text: str) -> tuple[str | None, str]:
    """Split a SKILL.md-style file into (raw frontmatter YAML, body).

    Frontmatter is a block delimited by a `---` line at the very start of
    the file and a closing `---` line. Returns (None, text) if the file
    does not open with such a block.
    """
    # A leading UTF-8 BOM (produced by some editors) is not part of the
    # delimiter and must not stop the frontmatter block from being found.
    text = text.removeprefix("﻿")
    if not text.startswith("---"):
        return None, text
    lines = text.splitlines(keepends=True)
    # Trailing whitespace on a delimiter line (e.g. "--- ") is still a
    # valid `---` delimiter to every YAML frontmatter consumer we know of.
    if lines[0].rstrip() != "---":
        return None, text
    for i in range(1, len(lines)):
        if lines[i].rstrip() == "---":
            frontmatter = "".join(lines[1:i])
            body = "".join(lines[i + 1 :])
            return frontmatter, body
    return None, text
