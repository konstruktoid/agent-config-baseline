"""Anchored, segment-aware glob matching for exclusion and exception patterns.

Patterns are relative to the scanned PATH. `*` and `?` never cross a `/`;
`**` matches any number of whole segments. This replaces fnmatch, whose `*`
crosses `/` and so made `path: "*"` match every file in the tree.
"""

from __future__ import annotations

import re
from functools import lru_cache


class PatternError(ValueError):
    """Raised for an invalid path pattern."""


def normalize_pattern(pattern: str) -> str:
    """Normalize a path pattern, rejecting one that becomes empty."""
    normalized = pattern.strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.strip("/")
    if not normalized:
        msg = f"pattern {pattern!r} is empty after normalization"
        raise PatternError(msg)
    if not re.sub(r"[*?/\[\]!]", "", normalized):
        msg = f"pattern {pattern!r} has no literal characters and would match everything"
        raise PatternError(msg)
    first = normalized.split("/", 1)[0]
    if ("/" in normalized and (not re.sub(r"[*?\[\]!]", "", first) or "**" in first)) or normalized in ("**", "*"):
        msg = (
            f"pattern {pattern!r} starts with a wildcard segment; anchor it with a literal directory "
            "so it cannot match across the whole tree"
        )
        raise PatternError(msg)
    if "\\" in normalized or ".." in normalized.split("/"):
        msg = f"pattern {pattern!r} must use '/' separators and no '..' segments"
        raise PatternError(msg)
    return normalized


def _translate(pattern: str) -> str:
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        at_segment_start = i == 0 or pattern[i - 1] == "/"
        if pattern.startswith("**/", i) and at_segment_start:
            out.append("(?:[^/]*/)*")
            i += 3
        elif pattern.startswith("/**", i) and i + 3 == n:
            out.append("(?:/.*)?")
            i += 3
        elif pattern.startswith("**", i):
            # Not a whole segment (a**b): behaves as a single `*`, never crossing '/'.
            out.append("[^/]*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        elif pattern[i] == "[" and (end := pattern.find("]", i + 1)) != -1:
            body = pattern[i + 1 : end].replace("\\", "\\\\")
            if body.startswith("!"):
                body = "^" + body[1:]
            out.append(f"(?!/)[{body}]")
            i = end + 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return "".join(out)


def validate_pattern(pattern: str) -> str:
    """Normalize a pattern and prove it compiles; raise PatternError otherwise."""
    normalized = normalize_pattern(pattern)
    _compile(normalized)
    return normalized


@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern[str]:
    try:
        return re.compile(_translate(normalize_pattern(pattern)))
    except re.error as exc:
        msg = f"pattern {pattern!r} is not a valid glob: {exc}"
        raise PatternError(msg) from exc


def matches(relative_posix: str, pattern: str) -> bool:
    """Report whether the path itself matches the pattern."""
    return _compile(pattern).fullmatch(relative_posix) is not None


def matches_or_under(relative_posix: str, pattern: str) -> bool:
    """Report whether the path or one of its ancestor directories matches the pattern."""
    regex = _compile(pattern)
    if regex.fullmatch(relative_posix):
        return True
    parts = relative_posix.split("/")
    return any(regex.fullmatch("/".join(parts[:k])) for k in range(1, len(parts)))
