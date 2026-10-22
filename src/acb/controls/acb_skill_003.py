"""ACB-SKILL-003: Bundled skill content is transparent, referenced and contained."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

from acb.model import Finding, Outcome
from acb.scan import (
    line_of,
    safe_read_bytes,
    safe_read_text,
    skill_files,
    split_frontmatter,
)

if TYPE_CHECKING:
    from acb.controls import CheckContext
    from acb.discovery import Skill

CONTROL_ID = "ACB-SKILL-003"
_TAR_MAGIC_START = 257
_TAR_MAGIC_END = 262
_MIN_BLOCK_LINES = 2
_MIN_BLOCK_CHARS = 256
_MAX_SCRIPT_LINE_LENGTH = 500

# "-_" added for base64url, alongside the standard base64 alphabet and hex
# (a subset of the same character class).
_ENCODED_RUN_RE = re.compile(r"[A-Za-z0-9+/=_-]{257,}")
# A run of 65+ consecutive `\xHH` hex escapes is 260+ characters: the same
# "more than 256 characters of encoded payload" bar as _ENCODED_RUN_RE, just
# expressed in the 4-characters-per-byte shape of a hex-escaped string.
_HEX_ESCAPE_RUN_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){65,}")
# A line made up entirely of base64/base64url/hex alphabet characters (and
# nothing else once surrounding whitespace is stripped). Used to detect
# MIME-wrapped (e.g. 76-column) multi-line encoded blocks, where no single
# line is long enough to trip _ENCODED_RUN_RE on its own.
_BASE64_LINE_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_TOKEN_RE = re.compile(r"[^\s`'\"()\[\]<>]+")
_STRIP_TRAILING = ".,;:"
_HOME_PREFIXES = ("~", "$HOME", "${HOME}")
_SCRIPT_SUFFIXES = (".sh", ".py", ".js", ".rb", ".pl", ".ps1")


def _looks_like_image(raw: bytes) -> bool:
    if raw.startswith(b"\x89PNG"):
        return True
    if raw.startswith(b"\xff\xd8\xff"):
        return True
    if raw.startswith((b"GIF87a", b"GIF89a")):
        return True
    return raw[:4] == b"RIFF" and raw[8:12] == b"WEBP"


def _looks_like_archive(raw: bytes) -> bool:
    """Signatures of common archive and compression containers.

    These are never permitted anywhere in a skill directory (unlike images,
    which get a narrow exception under `assets/`), so this is checked
    unconditionally, before any UTF-8-decodability shortcut: a tar header is
    mostly ASCII/NUL-padded and can decode as valid UTF-8 text even though it
    is a binary container format.
    """
    if raw.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):  # zip
        return True
    if raw.startswith(b"\x1f\x8b"):  # gzip
        return True
    # POSIX/GNU tar
    return len(raw) >= _TAR_MAGIC_END and raw[_TAR_MAGIC_START:_TAR_MAGIC_END] == b"ustar"


def _find_multiline_encoded_blocks(text: str) -> list[int]:
    """Return the 1-based start lines of blocks that look like an encoded payload.

    A block is 2+ consecutive lines that are each entirely base64/base64url/hex alphabet
    and total over 256 characters once joined.

    Trade-off: a line made solely of alphanumerics plus `+/=_-` is a fairly
    loose test (e.g. a line of hex-only identifiers could match), but a
    tighter per-line test would miss real wrapped payloads, and this only
    fires across 2+ consecutive such lines summing past the threshold.
    """
    starts: list[int] = []
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        stripped = lines[i].strip()
        if not stripped or not _BASE64_LINE_RE.match(stripped):
            i += 1
            continue
        start = i
        total = 0
        while i < n:
            s = lines[i].strip()
            if s and _BASE64_LINE_RE.match(s):
                total += len(s)
                i += 1
            else:
                break
        if (i - start) >= _MIN_BLOCK_LINES and total > _MIN_BLOCK_CHARS:
            starts.append(start + 1)
    return starts


def _skill_for_file(ctx: CheckContext, path: Path) -> Skill | None:
    best = None
    for skill in ctx.inventory.skills:
        skill_root = skill.directory.resolve()
        try:
            path.resolve().relative_to(skill_root)
        except ValueError:
            continue
        if best is None or len(str(skill_root)) > len(str(best.directory.resolve())):
            best = skill
    return best


def _check_text_only(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in skill_files(ctx):
        raw = safe_read_bytes(f.path)
        if raw is None:
            if f.text is not None:
                continue  # valid UTF-8 text; bytes re-read failed transiently
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="text-only",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (is a symlink, or an OS-level read error)",
                    path=f.relative,
                )
            )
            continue

        # Checked before the UTF-8-decodability shortcut below: an archive's
        # header bytes can happen to decode as valid UTF-8 even though the
        # format itself is exactly the kind of non-reviewable binary this
        # audit exists to catch, regardless of where it lives in the skill.
        if _looks_like_archive(raw):
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="text-only",
                    outcome=Outcome.FAIL,
                    message="file is a recognized archive/compression format, not permitted anywhere in a skill",
                    path=f.relative,
                )
            )
            continue

        if f.text is not None:
            continue  # valid UTF-8 text, nothing further to check

        skill = _skill_for_file(ctx, f.path)
        if skill is not None:
            rel_parts = f.path.resolve().relative_to(skill.directory.resolve()).parts
            under_assets = "assets" in rel_parts[:-1]
            if under_assets and _looks_like_image(raw):
                continue
        findings.append(
            Finding(
                control_id=CONTROL_ID,
                audit_id="text-only",
                outcome=Outcome.FAIL,
                message="file is not valid UTF-8 text and is not a recognized image under assets/",
                path=f.relative,
            )
        )
    return findings


def _check_no_encoded_payloads(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in skill_files(ctx):
        if f.text is None:
            continue

        findings.extend(
            Finding(
                control_id=CONTROL_ID,
                audit_id="no-encoded-payloads",
                outcome=Outcome.FAIL,
                message="contiguous base64/base64url/hex-looking run exceeds 256 characters",
                path=f.relative,
                line=line_of(f.text, match.start()),
            )
            for match in _ENCODED_RUN_RE.finditer(f.text)
        )

        findings.extend(
            Finding(
                control_id=CONTROL_ID,
                audit_id="no-encoded-payloads",
                outcome=Outcome.FAIL,
                message="contiguous `\\xHH` hex-escape run exceeds 256 characters",
                path=f.relative,
                line=line_of(f.text, match.start()),
            )
            for match in _HEX_ESCAPE_RUN_RE.finditer(f.text)
        )

        findings.extend(
            Finding(
                control_id=CONTROL_ID,
                audit_id="no-encoded-payloads",
                outcome=Outcome.FAIL,
                message="multi-line base64/base64url/hex-looking block exceeds 256 characters when joined",
                path=f.relative,
                line=line_no,
            )
            for line_no in _find_multiline_encoded_blocks(f.text)
        )

        lines = f.text.splitlines()
        has_shebang = bool(lines) and lines[0].startswith("#!")
        # The control's own procedure text says "any script file". scripts/
        # and shebang files are the unambiguous cases; a conventional script
        # extension or an explicit "minified" naming convention (e.g.
        # lib/app.min.js) is also "a script file" in the sense that matters
        # here -- it is code, and minified code is exactly what this check
        # is for -- so it gets the same long-line check regardless of
        # directory.
        name = Path(f.relative).name
        is_conventional_script = name.endswith(_SCRIPT_SUFFIXES) or ".min." in name
        is_script = "scripts/" in f.relative or has_shebang or is_conventional_script
        if is_script:
            for i, line in enumerate(lines, start=1):
                if len(line) > _MAX_SCRIPT_LINE_LENGTH:
                    findings.append(
                        Finding(
                            control_id=CONTROL_ID,
                            audit_id="no-encoded-payloads",
                            outcome=Outcome.FAIL,
                            message=f"line exceeds 500 characters ({len(line)})",
                            path=f.relative,
                            line=i,
                        )
                    )
    return findings


_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def _referenced_paths(text: str) -> set[str]:
    """Path-like tokens actually referenced in `text`.

    Strips HTML comments first: a reference visible only inside `<!-- -->`
    is invisible to a human reviewer reading the rendered body, so it must
    not count as "referenced" any more than it would for a real reviewer.
    Matches whole path tokens (not raw substring containment), so an
    unrelated file like `scripts/r` is not considered referenced merely
    because it is a textual substring of the distinct `scripts/run.sh`.
    """
    text = _HTML_COMMENT_RE.sub("", text)
    return {m.group(0).rstrip(_STRIP_TRAILING) for m in _TOKEN_RE.finditer(text)}


def _check_executables_referenced(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for skill in ctx.inventory.skills:
        skill_text = safe_read_text(skill.skill_md) or ""
        _frontmatter, body = split_frontmatter(skill_text)
        body_refs = _referenced_paths(body)

        all_paths = [p for p in sorted(skill.directory.rglob("*")) if p.is_file()]

        # Files directly referenced (one level) by SKILL.md's body.
        combined_refs = set(body_refs)
        for path in all_paths:
            rel = path.relative_to(skill.directory).as_posix()
            if rel == "SKILL.md":
                continue
            if rel in body_refs:
                referenced_text = safe_read_text(path)
                if referenced_text is not None:
                    combined_refs |= _referenced_paths(referenced_text)

        for path in all_paths:
            rel = path.relative_to(skill.directory).as_posix()
            if rel == "SKILL.md":
                continue

            is_script_dir = rel.startswith("scripts/")
            is_exec_bit = os.access(path, os.X_OK)
            raw_prefix = safe_read_bytes(path)
            has_shebang = raw_prefix is not None and raw_prefix[:2] == b"#!"

            if not (is_script_dir or is_exec_bit or has_shebang):
                continue

            if rel not in combined_refs:
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="executables-referenced",
                        outcome=Outcome.FAIL,
                        message=f"executable file {rel!r} is not referenced from SKILL.md",
                        path=ctx.relative(path),
                    )
                )
    return findings


def _looks_like_path_ref(ref: str) -> bool:
    # file:// is a real local-filesystem reference, not a web reference like
    # http(s)://, so it does not get the URL exemption other schemes get.
    if "://" in ref and not ref.lower().startswith("file://"):
        return False
    if ref.startswith(_HOME_PREFIXES):
        return True
    if ref == "..":
        return True
    return "/" in ref or "\\" in ref


def _local_path(token: str) -> tuple[str, str | None]:
    """Return the path a reference names, and why it leaves the skill directory when its form alone shows that."""
    if token.startswith(_HOME_PREFIXES):
        return token, "is a home-directory reference, outside the skill directory"
    if not token.lower().startswith("file:"):
        return token, None
    try:
        uri = urlsplit(token)
    except ValueError:
        return token, "is not a valid file URI"
    # RFC 8089: an empty or localhost authority names a local file, and any other host a remote one.
    if uri.netloc.lower() not in ("", "localhost"):
        return token, "names a remote host, outside the skill directory"
    return unquote(uri.path), None


def _reference_problem(token: str, base: Path, skill_root: Path) -> str | None:
    """Return why a reference leaves the skill directory, or None when it stays inside or cannot be resolved."""
    check_token, problem = _local_path(token)
    if problem is not None:
        return problem

    if check_token.startswith("/"):
        return "is an absolute path"

    # Checked on both `/` and `\` segments: a backslash-style
    # traversal (`..\..\secret`) is just as real on a filesystem
    # that accepts it as a separator as the forward-slash form.
    if ".." in re.split(r"[/\\]", check_token):
        return "contains a `..` path segment"

    try:
        resolved = (base / check_token).resolve()
    except (OSError, ValueError):
        return None

    try:
        resolved.relative_to(skill_root)
    except ValueError:
        return "resolves outside the skill directory"
    return None


def _check_references_contained(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []

    for skill in ctx.inventory.skills:
        findings.extend(
            Finding(
                control_id=CONTROL_ID,
                audit_id="references-contained",
                outcome=Outcome.FAIL,
                message="skill directory contains a symlink",
                path=ctx.relative(path),
            )
            for path in sorted(skill.directory.rglob("*"))
            if path.is_symlink()
        )

    for f in skill_files(ctx):
        if f.text is None:
            continue
        skill = _skill_for_file(ctx, f.path)
        if skill is None:
            continue
        skill_root = skill.directory.resolve()

        for match in _TOKEN_RE.finditer(f.text):
            raw_token = match.group(0)
            # A bare ".." is itself all trailing-strippable characters, so
            # falling back to the unstripped token when stripping would
            # erase it entirely keeps a bare "cd .." traversal token alive.
            token = raw_token.rstrip(_STRIP_TRAILING) or raw_token
            if not token or not _looks_like_path_ref(token):
                continue
            problem = _reference_problem(token, f.path.parent, skill_root)
            if problem is not None:
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="references-contained",
                        outcome=Outcome.FAIL,
                        message=f"reference {token!r} {problem}",
                        path=f.relative,
                        line=line_of(f.text, match.start()),
                    )
                )
    return findings


AUDITS = {
    "text-only": _check_text_only,
    "no-encoded-payloads": _check_no_encoded_payloads,
    "executables-referenced": _check_executables_referenced,
    "references-contained": _check_references_contained,
}
