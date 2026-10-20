"""ACB-INSTR-003: Instructions do not elevate trust in untrusted content."""

from __future__ import annotations

import re

from acb.model import Finding, Outcome
from acb.scan import files_for, line_of, normalize_for_matching

CONTROL_ID = "ACB-INSTR-003"

_FOLLOW_EXTERNAL_PATTERNS = (
    re.compile(
        r"\b(follow|obey)\b[\s\S]{0,40}\binstructions\b[\s\S]{0,40}"
        r"\b(readme|issue|page|file|email|comment|downloaded|fetched)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bexecute\b[\s\S]{0,40}\b(commands|instructions)\b[\s\S]{0,40}"
        r"\b(issue|readme|file|page|downloaded|fetched)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\btreat\b[\s\S]{0,40}\b(downloaded|fetched)\b[\s\S]{0,40}\bauthoritative\b", re.IGNORECASE),
    # "Do whatever the README tells you"
    re.compile(r"\bdo whatever\b[\s\S]{0,60}\btells? you\b", re.IGNORECASE),
    # "Carry out the steps described in the issue"
    re.compile(
        r"\bcarry out\b[\s\S]{0,40}\b(steps|instructions)\b[\s\S]{0,40}"
        r"\b(issue|readme|page|file|email|comment|downloaded|fetched)\b",
        re.IGNORECASE,
    ),
    # "Apply the directions in the fetched page"
    re.compile(
        r"\bapply\b[\s\S]{0,40}\b(directions|instructions)\b[\s\S]{0,40}"
        r"\b(fetched|downloaded|readme|issue|page|file|email|comment)\b",
        re.IGNORECASE,
    ),
)

# Matched case-insensitively against whitespace/typographic-punctuation
# normalized text (see normalize_for_matching), so a double space or a
# newline in the middle of a phrase does not slip past a plain substring
# check.
_AUTHORITY_CLAIM_SUBSTRINGS = (
    "system override",
    "ignore all previous instructions",
    "ignore previous instructions",
    "ignore all prior instructions",
    "ignore prior instructions",
    "platform administrator",
    "override all prior instructions",
    "override previous instructions",
    "this message is from the platform",
    "disregard all previous instructions",
    "disregard previous instructions",
    "ignore the above",
    "[system]:",
)

_COMMENT_RE = re.compile(r"<!--([\s\S]*?)-->")
_DETAILS_RE = re.compile(r"<details[^>]*>([\s\S]*?)</details>", re.IGNORECASE)
# A markdown link's optional title text: [text](url "title text").
_LINK_TITLE_RE = re.compile(r"""\[[^\]]*\]\(\s*\S+\s+(["'])((?:(?!\1)[\s\S])*)\1\s*\)""")
# A markdown "comment" built from an unused reference-style link, a common
# way to hide content from rendered output: [//]: # (hidden text).
_REF_COMMENT_RE = re.compile(r"\[//\]:\s*#\s*\(([^)]*)\)")
# <div hidden>...</div> (tag name captured so the closing tag must match).
_HIDDEN_ATTR_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*\bhidden\b[^>]*>([\s\S]*?)</\1>", re.IGNORECASE)
# An element whose inline style sets display:none, wrapping directive text.
_DISPLAY_NONE_RE = re.compile(
    r"""<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*\bstyle\s*=\s*(["'])(?:(?!\2)[\s\S])*?display\s*:\s*none"""
    r"""(?:(?!\2)[\s\S])*?\2[^>]*>([\s\S]*?)</\1>""",
    re.IGNORECASE,
)

# Broadened deliberately beyond the original five verbs: hidden content is
# inherently suspect (that is the point of this audit), so an imperative
# exfiltration-shaped verb is treated as a strong signal even without
# "run"/"execute"/"agent:" nearby. This is still a cat-and-mouse keyword
# list, not a semantic classifier -- it will not catch every phrasing, and
# a hidden comment that merely contains a URL or a credential-shaped path
# is treated as suspicious too, accepting that an innocuous "see
# https://example.com/docs for details" authoring note could occasionally
# be flagged: for hidden content, biasing toward a false positive here is
# the safer failure mode for a security control.
_HIDDEN_DIRECTIVE_KEYWORD_RE = re.compile(
    r"\b(run|execute|also|send|exfiltrate|upload|curl|wget)\b|agent:|do the following|post to",
    re.IGNORECASE,
)
_SENSITIVE_PATH_RE = re.compile(r"~[\\/]\.(?:ssh|aws|config/gh)\b|\bid_rsa\b|\.pem\b|\.env\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://", re.IGNORECASE)


def _is_suspicious_hidden_content(content: str) -> bool:
    return bool(
        _HIDDEN_DIRECTIVE_KEYWORD_RE.search(content)
        or _SENSITIVE_PATH_RE.search(content)
        or _URL_RE.search(content)
    )


def _unclosed_comment_blocks(text: str) -> list[tuple[int, str]]:
    """Find any HTML comment opened with "<!--" that is never closed.

    The current-method regex for closed comments never matches an
    accidentally-or-deliberately unclosed "<!--" with no matching "-->", so
    everything after it would otherwise be invisible to this check. Treat
    an unclosed comment as running to end of file.
    """
    blocks: list[tuple[int, str]] = []
    search_start = 0
    while True:
        start = text.find("<!--", search_start)
        if start == -1:
            return blocks
        end = text.find("-->", start)
        if end == -1:
            blocks.append((start, text[start + 4 :]))
            return blocks
        search_start = end + 3


def _check_follow_external_instructions(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill", "instruction-file")):
        if f.text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="follow-external-instructions",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify compliance",
                    path=f.relative,
                )
            )
            continue
        for pattern in _FOLLOW_EXTERNAL_PATTERNS:
            match = pattern.search(f.text)
            if match:
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="follow-external-instructions",
                        outcome=Outcome.FAIL,
                        message=f"instruction tells the agent to follow external content: {match.group(0)!r}",
                        path=f.relative,
                        line=line_of(f.text, match.start()),
                    )
                )
    return findings


def _check_authority_claims(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill", "instruction-file")):
        if f.text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="authority-claims",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify compliance",
                    path=f.relative,
                )
            )
            continue
        normalized, index_map = normalize_for_matching(f.text)
        lowered = normalized.lower()
        for phrase in _AUTHORITY_CLAIM_SUBSTRINGS:
            idx = lowered.find(phrase)
            if idx != -1:
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="authority-claims",
                        outcome=Outcome.FAIL,
                        message=f"instruction claims unearned authority: {phrase!r}",
                        path=f.relative,
                        line=line_of(f.text, index_map[idx]),
                    )
                )
    return findings


def _check_hidden_directives(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill", "instruction-file")):
        if f.text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="hidden-directives",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify compliance",
                    path=f.relative,
                )
            )
            continue

        for regex, kind, group in (
            (_COMMENT_RE, "HTML comment", 1),
            (_DETAILS_RE, "details block", 1),
            (_REF_COMMENT_RE, "markdown reference-link comment", 1),
            (_HIDDEN_ATTR_RE, "hidden element", 2),
            (_DISPLAY_NONE_RE, "display:none element", 3),
        ):
            for match in regex.finditer(f.text):
                if _is_suspicious_hidden_content(match.group(group)):
                    findings.append(
                        Finding(
                            control_id=CONTROL_ID,
                            audit_id="hidden-directives",
                            outcome=Outcome.FAIL,
                            message=f"directive-like content hidden in a {kind}",
                            path=f.relative,
                            line=line_of(f.text, match.start()),
                        )
                    )

        for match in _LINK_TITLE_RE.finditer(f.text):
            if _is_suspicious_hidden_content(match.group(2)):
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="hidden-directives",
                        outcome=Outcome.FAIL,
                        message="directive-like content hidden in a link title",
                        path=f.relative,
                        line=line_of(f.text, match.start()),
                    )
                )

        for start, content in _unclosed_comment_blocks(f.text):
            if _is_suspicious_hidden_content(content):
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="hidden-directives",
                        outcome=Outcome.FAIL,
                        message="directive-like content hidden in an unclosed HTML comment",
                        path=f.relative,
                        line=line_of(f.text, start),
                    )
                )
    return findings


AUDITS = {
    "follow-external-instructions": _check_follow_external_instructions,
    "authority-claims": _check_authority_claims,
    "hidden-directives": _check_hidden_directives,
}
