"""ACB-INSTR-001: Instructions do not direct the agent to bypass human oversight."""

from __future__ import annotations

import re

from acb.model import Finding, Outcome
from acb.scan import files_for, line_of, normalize_for_matching

CONTROL_ID = "ACB-INSTR-001"

# Phrases telling the agent to skip confirmation, auto-approve, or hide its
# actions from the user. Matched case-insensitively against text that has
# already been whitespace/typographic-punctuation normalized (see
# normalize_for_matching), so a curly apostrophe or an extra space/newline
# inside the phrase does not slip past a plain substring check.
_OVERSIGHT_BYPASS_SUBSTRINGS = (
    "do not ask",
    "don't ask",
    "without confirmation",
    "skip confirmation",
    "skip the confirmation",
    "auto-approve",
    "auto approve",
    "auto-accept",
    "auto accept",
    "don't tell the user",
    "do not tell the user",
    "don't mention this",
    "do not mention this",
    "pre-approved",
    "preapproved",
    "never ask for confirmation",
    "proceed without asking",
    "blanket permission to run anything",
    "keep this step to yourself",
)
_ASSUME_APPROVED_RE = re.compile(r"assume\b[\s\S]{0,60}\bapproved\b", re.IGNORECASE)

# Regex-based coverage for safety-mechanism-disabling commands/env vars, so
# flag combinations (-sSk), separated short flags (-s -k), alternate values
# ('0' vs 0, true vs yes) and additional disable mechanisms are caught
# rather than only one literal full-string spelling.
_SAFETY_DISABLE_PATTERNS = (
    # curl -k / --insecure, combined or separated short flags, e.g.
    # "curl -sSk", "curl -s -k", "curl --insecure".
    re.compile(r"\bcurl\b[^\n]{0,40}?(?<!\S)(?:--insecure|-[A-Za-z]*k[A-Za-z]*)\b", re.IGNORECASE),
    # wget --no-check-certificate
    re.compile(r"\bwget\b[^\n]{0,40}?--no-check-certificate\b", re.IGNORECASE),
    # git commit --no-verify / -n, git push --no-verify
    re.compile(r"\bgit\s+(?:commit|push)\b[^\n]{0,40}?(?<!\S)(?:--no-verify|-n)\b", re.IGNORECASE),
    # git -c http.sslVerify=false
    re.compile(r"\bgit\s+-c\s+http\.sslverify\s*=\s*false\b", re.IGNORECASE),
    # NODE_TLS_REJECT_UNAUTHORIZED=0, with or without quotes around the value
    re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0['\"]?"),
    # GIT_SSL_NO_VERIFY=1 / true / yes
    re.compile(r"GIT_SSL_NO_VERIFY\s*=\s*['\"]?(?:1|true|yes)['\"]?", re.IGNORECASE),
    # pip ... --trusted-host ...
    re.compile(r"\bpip[0-9.]*\b[^\n]{0,80}?--trusted-host\b", re.IGNORECASE),
    # npm config set strict-ssl false
    re.compile(r"\bnpm\s+config\s+set\s+strict-ssl\s+false\b", re.IGNORECASE),
    # PYTHONHTTPSVERIFY=0
    re.compile(r"PYTHONHTTPSVERIFY\s*=\s*['\"]?0['\"]?"),
    # HUSKY=0, a common way to disable git hooks installed via Husky
    re.compile(r"\bHUSKY\s*=\s*['\"]?0['\"]?\b"),
    # --no-gpg-sign
    re.compile(r"--no-gpg-sign\b", re.IGNORECASE),
)


def _check_oversight_bypass_directives(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill", "instruction-file")):
        if f.text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="oversight-bypass-directives",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify compliance",
                    path=f.relative,
                )
            )
            continue
        normalized, index_map = normalize_for_matching(f.text)
        lowered = normalized.lower()
        for phrase in _OVERSIGHT_BYPASS_SUBSTRINGS:
            idx = lowered.find(phrase)
            if idx != -1:
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="oversight-bypass-directives",
                        outcome=Outcome.FAIL,
                        message=f"instruction directs bypassing oversight: {phrase!r}",
                        path=f.relative,
                        line=line_of(f.text, index_map[idx]),
                    )
                )
        match = _ASSUME_APPROVED_RE.search(normalized)
        if match:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="oversight-bypass-directives",
                    outcome=Outcome.FAIL,
                    message="instruction tells the agent to assume actions are pre-approved",
                    path=f.relative,
                    line=line_of(f.text, index_map[match.start()]),
                )
            )
    return findings


def _check_bypass_flags(ctx) -> list[Finding]:
    """Fail if scanned text invokes an agent with a client-declared bypass flag.

    The flag list is per-client data (``ctx.clients.permission_bypass_flags``),
    not part of the control text; with no client data loaded it is empty and
    this audit has no scope to check, which is reported as NOT_APPLICABLE:
    neither a pass (nothing was checked) nor a failure to check (nothing was
    declared that could be).
    """
    flags = ctx.clients.permission_bypass_flags
    if not flags:
        return [
            Finding(
                control_id=CONTROL_ID,
                audit_id="bypass-flags",
                outcome=Outcome.NOT_APPLICABLE,
                message="no client-declared permission-bypass flags in scope (none in the loaded client data)",
            )
        ]
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill", "instruction-file")):
        if f.text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="bypass-flags",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify compliance",
                    path=f.relative,
                )
            )
            continue
        lowered = f.text.lower()
        for flag in flags:
            idx = lowered.find(flag.lower())
            if idx != -1:
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="bypass-flags",
                        outcome=Outcome.FAIL,
                        message=f"permission-bypass flag {flag!r} found",
                        path=f.relative,
                        line=line_of(f.text, idx),
                    )
                )
    return findings


def _check_safety_disable(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill", "instruction-file")):
        if f.text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="safety-disable",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify compliance",
                    path=f.relative,
                )
            )
            continue
        for pattern in _SAFETY_DISABLE_PATTERNS:
            match = pattern.search(f.text)
            if match:
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="safety-disable",
                        outcome=Outcome.FAIL,
                        message=f"instruction disables a verification mechanism: {match.group(0)!r}",
                        path=f.relative,
                        line=line_of(f.text, match.start()),
                    )
                )
    return findings


AUDITS = {
    "oversight-bypass-directives": _check_oversight_bypass_directives,
    "bypass-flags": _check_bypass_flags,
    "safety-disable": _check_safety_disable,
}
