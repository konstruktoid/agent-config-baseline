"""ACB-GEN-003: Artifacts contain no embedded secrets."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import TYPE_CHECKING

from acb.model import Finding, Outcome
from acb.scan import files_for, line_of

if TYPE_CHECKING:
    from acb.controls import CheckContext
    from acb.scan import TextFile

CONTROL_ID = "ACB-GEN-003"
_MIN_MIXED_CASE_LENGTH = 32
_MAX_SLASHES = 3
_MIN_ASSIGNED_ENTROPY = 3.0

_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----")
# scheme://user:password@host. $ and {} are allowed in user/password (a real
# password can contain them, e.g. "hunter$2") so they are not excluded from
# the character class; a password that is ENTIRELY a placeholder reference is
# filtered out afterwards instead, via `_PURE_PLACEHOLDER_RE`.
_CONN_STRING_RE = re.compile(r"\b[a-zA-Z][\w+.-]*://(?P<user>[^\s:@/<>]+):(?P<password>[^\s@/<>'\"]+)@[^\s/'\"]+")
_PURE_PLACEHOLDER_RE = re.compile(r"^(?:\$\{[^}]+\}|\{\{[^}]+\}\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^>]+>)$")

_GENERIC_SECRET_RE = re.compile(
    r"\b("
    r"sk-proj-[A-Za-z0-9_-]{10,}|"
    r"sk-ant-api03-[A-Za-z0-9_-]{10,}|"
    r"sk-live-[A-Za-z0-9]{8,}|"
    r"sk-[A-Za-z0-9]{20,}|"
    r"ghp_[A-Za-z0-9]{20,}|"
    r"xoxb-[A-Za-z0-9-]{10,}|"
    r"AIza[0-9A-Za-z_-]{10,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"ASIA[0-9A-Z]{16}|"
    r"Bearer\s+[A-Za-z0-9\-_.]{20,}|"
    r"gh[ousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{30,}|hf_[A-Za-z0-9]{30,}|"
    r"xox[pas]-[A-Za-z0-9-]{10,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"
    r")(?![\w-])"
)
# Credentials that only show up as part of a URL or as a keyword assignment.
_URL_USERINFO_TOKEN_RE = re.compile(r"://([A-Za-z0-9_.~%-]{20,})@")
_WEBHOOK_RE = re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}")
_URL_QUERY_SECRET_RE = re.compile(
    r"[?&]\w*(?:token|key|secret|password|passwd|auth|sig)\w*=([^&\s\"'<>)]{12,})", re.IGNORECASE
)
_KEYWORD_HEX_RE = re.compile(
    r"(?:secret|token|password|passwd|api[_-]?key|auth)\w*[\"']?\s*[:=]\s*[\"']?([0-9a-fA-F]{32,})\b", re.IGNORECASE
)
_KEYWORD_ASSIGN_RE = re.compile(
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key)\b[\"']?\s*[:=]\s*[\"']?([^\s\"'`<>{}$]{8,})",
    re.IGNORECASE,
)

_SECRET_PATTERNS = [_PRIVATE_KEY_RE, _CONN_STRING_RE, _GENERIC_SECRET_RE, _URL_USERINFO_TOKEN_RE, _WEBHOOK_RE]

# Generic high-entropy detection (the control's procedure explicitly requires
# it, beyond provider-specific prefixes above). A candidate is any run of 24+
# base64/hex-alphabet characters; it is flagged when its Shannon entropy is
# high enough that it looks like random token material rather than prose or
# an identifier. Threshold/length were tuned against this repo's own test
# suite and fixtures: ordinary long snake_case/kebab-case identifiers and
# prose top out around 3.9 bits/char, while generated base64/base64url
# tokens of 24+ characters measure 4.2+, so 4.2 separates the two cleanly.
_ENTROPY_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_=-]{24,}")
_ENTROPY_MIN_LENGTH = 24
_ENTROPY_THRESHOLD = 4.2

# Short credential words (pat, pass, pwd, key) only count as a whole name
# segment, so `path`, `pattern`, `bypass` and `keyboard` are not credentials.
_CRED_KEY_RE = re.compile(
    r"token|secret|password|passwd|auth|api[_-]?key|(?:^|[_.-])(?:key|pat|pass|pwd)(?:$|[_.-])",
    re.IGNORECASE,
)
_MAX_DEPTH = 32


# A four-character prefix identifies a token type such as ghp_ but gives away too much of a shorter secret.
_REDACT_PREFIX_MIN_LENGTH = 16


def _redact(value: str) -> str:
    """Redact a secret for use in a finding message.

    Finding messages end up in SARIF uploads and CI logs, so they never repeat the secret itself.
    """
    prefix = value[:4] if len(value) >= _REDACT_PREFIX_MIN_LENGTH else ""
    return f"{prefix}… ({len(value)} chars)"


_PLACEHOLDER_RE = re.compile(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^>]+>|\{\{[^}]+\}\}")
# An HTTP auth-scheme prefix is literal boilerplate, not part of the secret
# material; strip it before checking whether the REST of the value is
# entirely a placeholder, so "Bearer ${AUTH_TOKEN}" still counts as a
# reference while "Bearer eyJ...<a real-looking token>" still does not.
_AUTH_SCHEME_PREFIX_RE = re.compile(r"^(?:Bearer|Basic|Token)\s+", re.IGNORECASE)
# A header/argument value of this shape is a credential regardless of the key
# or flag name carrying it, e.g. `--header "Authorization: Bearer shorttok123"`.
_HEADER_VALUE_RE = re.compile(
    r"\b(?:authorization|bearer|api[-_]?key|token|secret|password|auth)\b\s*:?\s*([^\s\"']{8,})",
    re.IGNORECASE,
)
# A credential embedded in a URL's query string, e.g.
# "https://mcp.example.com/sse?api_key=LIVEVALUE123456".
_URL_QUERY_CRED_RE = re.compile(r"[?&](\w*(?:token|key|secret|password|auth)\w*)=([^&\s\"']+)", re.IGNORECASE)


def _looks_like_random_token(text: str, match: re.Match[str]) -> bool:
    """Separate generated token material from structure.

    URL path segments, file paths and identifiers are structure; a query
    value, userinfo or a bare token is not, even inside a URL. Generated
    tokens contain a digit and, unless long, both letter cases. Hex-only runs
    are handled by the keyword rule instead (their entropy cannot exceed 4.0).
    """
    candidate = match.group(0)
    if re.fullmatch(r"[0-9a-fA-F]+", candidate):
        return False
    if not any(c.isdigit() for c in candidate):
        return False
    mixed_case = any(c.isupper() for c in candidate) and any(c.islower() for c in candidate)
    if not mixed_case and len(candidate) < _MIN_MIXED_CASE_LENGTH:
        return False
    start = match.start()
    token_start = max(text.rfind(" ", 0, start), text.rfind("\n", 0, start), text.rfind("(", 0, start)) + 1
    prefix = text[token_start:start]
    if "://" in prefix and (not prefix or prefix[-1] not in "?&=@:"):
        return False
    return candidate.count("/") <= _MAX_SLASHES and (
        candidate.count("/") == 0 or len(candidate) >= _MIN_MIXED_CASE_LENGTH
    )


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _secret_failure(f: TextFile, text: str, message: str, offset: int) -> Finding:
    return Finding(
        control_id=CONTROL_ID,
        audit_id="secret-scan",
        outcome=Outcome.FAIL,
        message=message,
        path=f.relative,
        line=line_of(text, offset),
    )


def _embedded_secret_findings(f: TextFile, text: str) -> list[Finding]:
    """Report text matching a known secret pattern, unless the password is a pure placeholder."""
    findings: list[Finding] = []
    for pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            if "password" in pattern.groupindex and _PURE_PLACEHOLDER_RE.fullmatch(match.group("password")):
                continue
            message = f"artifact contains what looks like an embedded secret: {_redact(match.group(0))}"
            findings.append(_secret_failure(f, text, message, match.start()))
    return findings


def _credential_value_findings(f: TextFile, text: str) -> list[Finding]:
    """Report credential values assigned to secret-looking keys and URL query parameters."""
    findings: list[Finding] = []
    for rule, check in (
        (_URL_QUERY_SECRET_RE, lambda v: not _is_placeholder_or_reference(v)),
        (_KEYWORD_HEX_RE, lambda _v: True),
        (
            _KEYWORD_ASSIGN_RE,
            lambda v: (
                not _is_placeholder_or_reference(v)
                and any(c.isdigit() for c in v)
                and _shannon_entropy(v) > _MIN_ASSIGNED_ENTROPY
            ),
        ),
    ):
        for match in rule.finditer(text):
            value = match.group(1)
            if check(value):
                message = f"artifact contains a credential value: {_redact(value)}"
                findings.append(_secret_failure(f, text, message, match.start(1)))
    return findings


def _high_entropy_findings(f: TextFile, text: str) -> list[Finding]:
    """Report long random-looking tokens."""
    findings: list[Finding] = []
    for match in _ENTROPY_CANDIDATE_RE.finditer(text):
        candidate = match.group(0)
        if len(candidate) < _ENTROPY_MIN_LENGTH:
            continue
        if not _looks_like_random_token(text, match):
            continue
        if _shannon_entropy(candidate) > _ENTROPY_THRESHOLD:
            message = f"artifact contains a high-entropy string that looks like a secret: {_redact(candidate)}"
            findings.append(_secret_failure(f, text, message, match.start()))
    return findings


def _check_secret_scan(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill", "instruction-file", "mcp-server-declaration")):
        if f.text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="secret-scan",
                    outcome=Outcome.NOT_EVALUATED,
                    message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify compliance",
                    path=f.relative,
                )
            )
            continue
        findings.extend(_embedded_secret_findings(f, f.text))
        findings.extend(_credential_value_findings(f, f.text))
        findings.extend(_high_entropy_findings(f, f.text))
    return findings


def _is_placeholder_or_reference(value: str) -> bool:
    """Report whether the whole value is a placeholder or reference.

    `fullmatch`, not `search`: a value that merely contains `$x` or `<x>`
    somewhere inside it (e.g. "abc$def123realsecret", "realsecret <x>") is
    not a reference, it is a literal secret with incidental placeholder-like
    characters in it.
    """
    stripped = value.strip()
    if stripped == "":
        return True
    stripped = _AUTH_SCHEME_PREFIX_RE.sub("", stripped, count=1)
    return bool(_PLACEHOLDER_RE.fullmatch(stripped))


def _flag_hit(args: list, index: int, item: str) -> tuple[str, str] | None:
    """Return (flag, value) when the item is a credential flag with a real value inline or in the next argument."""
    flag_match = re.match(r"^--?([A-Za-z][\w-]*)", item)
    if not (flag_match and _CRED_KEY_RE.search(flag_match.group(1))):
        return None
    if "=" in item:
        value = item.split("=", 1)[1]
    elif index + 1 < len(args) and isinstance(args[index + 1], str):
        value = args[index + 1]
    else:
        return None
    if _is_placeholder_or_reference(value):
        return None
    return (flag_match.group(1), value)


def _scan_args_list(args: list) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for index, item in enumerate(args):
        if not isinstance(item, str):
            continue
        flag_hit = _flag_hit(args, index, item)
        if flag_hit is not None:
            hits.append(flag_hit)

        # A credential can also be embedded in the string itself regardless of
        # whether this item is itself a flag, e.g. a single arg
        # "Authorization: Bearer shorttok123" passed to `--header`.
        header_match = _HEADER_VALUE_RE.search(item)
        if header_match:
            value = header_match.group(1)
            if not _is_placeholder_or_reference(value):
                hits.append(("header", value))

        hits.extend(
            (qmatch.group(1), qmatch.group(2))
            for qmatch in _URL_QUERY_CRED_RE.finditer(item)
            if not _is_placeholder_or_reference(qmatch.group(2))
        )
    return hits


def _is_env_list_shape(value: list) -> bool:
    """Report whether `env` is a list of name/value dicts instead of a mapping.

    Some MCP clients use that shape, and detecting it lets the values still get scanned.
    """
    return bool(value) and all(isinstance(item, dict) and "name" in item for item in value)


def _scan_list_value(value: list, depth: int, seen: set[int]) -> list[tuple[str, str]]:
    if id(value) in seen:
        return []
    seen.add(id(value))
    if _is_env_list_shape(value):
        converted = {str(item["name"]): item.get("value") for item in value}
        hits = _scan_mapping(converted, depth + 1, seen)
        # Any field besides name and value is scanned under its own key rather than dropped by the conversion.
        for item in value:
            hits.extend(_scan_mapping({k: v for k, v in item.items() if k not in ("name", "value")}, depth + 1, seen))
        return hits
    hits = _scan_args_list(value)
    for item in value:
        if isinstance(item, dict):
            hits.extend(_scan_mapping(item, depth + 1, seen))
    return hits


def _scan_scalar_value(key: str, value: object) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    if isinstance(value, str):
        if _CRED_KEY_RE.search(key) and not _is_placeholder_or_reference(value):
            hits.append((key, value))
        hits.extend(
            (f"{key}.{qmatch.group(1)}", qmatch.group(2))
            for qmatch in _URL_QUERY_CRED_RE.finditer(value)
            if not _is_placeholder_or_reference(qmatch.group(2))
        )
    elif isinstance(value, (int, float, bool)) and _CRED_KEY_RE.search(key):
        # A numeric-looking credential value (`PASSWORD: 86753091`) is
        # still worth flagging; stringify it rather than skipping just
        # because it did not come through YAML/JSON as a str.
        hits.append((key, str(value)))
    return hits


def _scan_mapping(mapping: dict, depth: int = 0, seen: set[int] | None = None) -> list[tuple[str, str]]:
    # YAML aliases can make a structure recursive or exponentially shared;
    # visit each container once and stop at a fixed depth.
    seen = set() if seen is None else seen
    if depth > _MAX_DEPTH or id(mapping) in seen:
        return []
    seen.add(id(mapping))
    hits: list[tuple[str, str]] = []
    for raw_key, value in mapping.items():
        if isinstance(value, dict):
            hits.extend(_scan_mapping(value, depth + 1, seen))
        elif isinstance(value, list):
            hits.extend(_scan_list_value(value, depth, seen))
        else:
            hits.extend(_scan_scalar_value(str(raw_key), value))
    return hits


def _check_mcp_env_indirection(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for decl in ctx.inventory.mcp_declarations:
        for name, server in decl.servers.items():
            if not isinstance(server, dict):
                continue
            for key, value in _scan_mapping(server):
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="mcp-env-indirection",
                        outcome=Outcome.FAIL,
                        message=(
                            f"server {name!r} field {key!r} is a literal value, not an "
                            f"environment-variable reference or placeholder: {_redact(value)}"
                        ),
                        path=ctx.relative(decl.path),
                    )
                )
    return findings


AUDITS = {
    "secret-scan": _check_secret_scan,
    "mcp-env-indirection": _check_mcp_env_indirection,
}
