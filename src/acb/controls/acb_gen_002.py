"""ACB-GEN-002: External code and dependencies are pinned immutably."""

from __future__ import annotations

import re

from acb.model import Finding, Outcome
from acb.scan import files_for, line_of

CONTROL_ID = "ACB-GEN-002"

# Only a full major.minor.patch numeric version (optionally `v`-prefixed, with an
# optional -prerelease/+build suffix) counts as pinned. A bare major ("1"), a
# partial version ("2.0"), a range ("1.x", "^1.2") or a dist-tag ("latest") must
# all fail, since any of those can resolve to a different artifact over time.
_VALID_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?$")

_FLAG_RE = re.compile(r"^-")
# A shell control operator ends the argument list we scan for specs on this
# invocation; anything after it belongs to a different command.
_CHAIN_OPERATOR_RE = re.compile(r"&&|\|\||;|\|")

# Docker/podman/nerdctl flags that consume a following value token, so that
# value is never mistaken for the image positional argument (the "smuggling"
# false negative: `docker run -e X=y@sha256:<hex> evil:latest` must resolve
# the image to `evil:latest`, not to the -e flag's value).
_DOCKER_VALUE_FLAGS = frozenset(
    {
        "-e", "--env", "-v", "--volume", "-p", "--publish", "-w", "--workdir",
        "-u", "--user", "--name", "-l", "--label", "--network", "--mount",
        "--entrypoint", "--add-host", "--dns", "--group-add", "-m", "--memory",
        "--cpus", "--restart", "--tmpfs", "--device", "--security-opt", "--ulimit", "--cap-add",
        "--cap-drop", "--pid", "--ipc", "--hostname", "-h", "--platform", "--pull", "--cgroupns", "--shm-size",
        "--gpus", "--log-driver", "--log-opt", "--stop-signal", "--userns", "--uts", "--volumes-from",
        "--env-file", "--cidfile", "--link", "--ip", "--mac-address", "--runtime", "--domainname",
    }
)

# (command-prefix regex, pin-check kind, check_all_specs)
# check_all_specs=True for installers that commonly take several package specs
# on one line (`pip install a==1.2.3 b`); False for runners that launch exactly
# one package and treat the rest of the line as that package's own arguments.
_COMMAND_PATTERNS = [
    (re.compile(r"\bnpx[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "npm", False),
    (re.compile(r"\bnpm[ \t]+exec[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "npm", False),
    (re.compile(r"\bnpm[ \t]+(?:install|i)[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "npm", True),
    (re.compile(r"\bbunx[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "generic", False),
    (re.compile(r"\bpnpm[ \t]+dlx[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "generic", False),
    (re.compile(r"\byarn[ \t]+dlx[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "generic", False),
    (re.compile(r"\bpnpx[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "generic", False),
    (re.compile(r"\bpipx[ \t]+run[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "generic", False),
    (re.compile(r"\bpipx[ \t]+install[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "generic", True),
    (re.compile(r"\buvx[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "generic", False),
    (re.compile(r"\buv[ \t]+tool[ \t]+install[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "generic", True),
    (re.compile(r"\bpip[0-9.]*[ \t]+install[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "pip", True),
    (re.compile(r"\bgem[ \t]+install[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "generic", True),
    (re.compile(r"\bcargo[ \t]+install[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "generic", True),
    (re.compile(r"\bgo[ \t]+install[ \t]+(?:-{1,2}\S+[ \t]+)*", re.IGNORECASE), "generic", False),
    (
        re.compile(r"\b(?:docker|podman|nerdctl)[ \t]+(?:run|pull|create)[ \t]+", re.IGNORECASE),
        "docker-image",
        False,
    ),
]
# Value-taking flags, keyed by kind. Only docker-family flags are modeled;
# other commands' flags here are assumed boolean or self-contained
# (`--flag=value`), so a plain flag token is simply skipped for them.
_PIP_VALUE_FLAGS = frozenset(
    {
        "-r", "--requirement", "-c", "--constraint", "-f", "--find-links",
        "-i", "--index-url", "--extra-index-url", "-t", "--target", "--prefix", "--root",
    }
)
_VALUE_FLAGS_BY_KIND: dict[str, frozenset[str]] = {
    "docker-image": _DOCKER_VALUE_FLAGS,
    "pip": _PIP_VALUE_FLAGS,
}

# A package spec or image reference is a short run of name characters. Anything
# else (a closing backtick followed by prose, a comma, a quote) means the
# command ended and what follows is prose, not more arguments.
_SPEC_RE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@._/+:=<>!~^*|#%?&\[\],-]*$")
_IMAGE_REF_RE = re.compile(
    r"^[a-z0-9][a-z0-9._-]*(?::\d+)?(?:/[a-z0-9._-]+)*(?::[\w.-]+)?(?:@sha256:[0-9a-f]{64})?$", re.IGNORECASE
)
_CONTINUATION_RE = re.compile(r"\\\r?\n")

_INTEGRITY_MARKER_RE = re.compile(
    r"--require-hashes|--hash\b|sha256|sha384|sha512|\.lock\b|lockfile|"
    r"package-lock\.json|poetry\.lock|uv\.lock|requirements\.lock|integrity=",
    re.IGNORECASE,
)
# How far past the end of the invocation's line to still consider an
# integrity marker "nearby" (e.g. a lockfile mention on the very next line).
_LOCKFILE_WINDOW = 200

_IMAGE_DIGEST_RE = re.compile(r"@sha256:[0-9a-fA-F]{64}")

_YAML_IMAGE_RE = re.compile(r"(?m)^\s*image:\s*(\S+)")
_JSON_IMAGE_RE = re.compile(r'"image"\s*:\s*"([^"\n]+)"')
_DOCKERFILE_FROM_RE = re.compile(r"(?mi)^\s*FROM\s+(?:--\S+\s+)*(\S+)")
_KUBECTL_IMAGE_FLAG_RE = re.compile(r"--image[=\s]+(\S+)")

# Scheme-less and ftp:// URLs, in addition to http(s)://.
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s)\]\"'<>]+")
_BARE_URL_RE = re.compile(
    r"\b(?:curl|wget)\b[^\n]{0,80}?\s((?:[a-zA-Z0-9][a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}(?:/[^\s)\]\"'<>]*)?)"
)
_COMMIT_HASH_RE = re.compile(r"/(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?:/|$)")
# This 40/64-hex heuristic accepts any path segment that merely *looks* like a
# commit hash, even one that is not actually a commit reference (e.g. a hex
# string of all zeros used as a placeholder). Tightening it to require a
# recognized host/owner/repo shape in front is possible but has its own false
# negatives (self-hosted git servers, mirrors); left as a known limitation.
_VERIFY_ACTION_RE = re.compile(r"sha256sum|shasum|--require-hashes|gpg\s+--verify|\.sig\b|CHECKSUMS\b", re.IGNORECASE)
# These keyword labels only count as verification when followed by something
# that looks like an actual hash value; a bare mention ("# checksum: not
# needed") must not satisfy the check.
_VERIFY_LABEL_WITH_VALUE_RE = re.compile(r"(?:sha256|sha384|sha512|checksum)\s*[:=]?\s*[0-9a-fA-F]{8,}", re.IGNORECASE)


def _strip_trailing_punct(token: str) -> str:
    return token.rstrip(")],.;\"'`")


def _is_valid_version(version: str) -> bool:
    version = _strip_trailing_punct(version)
    return bool(_VALID_VERSION_RE.match(version))


def _npm_pinned(spec: str) -> bool:
    spec = _strip_trailing_punct(spec)
    if spec.startswith("@"):
        rest = spec[1:]
        if "@" not in rest:
            return False
        _, version = rest.split("@", 1)
        return _is_valid_version(version)
    if "@" not in spec:
        return False
    _, version = spec.split("@", 1)
    return _is_valid_version(version)


def _pip_pinned(spec: str) -> bool:
    spec = _strip_trailing_punct(spec)
    if "==" not in spec:
        return False
    version = spec.split("==", 1)[1]
    return _is_valid_version(version)


def _generic_pinned(spec: str) -> bool:
    spec = _strip_trailing_punct(spec)
    if "@" not in spec:
        return False
    _, version = spec.rsplit("@", 1)
    return _is_valid_version(version)


def _docker_image_pinned(spec: str) -> bool:
    spec = _strip_trailing_punct(spec)
    return bool(_IMAGE_DIGEST_RE.search(spec)) or _generic_pinned(spec)


_PINNED_CHECK = {
    "npm": _npm_pinned,
    "pip": _pip_pinned,
    "generic": _generic_pinned,
    "docker-image": _docker_image_pinned,
}


def _iter_runner_invocations(text: str):
    """Yield (cmd_match, token, kind, pinned, abs_start) for every package-runner,
    installer or docker-family invocation found.

    For each command-prefix match, the rest of its line is tokenized; flag
    tokens (leading `-`) are skipped (along with their value token, for a
    flag known to take one — see `_VALUE_FLAGS_BY_KIND` — so that value is
    never mistaken for a positional spec), and either only the first
    remaining token or every remaining token is yielded as a spec, per that
    command's `check_all_specs` setting.
    """
    # A shell line continuation joins two physical lines into one command;
    # replace it with same-length whitespace so offsets stay valid.
    text = _CONTINUATION_RE.sub(lambda m: " " * len(m.group(0)), text)
    for cmd_re, kind, check_all in _COMMAND_PATTERNS:
        value_flags = _VALUE_FLAGS_BY_KIND.get(kind, frozenset())
        for cmd_match in cmd_re.finditer(text):
            line_end = text.find("\n", cmd_match.end())
            if line_end == -1:
                line_end = len(text)
            tail = text[cmd_match.end() : line_end]
            op_match = _CHAIN_OPERATOR_RE.search(tail)
            if op_match:
                tail = tail[: op_match.start()]
            tokens = list(re.finditer(r"\S+", tail))
            i = 0
            while i < len(tokens):
                token = tokens[i].group(0)
                if _FLAG_RE.match(token):
                    if "=" not in token and token in value_flags:
                        i += 2
                        continue
                    i += 1
                    continue
                ends_command = token.endswith(("`", ",", ";", ")"))
                spec = token.strip("`").strip("\"'")
                spec = spec.rstrip(",;)")
                if not spec or not _SPEC_RE.match(spec):
                    break
                if kind == "docker-image" and not _IMAGE_REF_RE.fullmatch(spec):
                    # An unknown flag's value (a path, key=value) is not the image;
                    # keep looking for the first token that is.
                    i += 1
                    continue
                abs_start = cmd_match.end() + tokens[i].start()
                pinned = _PINNED_CHECK[kind](spec)
                yield cmd_match, spec, kind, pinned, abs_start
                if not check_all or ends_command:
                    break
                i += 1


def _unreadable_finding(audit_id: str, f) -> Finding:
    return Finding(
        control_id=CONTROL_ID,
        audit_id=audit_id,
        outcome=Outcome.NOT_EVALUATED,
        message="file could not be read (not valid UTF-8 text, or is a symlink); cannot verify compliance",
        path=f.relative,
    )


def _mcp_command_line(server: dict) -> str | None:
    command = server.get("command")
    if not isinstance(command, str):
        return None
    args = server.get("args")
    parts = [command]
    if isinstance(args, list):
        parts.extend(a for a in args if isinstance(a, str))
    return " ".join(parts)


def _check_mcp_package_runners(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for decl in ctx.inventory.mcp_declarations:
        for name, server in decl.servers.items():
            if not isinstance(server, dict):
                continue
            line = _mcp_command_line(server)
            if line is None:
                continue
            for cmd_match, token, _kind, pinned, _abs_start in _iter_runner_invocations(line):
                if not pinned:
                    invocation = line[cmd_match.start() :].split("\n", 1)[0]
                    findings.append(
                        Finding(
                            control_id=CONTROL_ID,
                            audit_id="package-runners-pinned",
                            outcome=Outcome.FAIL,
                            message=(
                                f"MCP server {name!r} launches an unpinned package runner invocation: "
                                f"{invocation!r} (spec {token!r})"
                            ),
                            path=ctx.relative(decl.path),
                        )
                    )
    return findings


def _check_package_runners_pinned(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill", "instruction-file", "mcp-server-declaration")):
        if f.text is None:
            findings.append(_unreadable_finding("package-runners-pinned", f))
            continue
        for cmd_match, token, _kind, pinned, abs_start in _iter_runner_invocations(f.text):
            if not pinned:
                invocation = f.text[cmd_match.start() : abs_start + len(token)]
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="package-runners-pinned",
                        outcome=Outcome.FAIL,
                        message=f"package runner invocation is not pinned to an exact version: {invocation!r}",
                        path=f.relative,
                        line=line_of(f.text, abs_start),
                    )
                )
    findings.extend(_check_mcp_package_runners(ctx))
    return findings


def _check_lockfile_or_hash(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill", "instruction-file", "mcp-server-declaration")):
        if f.text is None:
            findings.append(_unreadable_finding("lockfile-or-hash", f))
            continue
        for cmd_match, token, _kind, pinned, abs_start in _iter_runner_invocations(f.text):
            if not pinned:
                continue
            line_end = f.text.find("\n", abs_start)
            if line_end == -1:
                line_end = len(f.text)
            window_end = min(len(f.text), line_end + _LOCKFILE_WINDOW)
            window = f.text[cmd_match.start() : window_end]
            if _INTEGRITY_MARKER_RE.search(window):
                continue
            invocation = f.text[cmd_match.start() : abs_start + len(token)]
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="lockfile-or-hash",
                    outcome=Outcome.FAIL,
                    message=(
                        f"pinned install {invocation!r} has no bundled lockfile, hash "
                        "flag or digest check near this invocation in this artifact"
                    ),
                    path=f.relative,
                    line=line_of(f.text, abs_start),
                )
            )
    return findings


def _iter_image_refs(text: str, structured: bool = False):
    """Yield (position, raw_spec) for every container image reference found.

    Reuses `_iter_runner_invocations`'s flag-and-value-aware tokenizer for
    `docker|podman|nerdctl run|pull|create`, so a digest or version string
    smuggled into an unrelated flag's value (`-e X=y@sha256:<hex>`, `-v
    /x@sha256:<hex>:/y`) is never mistaken for the image argument; the first
    true positional token is the image.
    """
    for _cmd_match, token, kind, _pinned, abs_start in _iter_runner_invocations(text):
        if kind == "docker-image":
            yield abs_start, token

    for pattern in (_YAML_IMAGE_RE, _JSON_IMAGE_RE, _DOCKERFILE_FROM_RE, _KUBECTL_IMAGE_FLAG_RE):
        for match in pattern.finditer(text):
            spec = _strip_trailing_punct(match.group(1)).strip("`\"'")
            # In prose ("image: a hardened base") and in Python ("from x import y")
            # these keys and keywords do not name an image. A reference that
            # carries a registry path, tag or digest is unmistakable; a bare
            # word only counts in a file whose format is structured.
            if not _IMAGE_REF_RE.fullmatch(spec):
                continue
            if not structured and not any(c in spec for c in "/:@"):
                continue
            line_end = text.find("\n", match.end())
            rest = text[match.end() : line_end if line_end != -1 else len(text)]
            if pattern is _DOCKERFILE_FROM_RE and re.match(r"\s+import\b", rest):
                continue
            yield match.start(1), spec


def _check_images_by_digest(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill", "instruction-file", "mcp-server-declaration")):
        if f.text is None:
            findings.append(_unreadable_finding("images-by-digest", f))
            continue
        structured = f.path.suffix.lower() in {".yaml", ".yml", ".json", ".jsonc"} or f.path.name.lower().startswith(
            ("dockerfile", "containerfile")
        )
        for pos, raw_spec in _iter_image_refs(f.text, structured):
            spec = _strip_trailing_punct(raw_spec)
            if not _IMAGE_DIGEST_RE.search(spec):
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="images-by-digest",
                        outcome=Outcome.FAIL,
                        message=f"container image reference has no @sha256: digest: {spec!r}",
                        path=f.relative,
                        line=line_of(f.text, pos),
                    )
                )
    return findings


# The procedure covers *fetched* URLs. A URL counts as fetched when it sits on
# the same logical line as a fetch invocation, or when it points directly at
# a script, binary or archive (a link to install.sh is a download whether or
# not the command is spelled out). A citation link in prose is neither.
_FETCH_INVOCATION_RE = re.compile(
    r"\b(?:curl|wget|aria2c|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer|"
    r"urlopen|urlretrieve|requests\.get|httpx\.get|git\s+clone|pip[0-9.]*\s+install|npm\s+(?:i|install)|"
    r"yarn\s+add|pnpm\s+add|uvx|uv\s+(?:pip|tool|run)|deno\s+run|bunx|download)\b",
    re.IGNORECASE,
)
_DOWNLOAD_SUFFIX_RE = re.compile(
    r"\.(?:sh|bash|zsh|ps1|psm1|py|pl|rb|js|mjs|exe|msi|bin|run|appimage|deb|rpm|apk|jar|whl|"
    r"tar|tgz|gz|bz2|xz|zip|7z|dmg|pkg)$",
    re.IGNORECASE,
)


def _logical_lines(text: str):
    """Yield (start offset, line) with backslash-continued lines joined."""
    start = 0
    pending_start = None
    pending: list[str] = []
    for line in text.splitlines(keepends=True):
        if pending_start is None:
            pending_start = start
        start += len(line)
        stripped = line.rstrip("\r\n")
        if stripped.endswith("\\"):
            # Same length as the backslash and line break, so offsets stay valid.
            pending.append(stripped[:-1] + " " * (len(line) - len(stripped) + 1))
            continue
        pending.append(line)
        yield pending_start, "".join(pending)
        pending, pending_start = [], None
    if pending:
        yield pending_start, "".join(pending)


_FENCE_RE = re.compile(r"(?ms)^[ \t]*(```|~~~)[^\n]*\n.*?(?:^[ \t]*\1[ \t]*$|\Z)")


def _fenced_ranges(text: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in _FENCE_RE.finditer(text)]


def _iter_fetch_urls(text: str):
    # Inside a fenced code block a URL is part of something to run, not a
    # citation; outside one, only a fetch command or a script/archive link counts.
    fences = _fenced_ranges(text)
    for line_start, line in _logical_lines(text):
        in_fence = any(a <= line_start < b for a, b in fences)
        fetch_line = in_fence or _FETCH_INVOCATION_RE.search(line) is not None
        for match in _URL_RE.finditer(line):
            path = _strip_trailing_punct(match.group(0)).split("?", 1)[0].split("#", 1)[0]
            if fetch_line or _DOWNLOAD_SUFFIX_RE.search(path):
                yield line_start + match.start(), match.group(0)
        if fetch_line:
            for match in _BARE_URL_RE.finditer(line):
                yield line_start + match.start(1), match.group(1)


def _check_downloads_verified(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for f in files_for(ctx, ("skill", "instruction-file", "mcp-server-declaration")):
        if f.text is None:
            findings.append(_unreadable_finding("downloads-verified", f))
            continue
        for start, raw_url in _iter_fetch_urls(f.text):
            url = _strip_trailing_punct(raw_url)
            end = start + len(url)
            if _COMMIT_HASH_RE.search(url):
                continue
            window_after = f.text[end : end + 300]
            window_before = f.text[max(0, start - 100) : start]
            if _VERIFY_ACTION_RE.search(window_after) or _VERIFY_ACTION_RE.search(window_before):
                continue
            if _VERIFY_LABEL_WITH_VALUE_RE.search(window_after) or _VERIFY_LABEL_WITH_VALUE_RE.search(window_before):
                continue
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="downloads-verified",
                    outcome=Outcome.FAIL,
                    message=f"fetched URL has no nearby digest verification and no commit hash: {url!r}",
                    path=f.relative,
                    line=line_of(f.text, start),
                )
            )
    return findings


AUDITS = {
    "package-runners-pinned": _check_package_runners_pinned,
    "lockfile-or-hash": _check_lockfile_or_hash,
    "images-by-digest": _check_images_by_digest,
    "downloads-verified": _check_downloads_verified,
}
