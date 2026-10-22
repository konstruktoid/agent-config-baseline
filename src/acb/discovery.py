"""Find the artifacts a baseline run evaluates under PATH.

Those are skills, instruction files, MCP server declarations, and the extension packages and
agent settings files that client data describes.

Discovery errs toward finding too much rather than too little: anything it
cannot inspect but might be an artifact is recorded as unscanned, which makes
every control not-evaluated rather than letting the run pass.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote

import yaml

from acb.config import CheckerConfig, matching_exclusion
from acb.paths import matches
from acb.scan import safe_read_bytes, safe_read_text

if TYPE_CHECKING:
    from collections.abc import Iterator

    from acb.clients import ClientData

ALWAYS_IGNORED_DIRS = {".git"}
AGENTS_MD = "AGENTS.md"
SKILL_MD = "SKILL.md"

_MCP_SUFFIXES = {".json", ".jsonc", ".yaml", ".yml"}
_MCP_BASE_KEYS = ("mcpServers", "servers")
_UNPARSEABLE = object()
_MAX_STRUCTURED_BYTES = 5_000_000

_MD_LINK_RE = re.compile(r"\]\(\s*(?:<([^>\n]+)>|([^)\s]+))")
_MD_REF_DEF_RE = re.compile(r"(?m)^[ ]{0,3}\[[^\]\n]+\]:\s*(?:<([^>\n]+)>|(\S+))")
_REFERENCED_DOC_SUFFIXES = {".md", ".markdown", ".txt"}


@dataclass(frozen=True)
class Skill:
    """A discovered skill directory."""

    directory: Path
    skill_md: Path


@dataclass(frozen=True)
class InstructionFile:
    """A discovered instruction file."""

    path: Path
    source: str


@dataclass(frozen=True)
class McpDeclaration:
    """A discovered MCP server declaration file."""

    path: Path
    key: str
    servers: dict[str, dict]


@dataclass(frozen=True)
class ExtensionPackage:
    """A discovered extension package."""

    root: Path
    manifest: Path
    manifest_data: dict
    client: str


@dataclass(frozen=True)
class SettingsFile:
    """A discovered agent settings file."""

    path: Path
    scope: str
    data: dict
    client: str


@dataclass(frozen=True)
class Unscanned:
    """A path that could not be scanned, with the reason."""

    path: str
    reason: str


@dataclass(frozen=True)
class Inventory:
    """Everything discovered under the scanned path."""

    root: Path
    skills: tuple[Skill, ...]
    instruction_files: tuple[InstructionFile, ...]
    mcp_declarations: tuple[McpDeclaration, ...]
    extension_packages: tuple[ExtensionPackage, ...] = ()
    agent_settings: tuple[SettingsFile, ...] = ()
    test_files: tuple[Path, ...] = ()
    unscanned: tuple[Unscanned, ...] = ()
    excluded: dict[str, int] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    def has_artifacts(self, artifact_type: str) -> bool:
        """Report whether any artifact of the given type was discovered."""
        return bool(
            {
                "skill": self.skills,
                "instruction-file": self.instruction_files,
                "mcp-server-declaration": self.mcp_declarations,
                "extension-package": self.extension_packages,
                "agent-settings": [s for s in self.agent_settings if s.scope == "project"],
                "managed-settings": [s for s in self.agent_settings if s.scope == "managed"],
            }[artifact_type]
        )


def _walk(
    root: Path, config: CheckerConfig, unscanned: list[Unscanned], excluded: Counter
) -> Iterator[tuple[Path, str]]:
    """Yield (path, relative posix) for every file under root that is not excluded.

    Directory symlinks are followed only when they resolve inside root (a
    symlink is otherwise a way to hide an artifact from discovery); a cycle
    is visited once. Symlinks resolving outside root are not followed and
    are recorded as unscanned.
    """
    visited: set[str] = set()

    def onerror(error: OSError) -> None:
        unscanned.append(Unscanned(_relative(Path(error.filename or root), root), "directory could not be listed"))

    for dirpath, dirnames, filenames in os.walk(root, followlinks=True, onerror=onerror):
        real = os.path.realpath(dirpath)
        if real in visited:
            dirnames[:] = []
            continue
        visited.add(real)
        current = Path(dirpath)

        kept = []
        for name in sorted(dirnames):
            if name in ALWAYS_IGNORED_DIRS and current == root:
                continue
            path = current / name
            rel = path.relative_to(root).as_posix()
            exclusion = matching_exclusion(rel, config)
            if exclusion is not None:
                excluded[exclusion.pattern] += 1
                continue
            if path.is_symlink() and not Path(os.path.realpath(path)).is_relative_to(root):
                unscanned.append(Unscanned(rel, "directory symlink points outside the scanned root; not followed"))
                continue
            kept.append(name)
        dirnames[:] = kept

        for name in sorted(filenames):
            path = current / name
            rel = path.relative_to(root).as_posix()
            exclusion = matching_exclusion(rel, config)
            if exclusion is not None:
                excluded[exclusion.pattern] += 1
                continue
            yield path, rel


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _strip_comments(text: str) -> str:
    """Remove // and /* */ comments outside JSON strings."""
    out: list[str] = []
    i, n, in_string = 0, len(text), False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
        elif ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(ch)
            i += 1

    return "".join(out)


def _strip_trailing_commas(stripped: str) -> str:
    """Remove commas that directly precede a closing brace or bracket, outside JSON strings."""
    result: list[str] = []
    i, n, in_string = 0, len(stripped), False
    while i < n:
        ch = stripped[i]
        if in_string:
            result.append(ch)
            if ch == "\\" and i + 1 < n:
                result.append(stripped[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
            result.append(ch)
        elif ch == ",":
            j = i + 1
            while j < n and stripped[j].isspace():
                j += 1
            if j >= n or stripped[j] not in "}]":
                result.append(ch)
        else:
            result.append(ch)
        i += 1
    return "".join(result)


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas outside JSON strings."""
    return _strip_trailing_commas(_strip_comments(text))


def _parse_structured(suffix: str, text: str) -> object:
    try:
        if suffix in (".json", ".jsonc"):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return json.loads(_strip_jsonc(text))
        return yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError, RecursionError, TypeError, ValueError):
        return _UNPARSEABLE


def _server_entries(key: str, value: object) -> dict[str, dict]:
    if isinstance(value, dict):
        return {str(name): entry for name, entry in value.items() if isinstance(entry, dict)}
    # A list of servers is a known shape for mcpServers; a top-level `servers`
    # list is excluded because OpenAPI documents use exactly that shape.
    if isinstance(value, list) and key != "servers":
        entries: dict[str, dict] = {}
        for index, item in enumerate(value):
            if isinstance(item, dict):
                name = item.get("name")
                label = name if isinstance(name, str) and name else f"[{index}]"
                entries[label if label not in entries else f"{label}[{index}]"] = item
        return entries
    return {}


def _server_mapping(data: object, key_paths: tuple[str, ...]) -> tuple[str, dict[str, dict]] | None:
    """Merge every server mapping that has at least one entry with a `command` or `url`.

    One such entry is enough: requiring it of every
    entry let a single dummy entry hide the whole file.
    """
    if not isinstance(data, dict):
        return None
    candidates: list[tuple[str, object]] = [(key, data[key]) for key in _MCP_BASE_KEYS if key in data]
    for dotted in key_paths:
        node: object = data
        for part in dotted.split("."):
            node = node.get(part) if isinstance(node, dict) else None
            if node is None:
                break
        if node is not None:
            candidates.append((dotted, node))

    keys: list[str] = []
    servers: dict[str, dict] = {}
    for key, value in candidates:
        entries = _server_entries(key, value)
        if not any("command" in entry or "url" in entry for entry in entries.values()):
            continue
        keys.append(key)
        for name, entry in entries.items():
            servers[name if name not in servers else f"{key}:{name}"] = entry
    return ("+".join(keys), servers) if keys else None


def _classify_mcp(path: Path, rel: str, clients: ClientData) -> McpDeclaration | Unscanned | None:
    mcp_named = "mcp" in path.name.lower()
    raw = safe_read_bytes(path)
    if raw is None:
        return (
            Unscanned(rel, "possible MCP declaration is a symlink or unreadable; not inspected") if mcp_named else None
        )

    # No byte pre-filter: JSON and YAML can spell a key with escapes
    # ("\u006dcpServers"), so only parsing tells whether a file is a declaration.
    suspicious = mcp_named or b"mcpServers" in raw
    if len(raw) > _MAX_STRUCTURED_BYTES:
        return Unscanned(rel, "possible MCP declaration is too large to inspect") if suspicious else None

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return Unscanned(rel, "possible MCP declaration is not valid UTF-8; not inspected") if suspicious else None

    data = _parse_structured(path.suffix.lower(), text)
    if data is _UNPARSEABLE:
        return (
            Unscanned(rel, "possible MCP declaration could not be parsed as JSON, JSONC or YAML")
            if suspicious
            else None
        )

    found = _server_mapping(data, clients.mcp_key_paths)
    if found is None:
        return None
    key, servers = found
    return McpDeclaration(path=path, key=key, servers=servers)


_TEST_DIR_NAMES = {"test", "tests", "__tests__", "spec", "specs"}
_TEST_NAME_RE = re.compile(r"^(test_.+|.+_test\.[^.]+|.+\.(test|spec)\.[^.]+|.+\.bats)$")


def is_test_file(rel: str) -> bool:
    """Vendor-neutral test naming: a tests/ style directory, or a test_/_test/.test./.spec./.bats file name."""
    parts = rel.split("/")
    return bool(_TEST_DIR_NAMES & {p.lower() for p in parts[:-1]}) or bool(_TEST_NAME_RE.match(parts[-1]))


def _suffix_matches(rel: str, match: str) -> bool:
    return rel == match or rel.endswith("/" + match)


def _parse_json_object(path: Path, rel: str, what: str) -> dict | Unscanned:
    text = safe_read_text(path)
    if text is None:
        return Unscanned(rel, f"{what} is a symlink or not valid UTF-8; not inspected")
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        return Unscanned(rel, f"{what} could not be parsed as JSON: {exc}")
    if not isinstance(data, dict):
        return Unscanned(rel, f"{what} is not a JSON object")
    return data


def _classify_client_files(
    path: Path, rel: str, clients: ClientData
) -> list[ExtensionPackage | SettingsFile | Unscanned]:
    """Return the settings files and extension package manifests that client data describes."""
    found: list[ExtensionPackage | SettingsFile | Unscanned] = []
    for client, profile in clients.profiles:
        for spec in profile.get("agent_settings", {}).get("files", []):
            if _suffix_matches(rel, spec["match"]):
                data = _parse_json_object(path, rel, f"{client} {spec['scope']} settings file")
                found.append(data if isinstance(data, Unscanned) else SettingsFile(path, spec["scope"], data, client))
        for manifest in profile.get("extension_packages", {}).get("manifest_paths", []):
            if _suffix_matches(rel, manifest):
                package_root = path
                for _ in manifest.split("/"):
                    package_root = package_root.parent
                data = _parse_json_object(path, rel, f"{client} extension manifest")
                found.append(
                    data if isinstance(data, Unscanned) else ExtensionPackage(package_root, path, data, client)
                )
    return found


def _link_candidate(
    instruction: InstructionFile, target: str, root: Path, origin: str, notes: list[str]
) -> Path | None:
    """Return the path a local link names, or None (with a note) when it cannot be followed."""
    if target.startswith("/"):
        notes.append(f"{origin} links to absolute path {target}; not scanned")
        return None
    candidate = Path(os.path.normpath(instruction.path.parent / target))
    if not candidate.is_relative_to(root):
        notes.append(f"{origin} links to {target}, which is outside the scanned root; not scanned")
        return None
    if candidate.is_dir():
        notes.append(f"{origin} links to directory {target}; its contents are not scanned as instructions")
        return None
    return candidate


def _referenced_docs(
    instruction: InstructionFile,
    root: Path,
    config: CheckerConfig,
    known: set[Path],
    notes: list[str],
) -> list[InstructionFile]:
    """Return the documents an instruction file links to, one level deep.

    They are instructions too: "follow docs/rules.md" must not move the payload out of scope.
    """
    text = safe_read_text(instruction.path)
    if text is None:
        return []
    origin = _relative(instruction.path, root)
    found: list[InstructionFile] = []
    targets = [m.group(1) or m.group(2) for m in (*_MD_LINK_RE.finditer(text), *_MD_REF_DEF_RE.finditer(text))]
    real_root = Path(os.path.realpath(root))
    for raw_target in targets:
        target = unquote(raw_target.split("#", 1)[0].split("?", 1)[0])
        if not target or "://" in target or target.startswith("mailto:"):
            continue
        candidate = _link_candidate(instruction, target, root, origin, notes)
        if candidate is None or Path(target).suffix.lower() not in _REFERENCED_DOC_SUFFIXES:
            continue
        rel = candidate.relative_to(root).as_posix()
        if matching_exclusion(rel, config) is not None:
            notes.append(f"{origin} links to {target}, which operator config excludes; not scanned")
            continue
        if not Path(os.path.realpath(candidate)).is_relative_to(real_root):
            notes.append(f"{origin} links to {target} through a symlink leaving the scanned root; not scanned")
            continue
        if candidate in known or not candidate.is_file():
            continue
        known.add(candidate)
        found.append(InstructionFile(path=candidate, source=f"referenced from {origin}"))
    return found


@dataclass
class _Found:
    """The artifacts collected so far during discovery."""

    skills: list[Skill] = field(default_factory=list)
    instruction_files: list[InstructionFile] = field(default_factory=list)
    mcp_declarations: list[McpDeclaration] = field(default_factory=list)
    extension_packages: list[ExtensionPackage] = field(default_factory=list)
    agent_settings: list[SettingsFile] = field(default_factory=list)
    test_files: list[Path] = field(default_factory=list)
    unscanned: list[Unscanned] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    instruction_names: dict[str, str] = field(default_factory=dict)
    matched_patterns: set[str] = field(default_factory=set)

    def add_mcp(self, classified: McpDeclaration | Unscanned | None) -> None:
        """Record a classified MCP candidate under the matching list."""
        if isinstance(classified, McpDeclaration):
            self.mcp_declarations.append(classified)
        elif isinstance(classified, Unscanned):
            self.unscanned.append(classified)

    def add_client_item(self, item: ExtensionPackage | SettingsFile | Unscanned) -> None:
        """Record a client-data artifact under the matching list."""
        if isinstance(item, ExtensionPackage):
            self.extension_packages.append(item)
        elif isinstance(item, SettingsFile):
            self.agent_settings.append(item)
        else:
            self.unscanned.append(item)


def _visit_file(
    found: _Found,
    path: Path,
    rel: str,
    clients: ClientData,
    config: CheckerConfig,
) -> None:
    """Classify one file and record every artifact it is."""
    lower = path.name.lower()
    if lower == SKILL_MD.lower():
        found.skills.append(Skill(directory=path.parent, skill_md=path))

    source = found.instruction_names.get(lower)
    for pattern in config.instruction_files:
        if matches(rel, pattern):
            found.matched_patterns.add(pattern)
            source = source or "operator config"
    if source is not None:
        found.instruction_files.append(InstructionFile(path=path, source=source))

    if path.suffix.lower() in _MCP_SUFFIXES:
        found.add_mcp(_classify_mcp(path, rel, clients))

    if is_test_file(rel):
        found.test_files.append(path)

    for item in _classify_client_files(path, rel, clients):
        found.add_client_item(item)


def _add_declared_mcp(found: _Found, root: Path, clients: ClientData, config: CheckerConfig) -> None:
    """Inspect the MCP locations client data declares, when discovery did not already find them."""
    known_mcp = {d.path for d in found.mcp_declarations}
    for declared in clients.mcp_declaration_paths:
        candidate = Path(os.path.normpath(root / declared))
        if not candidate.is_relative_to(root) or candidate in known_mcp or not candidate.is_file():
            continue
        rel = candidate.relative_to(root).as_posix()
        if matching_exclusion(rel, config) is not None:
            continue
        classified = _classify_mcp(candidate, rel, clients)
        if classified is None:
            found.unscanned.append(
                Unscanned(rel, "declared by client data as an MCP location, but no server mapping was understood")
            )
        else:
            found.add_mcp(classified)


def discover(root: Path, clients: ClientData, config: CheckerConfig) -> Inventory:
    """Discover skills, instructions, MCP declarations and extensions under a root."""
    root = Path(root).resolve()
    excluded: Counter = Counter()

    # Matched case-insensitively: a client on a case-insensitive filesystem
    # loads agents.md when it asks for AGENTS.md, so treating them as
    # different files would be an evasion.
    instruction_names = {AGENTS_MD.lower(): AGENTS_MD}
    for name in clients.instruction_file_names:
        instruction_names.setdefault(name.lower(), name)
    found = _Found(instruction_names=instruction_names)

    for path, rel in _walk(root, config, found.unscanned, excluded):
        _visit_file(found, path, rel, clients, config)

    found.notes.extend(
        f"instruction_files pattern {pattern!r} matched no file"
        for pattern in config.instruction_files
        if pattern not in found.matched_patterns
    )

    _add_declared_mcp(found, root, clients, config)

    known_instructions = {i.path for i in found.instruction_files}
    for instruction in list(found.instruction_files):
        found.instruction_files.extend(_referenced_docs(instruction, root, config, known_instructions, found.notes))

    return Inventory(
        root=root,
        skills=tuple(found.skills),
        instruction_files=tuple(found.instruction_files),
        mcp_declarations=tuple(found.mcp_declarations),
        extension_packages=tuple(found.extension_packages),
        agent_settings=tuple(found.agent_settings),
        test_files=tuple(found.test_files),
        unscanned=tuple(found.unscanned),
        excluded=dict(excluded),
        notes=tuple(found.notes),
    )
