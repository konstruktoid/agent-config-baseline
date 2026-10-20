"""Find the artifacts a baseline run evaluates under PATH: skills, instruction
files and MCP server declarations.

Discovery errs toward finding too much rather than too little: anything it
cannot inspect but might be an artifact is recorded as unscanned, which makes
every control not-evaluated rather than letting the run pass.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from urllib.parse import unquote
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from acb.clients import ClientData
from acb.config import CheckerConfig, matching_exclusion
from acb.paths import matches
from acb.scan import safe_read_bytes, safe_read_text

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
    directory: Path
    skill_md: Path


@dataclass(frozen=True)
class InstructionFile:
    path: Path
    source: str


@dataclass(frozen=True)
class McpDeclaration:
    path: Path
    key: str
    servers: dict[str, dict]


@dataclass(frozen=True)
class Unscanned:
    path: str
    reason: str


@dataclass(frozen=True)
class Inventory:
    root: Path
    skills: tuple[Skill, ...]
    instruction_files: tuple[InstructionFile, ...]
    mcp_declarations: tuple[McpDeclaration, ...]
    unscanned: tuple[Unscanned, ...] = ()
    excluded: dict[str, int] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    def has_artifacts(self, artifact_type: str) -> bool:
        return bool(
            {
                "skill": self.skills,
                "instruction-file": self.instruction_files,
                "mcp-server-declaration": self.mcp_declarations,
            }[artifact_type]
        )


def _walk(root: Path, config: CheckerConfig, unscanned: list[Unscanned], excluded: Counter):
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


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas outside JSON strings."""
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

    stripped = "".join(out)
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
    """Merge every server mapping in the file that has at least one entry with
    a `command` or `url`. One such entry is enough: requiring it of every
    entry let a single dummy entry hide the whole file."""
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
        return Unscanned(rel, "possible MCP declaration is a symlink or unreadable; not inspected") if mcp_named else None

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
        if suspicious:
            return Unscanned(rel, "possible MCP declaration could not be parsed as JSON, JSONC or YAML")
        return None

    found = _server_mapping(data, clients.mcp_key_paths)
    if found is None:
        return None
    key, servers = found
    return McpDeclaration(path=path, key=key, servers=servers)


def _referenced_docs(
    instruction: InstructionFile,
    root: Path,
    config: CheckerConfig,
    known: set[Path],
    notes: list[str],
) -> list[InstructionFile]:
    """Documents an instruction file links to are instructions too: "follow
    docs/rules.md" must not move the payload out of scope. One level deep."""
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
        if target.startswith("/"):
            notes.append(f"{origin} links to absolute path {target}; not scanned")
            continue
        candidate = Path(os.path.normpath(instruction.path.parent / target))
        if not candidate.is_relative_to(root):
            notes.append(f"{origin} links to {target}, which is outside the scanned root; not scanned")
            continue
        if candidate.is_dir():
            notes.append(f"{origin} links to directory {target}; its contents are not scanned as instructions")
            continue
        if Path(target).suffix.lower() not in _REFERENCED_DOC_SUFFIXES:
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


def discover(root: Path, clients: ClientData, config: CheckerConfig) -> Inventory:
    root = Path(root).resolve()
    skills: list[Skill] = []
    instruction_files: list[InstructionFile] = []
    mcp_declarations: list[McpDeclaration] = []
    unscanned: list[Unscanned] = []
    notes: list[str] = []
    excluded: Counter = Counter()

    # Matched case-insensitively: a client on a case-insensitive filesystem
    # loads agents.md when it asks for AGENTS.md, so treating them as
    # different files would be an evasion.
    instruction_names = {AGENTS_MD.lower(): AGENTS_MD}
    for name in clients.instruction_file_names:
        instruction_names.setdefault(name.lower(), name)

    known_instructions: set[Path] = set()
    matched_patterns: set[str] = set()

    for path, rel in _walk(root, config, unscanned, excluded):
        lower = path.name.lower()
        if lower == SKILL_MD.lower():
            skills.append(Skill(directory=path.parent, skill_md=path))

        source = instruction_names.get(lower)
        for pattern in config.instruction_files:
            if matches(rel, pattern):
                matched_patterns.add(pattern)
                source = source or "operator config"
        if source is not None:
            instruction_files.append(InstructionFile(path=path, source=source))
            known_instructions.add(path)

        if path.suffix.lower() in _MCP_SUFFIXES:
            classified = _classify_mcp(path, rel, clients)
            if isinstance(classified, McpDeclaration):
                mcp_declarations.append(classified)
            elif isinstance(classified, Unscanned):
                unscanned.append(classified)

    for pattern in config.instruction_files:
        if pattern not in matched_patterns:
            notes.append(f"instruction_files pattern {pattern!r} matched no file")

    known_mcp = {d.path for d in mcp_declarations}
    for declared in clients.mcp_declaration_paths:
        candidate = Path(os.path.normpath(root / declared))
        if not candidate.is_relative_to(root) or candidate in known_mcp or not candidate.is_file():
            continue
        rel = candidate.relative_to(root).as_posix()
        if matching_exclusion(rel, config) is not None:
            continue
        classified = _classify_mcp(candidate, rel, clients)
        if isinstance(classified, McpDeclaration):
            mcp_declarations.append(classified)
        elif isinstance(classified, Unscanned):
            unscanned.append(classified)
        else:
            unscanned.append(Unscanned(rel, "declared by client data as an MCP location, but no server mapping was understood"))

    for instruction in list(instruction_files):
        instruction_files.extend(_referenced_docs(instruction, root, config, known_instructions, notes))

    return Inventory(
        root=root,
        skills=tuple(skills),
        instruction_files=tuple(instruction_files),
        mcp_declarations=tuple(mcp_declarations),
        unscanned=tuple(unscanned),
        excluded=dict(excluded),
        notes=tuple(notes),
    )
