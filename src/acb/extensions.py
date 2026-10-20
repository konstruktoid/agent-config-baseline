"""Shared analysis of extension packages and agent settings files for the EXT
and CFG controls.

Everything product-specific (file layout, key paths, event names, the
validator command) comes from the package's or settings file's client
profile; this module only interprets that data.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from acb.discovery import ExtensionPackage, SettingsFile
from acb.scan import safe_read_text

CAPABILITY_RECORD = "extension-capabilities.txt"
_README_NAMES = ("readme.md", "readme", "readme.txt")
_MISSING = object()
_VALIDATOR_TIMEOUT_SECONDS = 120


def get_key(data: object, key_path: list[str]) -> object:
    """The value at key_path, or _MISSING."""
    node = data
    for part in key_path:
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


def has_key(data: object, key_path: list[str]) -> bool:
    return get_key(data, key_path) is not _MISSING


def rule_list(settings: SettingsFile, profile: dict, which: str) -> list[str]:
    value = get_key(settings.data, profile.get("agent_settings", {}).get(which, []) or ["\0"])
    return [r for r in value if isinstance(r, str)] if isinstance(value, list) else []


def requirement_failures(settings: SettingsFile, requirements: list[dict]) -> list[str]:
    """Human-readable failures for each managed requirement the file does not meet."""
    failures = []
    for req in requirements:
        value = get_key(settings.data, req["key"])
        key = ".".join(req["key"])
        if req["check"] == "equals" and value != req["value"]:
            shown = "unset" if value is _MISSING else json.dumps(value)
            failures.append(f"`{key}` must be {json.dumps(req['value'])} (is {shown})")
        elif req["check"] == "not-equals" and value is not _MISSING and value == req["value"]:
            failures.append(f"`{key}` must not be {json.dumps(req['value'])}")
        elif req["check"] == "contains-if-present" and value is not _MISSING:
            if not isinstance(value, list) or req["value"] not in value:
                failures.append(f"`{key}` is set, so it must list {json.dumps(req['value'])}")
    return failures


def _inside(path: Path, root: Path) -> bool:
    return Path(os.path.normpath(path)).is_relative_to(root)


@dataclass
class PackageAnalysis:
    """What a package ships, as far as static inspection can tell.

    `unreadable` lists package-relative paths that had to be inspected but
    could not be; callers report those as not evaluated.
    """

    content: list[str] = field(default_factory=list)
    # (kind, label, file the finding is anchored to)
    components: list[tuple[str, str, Path]] = field(default_factory=list)
    modules: list[Path] = field(default_factory=list)
    hook_configs: list[tuple[str, dict]] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)


def _manifest_paths(value: object) -> list[str]:
    items = value if isinstance(value, list) else [value]
    return [v for v in items if isinstance(v, str)]


def analyse_package(package: ExtensionPackage, profile: dict) -> PackageAnalysis:
    ext = profile.get("extension_packages", {})
    root = package.root
    result = PackageAnalysis()

    for rel in ext.get("content_paths", []):
        if (root / rel).exists():
            result.content.append(rel)
    for key in ext.get("content_manifest_keys", []):
        if has_key(package.manifest_data, key):
            result.content.append(f"manifest `{'.'.join(key)}`")

    for comp in ext.get("component_paths", []):
        if (root / comp["path"]).exists():
            result.components.append((comp["kind"], comp["path"], root / comp["path"]))
    for comp in ext.get("component_manifest_keys", []):
        if has_key(package.manifest_data, comp["key"]):
            result.components.append((comp["kind"], f"manifest `{'.'.join(comp['key'])}`", package.manifest))

    hook_files = [root / rel for rel in ext.get("hook_files", [])]
    manifest_hooks = get_key(package.manifest_data, ext.get("hook_files_manifest_key", ["\0"]))
    if manifest_hooks is not _MISSING:
        for item in manifest_hooks if isinstance(manifest_hooks, list) else [manifest_hooks]:
            if isinstance(item, dict):
                result.hook_configs.append(("manifest", {"hooks": item}))
        hook_files += [root / p for p in _manifest_paths(manifest_hooks) if p.endswith(".json")]

    modules: list[Path] = []
    list_key = ext.get("module_list_key")
    for hook_file in hook_files:
        if not hook_file.exists() or not _inside(hook_file, root):
            continue
        rel = hook_file.relative_to(root).as_posix()
        text = safe_read_text(hook_file)
        try:
            data = json.loads(text) if text is not None else None
        except (json.JSONDecodeError, RecursionError):
            data = None
        if not isinstance(data, dict):
            result.unreadable.append(rel)
            continue
        result.hook_configs.append((rel, data))
        listed = get_key(data, list_key) if list_key else _MISSING
        for entry in listed if isinstance(listed, list) else []:
            if isinstance(entry, str):
                candidate = Path(os.path.normpath(hook_file.parent / entry))
                if _inside(candidate, root):
                    modules.append(candidate)
                else:
                    result.unreadable.append(f"{rel} lists module {entry!r} outside the package")

    suffixes = tuple(ext.get("module_suffixes", []))
    test_suffixes = tuple(ext.get("module_test_suffixes", []))
    for rel_dir in ext.get("module_dirs", []):
        directory = root / rel_dir
        if directory.is_dir() and suffixes:
            for path in sorted(directory.rglob("*")):
                if path.is_file() and path.name.endswith(suffixes) and not path.name.endswith(test_suffixes):
                    modules.append(path)

    result.modules = list(dict.fromkeys(modules))
    for module in result.modules:
        result.components.append(("in-process-modules", module.relative_to(root).as_posix(), module))
    return result


def module_capabilities(module: Path, profile: dict) -> tuple[set[str], set[str]] | None:
    """(events, calls) a module's source registers and makes, or None if it cannot be read."""
    text = safe_read_text(module)
    if text is None:
        return None
    ext = profile.get("extension_packages", {})
    events = {m.group(1) for m in re.finditer(ext["module_event_pattern"], text)} if ext.get("module_event_pattern") else set()
    calls = {m.group(1) for m in re.finditer(ext["module_call_pattern"], text)} if ext.get("module_call_pattern") else set()
    return events, calls


def readme_text(package: ExtensionPackage) -> str | None:
    """The package README's text, '' when there is none, None when it exists but cannot be read."""
    for path in sorted(package.root.iterdir()):
        if path.is_file() and path.name.lower() in _README_NAMES:
            return safe_read_text(path)
    return ""


def parse_capability_lines(text: str, profile: dict) -> set[tuple[str, str, tuple[str, ...]]]:
    """(module file name, kind, sorted items) for every validator-format line in text."""
    validator = profile.get("extension_packages", {}).get("validator", {})
    pattern = validator.get("line_pattern")
    if not pattern:
        return set()
    found = set()
    for line in text.splitlines():
        m = re.match(pattern, line)
        if m:
            items = tuple(sorted(i.strip() for i in m.group("items").split(",") if i.strip()))
            found.add((Path(m.group("module")).name, m.group("kind"), items))
    return found


@dataclass(frozen=True)
class ValidatorResult:
    lines: set[tuple[str, str, tuple[str, ...]]] | None
    problem: str | None = None


def run_validator(package: ExtensionPackage, profile: dict) -> ValidatorResult:
    """Run the client's validator on the package without a shell, from an empty
    working directory so no project configuration next to the scan is loaded."""
    validator = profile.get("extension_packages", {}).get("validator")
    if not validator:
        return ValidatorResult(None, f"client {package.client} declares no capability validator")
    command = list(validator["command"])
    executable = shutil.which(command[0])
    if executable is None:
        return ValidatorResult(None, f"validator `{' '.join(command)}` is not installed")
    with tempfile.TemporaryDirectory(prefix="acb-validate-") as cwd:
        try:
            proc = subprocess.run(
                [executable, *command[1:], str(package.root)],
                cwd=cwd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=_VALIDATOR_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ValidatorResult(None, f"validator could not run: {exc}")
    if proc.returncode != 0:
        return ValidatorResult(None, f"validator exited {proc.returncode}: {proc.stdout.strip()[-300:]}")
    return ValidatorResult(parse_capability_lines(proc.stdout, profile))


@dataclass(frozen=True)
class BlockingHook:
    source: str
    event: str
    handler: dict


def blocking_hooks(config: dict, source: str, profile: dict) -> list[BlockingHook]:
    """Handlers registered for a blocking event in a settings-style hooks mapping."""
    settings = profile.get("agent_settings", {})
    events = get_key(config, settings.get("hooks_key", ["\0"]))
    found = []
    if not isinstance(events, dict):
        return found
    for event in settings.get("blocking_hook_events", []):
        groups = events.get(event)
        for group in groups if isinstance(groups, list) else []:
            handlers = group.get("hooks") if isinstance(group, dict) else None
            for handler in handlers if isinstance(handlers, list) else []:
                if isinstance(handler, dict):
                    found.append(BlockingHook(source, event, handler))
    return found


def hook_script_files(handler: dict, variables: dict[str, Path], root: Path) -> list[Path]:
    """Files under root that a command handler's command line or args name."""
    command = handler.get("command")
    if not isinstance(command, str):
        return []
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    args = handler.get("args")
    tokens += [a for a in args if isinstance(a, str)] if isinstance(args, list) else []
    found = []
    for token in tokens:
        expanded = token
        for name, base in variables.items():
            expanded = expanded.replace("${" + name + "}", str(base)).replace("$" + name, str(base))
        candidate = Path(expanded) if os.path.isabs(expanded) else root / expanded
        candidate = Path(os.path.normpath(candidate))
        if candidate.is_relative_to(root) and candidate.is_file():
            found.append(candidate)
    return found


def settings_by_client(settings_files) -> dict[str, list[SettingsFile]]:
    grouped: dict[str, list[SettingsFile]] = {}
    for settings in settings_files:
        grouped.setdefault(settings.client, []).append(settings)
    return grouped


def missing_rule_groups(settings_files: list[SettingsFile], profile: dict, groups_key: str) -> list[dict] | None:
    """Rule groups none of whose rules appear in the combined deny lists, or None
    when the client defines no groups and the requirement cannot be checked."""
    groups = profile.get(groups_key)
    if not groups:
        return None
    deny = {rule.strip() for settings in settings_files for rule in rule_list(settings, profile, "deny_rules_key")}
    return [group for group in groups if not deny & {rule.strip() for rule in group["any_of"]}]
