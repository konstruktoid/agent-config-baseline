"""Operator configuration: exclusions and extra instruction files.

Read from --config FILE, by default ./.acb.yaml relative to the current
working directory. It is never read from inside the scanned PATH: the
artifacts being judged must not be able to configure their own audit.

    exclude:
      - path: "tests/fixtures/**"
        reason: "Failing examples by design."
    instruction_files:
      - PROMPT.md
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from acb.loader import schema_errors
from acb.paths import PatternError, matches_or_under, validate_pattern
from acb.yamlsafe import safe_load_strict

CONFIG_FILENAME = ".acb.yaml"


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Exclusion:
    pattern: str
    reason: str


@dataclass(frozen=True)
class CheckerConfig:
    source: Path | None = None
    exclude: tuple[Exclusion, ...] = ()
    instruction_files: tuple[str, ...] = ()


def load_config(path: Path | None) -> CheckerConfig:
    if path is None:
        return CheckerConfig()
    try:
        data = safe_load_strict(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: cannot be read: {exc}") from exc
    except (yaml.YAMLError, RecursionError, TypeError, ValueError) as exc:
        raise ConfigError(f"{path}: not valid YAML: {exc}") from exc
    if data is None:
        data = {}

    errors = schema_errors("config.schema.json", data)
    if errors:
        raise ConfigError(f"{path}: " + "; ".join(errors))

    exclusions = []
    for entry in data.get("exclude", []):
        try:
            exclusions.append(Exclusion(pattern=validate_pattern(entry["path"]), reason=entry["reason"]))
        except PatternError as exc:
            raise ConfigError(f"{path}: exclude: {exc}") from exc

    instruction_files = []
    for entry in data.get("instruction_files", []):
        try:
            instruction_files.append(validate_pattern(entry))
        except PatternError as exc:
            raise ConfigError(f"{path}: instruction_files: {exc}") from exc

    return CheckerConfig(source=path, exclude=tuple(exclusions), instruction_files=tuple(instruction_files))


def matching_exclusion(relative_posix: str, config: CheckerConfig) -> Exclusion | None:
    for exclusion in config.exclude:
        if matches_or_under(relative_posix, exclusion.pattern):
            return exclusion
    return None
