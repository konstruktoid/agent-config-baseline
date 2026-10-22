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
from typing import TYPE_CHECKING

import yaml

from acb.loader import schema_errors
from acb.paths import PatternError, matches_or_under, validate_pattern
from acb.yamlsafe import safe_load_strict

if TYPE_CHECKING:
    from pathlib import Path

CONFIG_FILENAME = ".acb.yaml"


class ConfigError(Exception):
    """Raised when the checker configuration is invalid."""


@dataclass(frozen=True)
class Exclusion:
    """One exclusion pattern with its justification."""

    pattern: str
    reason: str


@dataclass(frozen=True)
class CheckerConfig:
    """Checker configuration read from an operator-supplied file."""

    source: Path | None = None
    exclude: tuple[Exclusion, ...] = ()
    instruction_files: tuple[str, ...] = ()


def load_config(path: Path | None) -> CheckerConfig:
    """Load and validate the checker configuration."""
    if path is None:
        return CheckerConfig()
    try:
        data = safe_load_strict(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        msg = f"{path}: cannot be read: {exc}"
        raise ConfigError(msg) from exc
    except (yaml.YAMLError, RecursionError, TypeError, ValueError) as exc:
        msg = f"{path}: not valid YAML: {exc}"
        raise ConfigError(msg) from exc
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
            msg = f"{path}: exclude: {exc}"
            raise ConfigError(msg) from exc

    instruction_files = []
    for entry in data.get("instruction_files", []):
        try:
            instruction_files.append(validate_pattern(entry))
        except PatternError as exc:
            msg = f"{path}: instruction_files: {exc}"
            raise ConfigError(msg) from exc

    return CheckerConfig(source=path, exclude=tuple(exclusions), instruction_files=tuple(instruction_files))


def matching_exclusion(relative_posix: str, config: CheckerConfig) -> Exclusion | None:
    """Return the first exclusion matching a relative POSIX path, or None."""
    for exclusion in config.exclude:
        if matches_or_under(relative_posix, exclusion.pattern):
            return exclusion
    return None
