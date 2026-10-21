"""Locate acb's bundled data (controls, schemas, client data) and load controls."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path

import jsonschema
import yaml
from jsonschema.protocols import Validator

from acb.model import Control
from acb.yamlsafe import safe_load_strict


class ControlLoadError(Exception):
    """Raised when a control file fails schema validation or a uniqueness check."""


def _repo_root_from(start: Path) -> Path | None:
    for parent in [start, *start.parents]:
        if (parent / "controls").is_dir() and (parent / "schema").is_dir():
            return parent
    return None


def _bundled_dir(name: str) -> Path:
    """acb's own copy of `name` (controls/, schema/, clients/): the installed
    package data, or the repository checkout when running from source."""
    bundled = resources.files("acb").joinpath("_data", name)
    if bundled.is_dir():
        return Path(str(bundled))
    root = _repo_root_from(Path(__file__).resolve())
    if root is not None and (root / name).is_dir():
        return root / name
    raise ControlLoadError(f"could not locate acb's bundled {name}/ directory")


def default_controls_dir() -> Path:
    return _bundled_dir("controls")


def default_schema_dir() -> Path:
    return _bundled_dir("schema")


def default_clients_dir() -> Path:
    return _bundled_dir("clients")


def default_schema_path() -> Path:
    return default_schema_dir() / "control.schema.json"


@lru_cache(maxsize=8)
def schema_validator(name: str) -> Validator:
    schema = json.loads((default_schema_dir() / name).read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(schema)


def schema_errors(name: str, data: object) -> list[str]:
    errors = sorted(schema_validator(name).iter_errors(data), key=lambda e: list(e.path))
    return [f"{'/'.join(str(p) for p in e.path) or '(root)'}: {e.message}" for e in errors]


def load_controls(controls_dir: Path, schema_path: Path) -> list[Control]:
    """Load, schema-validate and cross-check every control YAML file.

    Raises ControlLoadError on the first problem found, with the specific
    file and reason, rather than silently skipping or guessing.
    """
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)

    files = sorted(Path(controls_dir).glob("*.yaml"))
    if not files:
        raise ControlLoadError(f"no control YAML files found under {controls_dir}")

    controls: list[Control] = []
    seen_ids: dict[str, Path] = {}
    for path in files:
        text = path.read_text(encoding="utf-8")
        try:
            data = safe_load_strict(text)
        except yaml.YAMLError as exc:
            raise ControlLoadError(f"{path}: not valid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise ControlLoadError(f"{path}: top-level content must be a mapping")

        errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
        if errors:
            details = "; ".join(f"{list(e.path)}: {e.message}" for e in errors)
            raise ControlLoadError(f"{path}: schema validation failed: {details}")

        control_id = data["id"]
        if control_id in seen_ids:
            raise ControlLoadError(
                f"duplicate control id {control_id} in {path} (already defined in {seen_ids[control_id]})"
            )
        seen_ids[control_id] = path

        audit_ids = [a["id"] for a in data["audit"]]
        dupes = {a for a in audit_ids if audit_ids.count(a) > 1}
        if dupes:
            raise ControlLoadError(f"{path}: duplicate audit procedure id(s) {sorted(dupes)}")

        if data["id"] != path.stem:
            raise ControlLoadError(f"{path}: control id {control_id!r} does not match filename")

        if data["status"] == "deprecated" and "deprecated_by" not in data:
            raise ControlLoadError(f"{path}: status is deprecated but deprecated_by is missing")

        controls.append(Control.from_dict(data, path))

    return controls


def active_controls(controls: list[Control], profile: str = "strict-general") -> list[Control]:
    return [c for c in controls if c.status != "deprecated" and profile in c.profiles]
