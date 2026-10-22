"""Load optional per-client data.

Client data holds facts about one agent client that no open specification defines (extra
instruction-file names, MCP declaration locations, permission-bypass flags, configuration locations).

Client data belongs to acb, not to the repository being scanned. It is read
from acb's bundled clients/ directory, or from --clients DIR, which replaces
the bundled set. Each file is validated against schema/client.schema.json.
A client file only adds things to look for; it never changes control logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import yaml

from acb.loader import schema_errors
from acb.yamlsafe import safe_load_strict

if TYPE_CHECKING:
    from pathlib import Path


class ClientDataError(Exception):
    """Raised when client data cannot be loaded."""


@dataclass(frozen=True)
class ClientData:
    """Per-client profiles describing where each agent keeps its configuration."""

    source: Path | None = None
    clients: tuple[str, ...] = ()
    instruction_file_names: tuple[str, ...] = ()
    mcp_declaration_paths: tuple[str, ...] = ()
    mcp_key_paths: tuple[str, ...] = ()
    permission_bypass_flags: tuple[str, ...] = ()
    config_write_paths: tuple[str, ...] = ()
    # Per-client structured data (agent settings, extension packages); keyed by client name.
    profiles: tuple[tuple[str, dict[str, Any]], ...] = ()

    def profile(self, client: str) -> dict[str, Any]:
        """Return the profile for a client, or an empty one when it is unknown."""
        return dict(self.profiles).get(client, {})


_LIST_FIELDS = (
    "instruction_file_names",
    "mcp_declaration_paths",
    "mcp_key_paths",
    "permission_bypass_flags",
    "config_write_paths",
)


def load_clients(clients_dir: Path | None) -> ClientData:
    """Load and validate client data from a directory."""
    if clients_dir is None:
        return ClientData()
    if not clients_dir.is_dir():
        msg = f"{clients_dir}: not a directory"
        raise ClientDataError(msg)

    names: list[str] = []
    merged: dict[str, list[str]] = {field: [] for field in _LIST_FIELDS}
    profiles: list[tuple[str, dict]] = []
    for path in sorted(list(clients_dir.glob("*.yaml")) + list(clients_dir.glob("*.yml"))):
        try:
            data = safe_load_strict(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            msg = f"{path}: cannot be read: {exc}"
            raise ClientDataError(msg) from exc
        except (yaml.YAMLError, RecursionError, TypeError, ValueError) as exc:
            msg = f"{path}: not valid YAML: {exc}"
            raise ClientDataError(msg) from exc
        errors = schema_errors("client.schema.json", data)
        if errors:
            raise ClientDataError(f"{path}: " + "; ".join(errors))
        if data["client"] in names:
            msg = f"{path}: client {data['client']!r} is declared more than once"
            raise ClientDataError(msg)
        names.append(data["client"])
        for field in _LIST_FIELDS:
            merged[field].extend(data.get(field, []))
        profiles.append((data["client"], data))

    return ClientData(
        source=clients_dir,
        clients=tuple(names),
        profiles=tuple(profiles),
        **{field: tuple(dict.fromkeys(values)) for field, values in merged.items()},
    )
