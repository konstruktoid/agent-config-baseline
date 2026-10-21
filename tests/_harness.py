"""Shared helper for control-check tests: build a CheckContext over a fixture directory."""

from __future__ import annotations

from pathlib import Path

from acb.clients import ClientData
from acb.config import CheckerConfig
from acb.controls import CheckContext
from acb.discovery import discover


def context_for(root: Path, clients: ClientData | None = None) -> CheckContext:
    clients = clients if clients is not None else ClientData()
    root = root.resolve()
    inventory = discover(root, clients, CheckerConfig())
    return CheckContext(inventory=inventory, clients=clients, root=root)
