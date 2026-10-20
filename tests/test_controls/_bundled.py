"""The bundled client data, which the EXT and CFG controls need to find anything."""

from __future__ import annotations

from acb.clients import load_clients
from acb.loader import default_clients_dir

BUNDLED = load_clients(default_clients_dir())
