"""Explicit registry mapping control IDs to their check implementations.

No import-time magic: a control absent from REGISTRY, or an audit id
absent from a registered module's AUDITS, is reported as not-evaluated by
the runner rather than silently skipped or assumed to pass.

Each control module exposes:

    CONTROL_ID: str
    AUDITS: dict[str, Callable[[CheckContext], list[Finding]]]

An AUDITS function returns FAIL findings for violations it found, a
NOT_EVALUATED finding when it cannot check, or a NOT_APPLICABLE finding when
the procedure needs data that is absent (client data, for example); an empty
list means that procedure passed for this run. The runner rejects any other
shape.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from acb.clients import ClientData
from acb.discovery import Inventory
from acb.model import Finding


@dataclass(frozen=True)
class CheckContext:
    inventory: Inventory
    clients: ClientData
    root: Path

    def relative(self, path: Path) -> str:
        # abspath, not resolve: report the path discovery found, which for an
        # in-root symlinked directory is the alias, not the target.
        try:
            return Path(os.path.abspath(path)).relative_to(self.root).as_posix()
        except ValueError:
            return Path(path).name


AuditFunc = Callable[[CheckContext], list[Finding]]

from acb.controls import (  # noqa: E402
    acb_gen_001,
    acb_gen_002,
    acb_gen_003,
    acb_gen_004,
    acb_instr_001,
    acb_instr_002,
    acb_instr_003,
    acb_skill_001,
    acb_skill_002,
    acb_skill_003,
)

_MODULES = (
    acb_gen_001,
    acb_gen_002,
    acb_gen_003,
    acb_gen_004,
    acb_instr_001,
    acb_instr_002,
    acb_instr_003,
    acb_skill_001,
    acb_skill_002,
    acb_skill_003,
)

REGISTRY: dict[str, dict[str, AuditFunc]] = {}
for _module in _MODULES:
    if _module.CONTROL_ID in REGISTRY:
        raise ImportError(f"{_module.__name__}: CONTROL_ID {_module.CONTROL_ID} is already registered")
    REGISTRY[_module.CONTROL_ID] = _module.AUDITS
