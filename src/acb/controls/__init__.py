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
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from acb.controls import (
    acb_cfg_001,
    acb_cfg_002,
    acb_cfg_003,
    acb_cfg_004,
    acb_cfg_005,
    acb_ext_001,
    acb_ext_002,
    acb_ext_003,
    acb_ext_004,
    acb_gen_001,
    acb_gen_002,
    acb_gen_003,
    acb_gen_004,
    acb_instr_001,
    acb_instr_002,
    acb_instr_003,
    acb_mcp_001,
    acb_mcp_002,
    acb_mcp_003,
    acb_prov_001,
    acb_prov_002,
    acb_skill_001,
    acb_skill_002,
    acb_skill_003,
)
from acb.model import Finding
from acb.provenance import OperatorRecords

if TYPE_CHECKING:
    from acb.clients import ClientData
    from acb.discovery import Inventory


@dataclass(frozen=True)
class CheckContext:
    """Inputs shared by every audit function in one run."""

    inventory: Inventory
    clients: ClientData
    root: Path
    # Running a client's validator executes a third-party binary, so the operator opts in.
    run_validators: bool = False
    provenance_records: OperatorRecords = field(default_factory=OperatorRecords)

    def relative(self, path: Path) -> str:
        """Return a path relative to the root, or its name when it lies outside."""
        # Normalize without resolving: report the path discovery found, which for an
        # in-root symlinked directory is the alias, not the target.
        try:
            return Path(os.path.normpath(Path(path).absolute())).relative_to(self.root).as_posix()
        except ValueError:
            return Path(path).name


AuditFunc = Callable[[CheckContext], list[Finding]]

_MODULES = (
    acb_gen_001,
    acb_gen_002,
    acb_gen_003,
    acb_gen_004,
    acb_instr_001,
    acb_instr_002,
    acb_instr_003,
    acb_mcp_001,
    acb_mcp_002,
    acb_mcp_003,
    acb_prov_001,
    acb_prov_002,
    acb_skill_001,
    acb_skill_002,
    acb_skill_003,
    acb_ext_001,
    acb_ext_002,
    acb_ext_003,
    acb_ext_004,
    acb_cfg_001,
    acb_cfg_002,
    acb_cfg_003,
    acb_cfg_004,
    acb_cfg_005,
)

REGISTRY: dict[str, dict[str, AuditFunc]] = {}
for _module in _MODULES:
    if _module.CONTROL_ID in REGISTRY:
        msg = f"{_module.__name__}: CONTROL_ID {_module.CONTROL_ID} is already registered"
        raise ImportError(msg)
    REGISTRY[_module.CONTROL_ID] = dict(_module.AUDITS)
