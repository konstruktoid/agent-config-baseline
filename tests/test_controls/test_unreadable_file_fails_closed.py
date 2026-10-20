"""A symlinked (or otherwise unreadable) artifact must be reported as
NOT_EVALUATED, not silently skipped, for every ACB-GEN-00[1-4] audit that
reads file text.

This pins the fail-closed convention across the four ACB-GEN control
modules: `safe_read_text` returns None for a symlink (scan.py refuses to
dereference it), and each audit must turn that into an explicit
NOT_EVALUATED finding, which no exception can waive, rather than
`continue`-ing past it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from acb.controls.acb_gen_001 import AUDITS as GEN_001_AUDITS
from acb.controls.acb_gen_002 import AUDITS as GEN_002_AUDITS
from acb.controls.acb_gen_003 import AUDITS as GEN_003_AUDITS
from acb.controls.acb_gen_004 import AUDITS as GEN_004_AUDITS
from acb.model import Outcome
from tests._harness import context_for


def _make_symlinked_agents_md(tmp_path: Path) -> Path:
    real_target = tmp_path / "elsewhere.txt"
    real_target.write_text("not an agent instructions file", encoding="utf-8")
    link = tmp_path / "AGENTS.md"
    link.symlink_to(real_target)
    return tmp_path


@pytest.mark.parametrize(
    "audits,audit_id",
    [
        (GEN_001_AUDITS, "pipe-to-interpreter"),
        (GEN_002_AUDITS, "package-runners-pinned"),
        (GEN_002_AUDITS, "lockfile-or-hash"),
        (GEN_002_AUDITS, "images-by-digest"),
        (GEN_002_AUDITS, "downloads-verified"),
        (GEN_003_AUDITS, "secret-scan"),
        (GEN_004_AUDITS, "forbidden-code-points"),
        (GEN_004_AUDITS, "confusable-identifiers"),
    ],
)
def test_symlinked_instruction_file_fails_closed(tmp_path: Path, audits, audit_id):
    root = _make_symlinked_agents_md(tmp_path)
    ctx = context_for(root)
    findings = audits[audit_id](ctx)
    assert findings, f"{audit_id} silently skipped an unreadable (symlinked) file instead of failing closed"
    assert all(f.outcome == Outcome.NOT_EVALUATED for f in findings)
    assert any("could not be read" in f.message for f in findings)
