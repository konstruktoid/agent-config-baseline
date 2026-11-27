from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from acb.controls.acb_mcp_004 import AUDITS
from tests._harness import context_for
from tests.test_controls._shared import check_pass_and_fail

if TYPE_CHECKING:
    from pathlib import Path


def test_acb_mcp_004_fixtures() -> None:
    check_pass_and_fail("ACB-MCP-004", AUDITS)


@pytest.mark.parametrize(
    ("args", "fails"),
    [
        (["mcp-remote@0.0.5"], True),
        (["--package=mcp-remote@0.1.0", "mcp-remote-client"], True),
        (["-p", "mcp-remote@0.1.0", "mcp-remote-client"], True),
        (["mcp-remote@=0.1.15"], True),
        (["mcp-remote@ =v0.1.15"], True),
        (["mcp-remote@0.1.0-beta.1+build.5"], True),
        (["-p=mcp-remote@0.1.0", "mcp-remote"], True),
        (["--package=supergateway@3.4.0", "--package=mcp-remote@0.1.15", "mcp-remote"], True),
        (["-p", "mcp-remote@0.1.0", "-c", "mcp-remote https://mcp.example.com/mcp"], True),
        (["mcp-remote@=0.1.16"], False),
        (["mcp-remote@0.1.0-beta || 1.0.0"], False),
        (["mcp-remote@0.1.0 - 0.2.0"], False),
        (["mcp-remote@^0.1.0"], False),
        (["mcp-remote@0.0.4"], False),
        (["mcp-remote@0.2.0"], False),
        (["mcp-remote@latest"], False),
        (["@someone/mcp-remote@0.1.0"], False),
        (["mcp-remote@0.1.0", "https://mcp.example.com/mcp", "--ignore-tool", "mcp-remote"], True),
        (["mcp-remote"], False),
    ],
)
def test_version_bounds(tmp_path: Path, args: list[str], *, fails: bool) -> None:
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {"a": {"command": "npx", "args": args}}}))
    assert bool(AUDITS["mcp-remote-not-vulnerable"](context_for(tmp_path))) is fails
