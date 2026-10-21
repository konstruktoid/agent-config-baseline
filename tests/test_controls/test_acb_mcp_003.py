import json

import pytest

from acb.controls.acb_mcp_003 import AUDITS
from tests._harness import context_for
from tests.test_controls._shared import check_pass_and_fail


def test_acb_mcp_003_fixtures():
    check_pass_and_fail("ACB-MCP-003", AUDITS)


def _findings(tmp_path, server):
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {"a": server}}))
    return AUDITS["no-hijack-env"](context_for(tmp_path))


@pytest.mark.parametrize(
    "server",
    [
        {"command": "x", "env": {"bash_env": "/tmp/rc"}},
        {"command": "x", "environment": {"NODE_OPTIONS": "--max-old-space-size=1 -r ./h.js"}},
        {"command": "x", "env": [{"name": "NODE_OPTIONS", "value": "--import=./h.mjs"}]},
        {"command": "x", "env": {"NODE_OPTIONS": "--experimental-loader ./l.mjs"}},
        {"command": "env", "args": ["LD_PRELOAD=/tmp/h.so", "node", "s.js"]},
        {"command": "/usr/bin/sudo", "args": ["-n", "BASH_ENV=/tmp/rc", "node", "s.js"]},
        {"command": "env", "args": ["NODE_OPTIONS=--require ./h.js", "node", "s.js"]},
    ],
)
def test_hijack_forms_fail(tmp_path, server):
    assert _findings(tmp_path, server)


@pytest.mark.parametrize(
    "server",
    [
        {"command": "x", "env": {"NODE_OPTIONS": "--require-module-flag-lookalike"}},
        {"command": "x", "env": {"NODE_OPTIONS": "--max-old-space-size=4096"}},
        {"command": "x", "env": "not-a-mapping"},
        {"command": "env", "args": ["LOG=info", "node", "s.js"]},
        {"command": "node", "args": ["s.js", "LD_PRELOAD=/tmp/h.so"]},
    ],
)
def test_benign_forms_pass(tmp_path, server):
    assert _findings(tmp_path, server) == []
