import json

import pytest

from acb.controls.acb_mcp_002 import AUDITS
from tests._harness import context_for
from tests.test_controls._shared import check_pass_and_fail


def test_acb_mcp_002_fixtures():
    check_pass_and_fail("ACB-MCP-002", AUDITS)


@pytest.mark.parametrize(
    "server",
    [
        {"command": "/bin/bash", "args": ["-lc", "run"]},
        {"command": "C:\\Windows\\System32\\cmd.exe", "args": ["/c", "run"]},
        {"command": "pwsh", "args": ["-Command", "run"]},
        {"command": "node `id`"},
    ],
)
def test_shell_forms_fail(tmp_path, server):
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {"a": server}}))
    assert AUDITS["no-shell-interpretation"](context_for(tmp_path))


def test_shell_running_a_script_file_passes(tmp_path):
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {"a": {"command": "bash", "args": ["run.sh"]}}}))
    assert AUDITS["no-shell-interpretation"](context_for(tmp_path)) == []
