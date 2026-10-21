from __future__ import annotations

from typing import TYPE_CHECKING

from acb.controls.acb_mcp_001 import AUDITS
from acb.model import Outcome
from tests._harness import context_for
from tests.test_controls._shared import check_pass_and_fail

if TYPE_CHECKING:
    from pathlib import Path


def test_acb_mcp_001_fixtures() -> None:
    check_pass_and_fail("ACB-MCP-001", AUDITS)


def test_loopback_forms_are_exempt(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"a": {"url": "http://localhost/m"}, "b": {"url": "ws://[::1]:9/m"},'
        ' "c": {"url": "http://127.1.2.3/m"}}}'
    )
    for audit in AUDITS.values():
        assert audit(context_for(tmp_path)) == []


def test_unparseable_url_is_not_evaluated(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text('{"mcpServers": {"a": {"url": "${MCP_URL}/m"}}}')
    findings = AUDITS["remote-uses-tls"](context_for(tmp_path))
    assert [f.outcome for f in findings] == [Outcome.NOT_EVALUATED]


def test_proxy_authorization_is_not_server_authentication(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"a": {"url": "https://mcp.example.com/m", "headers": {"Proxy-Authorization": "${P}"}}}}'
    )
    assert AUDITS["remote-declares-auth"](context_for(tmp_path))
