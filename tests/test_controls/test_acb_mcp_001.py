from acb.controls.acb_mcp_001 import AUDITS
from acb.model import Outcome
from tests._harness import context_for
from tests.test_controls._shared import check_pass_and_fail


def test_acb_mcp_001_fixtures():
    check_pass_and_fail("ACB-MCP-001", AUDITS)


def test_loopback_forms_are_exempt(tmp_path):
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"a": {"url": "http://localhost/m"}, "b": {"url": "ws://[::1]:9/m"},'
        ' "c": {"url": "http://127.1.2.3/m"}}}'
    )
    for audit in AUDITS.values():
        assert audit(context_for(tmp_path)) == []


def test_unparseable_url_is_not_evaluated(tmp_path):
    (tmp_path / "mcp.json").write_text('{"mcpServers": {"a": {"url": "${MCP_URL}/m"}}}')
    findings = AUDITS["remote-uses-tls"](context_for(tmp_path))
    assert [f.outcome for f in findings] == [Outcome.NOT_EVALUATED]
