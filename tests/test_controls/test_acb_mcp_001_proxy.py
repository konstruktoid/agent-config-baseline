from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from acb.controls.acb_mcp_001 import AUDITS
from acb.model import Outcome
from tests._harness import context_for

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Any

_URL = "http://mcp.example.com/mcp"


def _findings(tmp_path: Path, audit: str, server: dict[str, Any]) -> list:
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {"a": server}}))
    return AUDITS[audit](context_for(tmp_path))


@pytest.mark.parametrize(
    "server",
    [
        {"command": "npx", "args": ["--package=mcp-remote@0.1.16", "mcp-remote-client", _URL]},
        {"command": "cmd", "args": ["/c", "npx", "mcp-remote", _URL]},
        {"command": "npx", "args": ["supergateway", "--sse", _URL]},
        {"command": "mcp-remote", "args": [_URL, "--ignore-tool", "mcp-remote"]},
        {"command": "npx", "args": ["supergateway", f"--streamableHttp={_URL}"]},
        {"command": "uvx", "args": ["mcp-proxy==0.8.0", "-H", "X-Trace", "1", _URL]},
        {"command": "/usr/local/bin/mcp-proxy", "args": ["--transport", "streamablehttp", _URL]},
        {"command": "docker", "args": ["run", "-i", "ghcr.io/sparfenyuk/mcp-proxy:v1", _URL]},
        {"command": "docker", "args": ["run", "--name", "mcp-proxy", "ghcr.io/sparfenyuk/mcp-proxy", _URL]},
        {"command": "mcp-proxy", "args": ["--", _URL]},
        {"command": "mcp-proxy", "args": ["--verify-ssl", "true", _URL]},
        {"command": "mcp-proxy", "args": ["--verify-ssl", _URL]},
        {"command": "mcp-proxy", "args": [], "env": {"SSE_URL": _URL}},
        {"command": "npx", "args": ["--package=supergateway@3.4.0", "-p", "mcp-remote", "mcp-remote", _URL]},
        {"command": "npx", "args": ["-p=mcp-remote@0.1.16", "mcp-remote-client", _URL]},
        {"command": "npx", "args": ["-p", "mcp-remote", "-c", f"mcp-remote {_URL}"]},
        {"command": "uvx", "args": ["--from", "mcp-proxy==0.8.0", "mcp-proxy", _URL]},
        {"command": "npx", "args": ["-p", "supergateway@3.4.0", "-c", f"supergateway\t--sse\t{_URL}"]},
        {"command": "docker", "args": ["run", "-v", "/a:/mcp-proxy", "ghcr.io/sparfenyuk/mcp-proxy", _URL]},
        {"command": "docker", "args": ["run", "--rm", "-ite", "X=mcp-remote", "supercorp/supergateway", "--sse", _URL]},
        {"command": "docker", "args": ["run", "--name=x", "--entrypoint", "mcp-proxy", "some/image", _URL]},
        {"command": "sudo", "args": ["docker", "run", "-v/a:/supergateway", "ghcr.io/sparfenyuk/mcp-proxy", _URL]},
        {"command": "docker", "args": ["run", "-i", "node:22", "npx", "-y", "mcp-remote", _URL]},
        {"command": "docker", "args": ["run", "-e", f"SSE_URL={_URL}", "x/mcp-proxy:v0.10.0"]},
        {"command": "docker", "args": ["run", f"--env=SSE_URL={_URL}", "x/mcp-proxy"]},
        {"command": "docker", "args": ["run", f"-ieSSE_URL={_URL}", "x/mcp-proxy"]},
        {"command": "docker", "args": ["run", "-e", "SSE_URL", "x/mcp-proxy"], "env": {"SSE_URL": _URL}},
    ],
)
def test_proxied_cleartext_fails(tmp_path: Path, server: dict[str, Any]) -> None:
    assert _findings(tmp_path, "remote-uses-tls", server)


@pytest.mark.parametrize(
    "server",
    [
        {"command": "mcp-proxy", "args": ["--port", "8080", "uvx", "server", "--api", _URL]},
        {"command": "mcp-proxy", "args": ["--", "server", _URL]},
        {"command": "npx", "args": ["supergateway", "--stdio", "server", "--baseUrl", _URL]},
        {"command": "npx", "args": ["some-server", _URL]},
        {"command": "mcp-proxy", "args": ["--allow-origin", "http://a.example.com", "http://b.example.com"]},
        {"command": "npx", "args": ["-p", "mcp-remote", "some-server", _URL]},
        {"command": "docker", "args": ["run", "x/mcp-proxy"], "env": {"SSE_URL": _URL}},
    ],
)
def test_other_urls_are_not_the_server(tmp_path: Path, server: dict[str, Any]) -> None:
    assert _findings(tmp_path, "remote-uses-tls", server) == []


@pytest.mark.parametrize(
    "server",
    [
        {"command": "mcp-remote", "args": ["mcp.example.com/mcp"]},
        {"command": "mcp-remote", "args": ["${MCP_URL}"]},
        {"command": "supergateway", "args": ["--sse", "mcp.example.com/sse"]},
    ],
)
def test_unreadable_endpoint_is_not_evaluated(tmp_path: Path, server: dict[str, Any]) -> None:
    assert [f.outcome for f in _findings(tmp_path, "remote-uses-tls", server)] == [Outcome.NOT_EVALUATED]


@pytest.mark.parametrize(
    ("server", "fails"),
    [
        ({"command": "mcp-remote", "args": [_URL, "--header", "X-Trace: 1"]}, True),
        ({"command": "mcp-remote", "args": [_URL, "--header-file", "h.txt"]}, True),
        ({"command": "mcp-remote", "args": [_URL, "--client-credentials"]}, True),
        (
            {
                "command": "mcp-remote",
                "args": ["--header-file", "/etc/mcp-remote", _URL, "--header", "Authorization: x"],
            },
            False,
        ),
        ({"command": "mcp-remote", "args": [_URL, "--header=Authorization: Bearer ${T}"]}, True),
        ({"command": "mcp-remote", "args": [_URL, "--header-file=h.txt"]}, True),
        ({"command": "mcp-remote", "args": [_URL, "--static-oauth-client-info", "@c.json"]}, False),
        ({"command": "mcp-remote", "args": [_URL, "--device-code"]}, True),
        ({"command": "docker", "args": ["run", "-e", "API_ACCESS_TOKEN=${T}", "x/mcp-proxy", _URL]}, False),
        (
            {
                "command": "docker",
                "args": ["run", "-e", "API_ACCESS_TOKEN", "x/mcp-proxy", _URL],
                "env": {"API_ACCESS_TOKEN": "${T}"},
            },
            False,
        ),
        ({"command": "docker", "args": ["run", "x/mcp-proxy", _URL], "env": {"API_ACCESS_TOKEN": "${T}"}}, True),
        ({"command": "supergateway", "args": ["--sse", _URL, "--header", "X-A: 1", "Authorization: ${T}"]}, False),
        ({"command": "supergateway", "args": ["--sse", _URL, "--header=Authorization: ${T}"]}, False),
        ({"command": "supergateway", "args": ["--sse", _URL]}, True),
        ({"command": "supergateway", "args": ["--sse", _URL, "--oauth2Bearer", "${T}"]}, False),
        ({"command": "mcp-proxy", "args": [_URL]}, True),
        ({"command": "mcp-proxy", "args": ["-H", "Authorization", "Bearer ${T}", _URL]}, False),
        ({"command": "mcp-proxy", "args": [_URL], "env": {"API_ACCESS_TOKEN": "${T}"}}, False),
        ({"command": "mcp-proxy", "args": ["--client-id", "id", _URL]}, False),
    ],
)
def test_proxied_auth(tmp_path: Path, server: dict[str, Any], *, fails: bool) -> None:
    assert bool(_findings(tmp_path, "remote-declares-auth", server)) is fails
