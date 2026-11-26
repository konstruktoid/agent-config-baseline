from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from acb.controls.acb_mcp_001 import AUDITS
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
    ],
)
def test_other_urls_are_not_the_server(tmp_path: Path, server: dict[str, Any]) -> None:
    assert _findings(tmp_path, "remote-uses-tls", server) == []


@pytest.mark.parametrize(
    ("server", "fails"),
    [
        ({"command": "mcp-remote", "args": [_URL, "--header", "X-Trace: 1"]}, True),
        ({"command": "mcp-remote", "args": [_URL, "--header-file", "h.txt"]}, False),
        ({"command": "mcp-remote", "args": [_URL, "--client-credentials"]}, False),
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
