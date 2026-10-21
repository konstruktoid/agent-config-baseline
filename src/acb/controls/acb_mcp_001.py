"""ACB-MCP-001: Remote MCP servers use TLS and declare authentication."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from acb.model import Finding, Outcome

CONTROL_ID = "ACB-MCP-001"

_URL_KEYS = ("url", "serverUrl")
_TLS_SCHEMES = {"https", "wss"}
_AUTH_KEYS = {"auth", "oauth", "authorization"}
_AUTH_HEADERS = {"authorization", "proxy-authorization", "x-api-key", "api-key", "apikey"}


def _is_loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _remote_servers(ctx):
    """Yield (declaration, server name, url) for every server with a non-loopback url."""
    for decl in ctx.inventory.mcp_declarations:
        for name, server in decl.servers.items():
            raw = next((server[key] for key in _URL_KEYS if key in server), None)
            if raw is None:
                continue
            try:
                host = urlsplit(raw).hostname if isinstance(raw, str) else None
            except ValueError:
                host = None
            if host is not None and _is_loopback(host):
                continue
            yield decl, name, server, raw


def _finding(ctx, decl, audit_id: str, outcome: Outcome, message: str) -> Finding:
    return Finding(
        control_id=CONTROL_ID,
        audit_id=audit_id,
        outcome=outcome,
        message=message,
        path=ctx.relative(decl.path),
    )


def _check_tls(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for decl, name, _server, raw in _remote_servers(ctx):
        try:
            parts = urlsplit(raw) if isinstance(raw, str) else None
        except ValueError:
            parts = None
        if parts is None or not parts.scheme or not parts.hostname:
            findings.append(
                _finding(ctx, decl, "remote-uses-tls", Outcome.NOT_EVALUATED, f"server {name!r} url cannot be parsed")
            )
        elif parts.scheme.lower() not in _TLS_SCHEMES:
            findings.append(
                _finding(
                    ctx, decl, "remote-uses-tls", Outcome.FAIL, f"server {name!r} uses cleartext scheme {parts.scheme!r}"
                )
            )
    return findings


def _declares_auth(server: dict) -> bool:
    if any(server.get(key) for key in _AUTH_KEYS):
        return True
    headers = server.get("headers")
    return isinstance(headers, dict) and any(str(key).lower() in _AUTH_HEADERS for key in headers)


def _check_auth(ctx) -> list[Finding]:
    return [
        _finding(ctx, decl, "remote-declares-auth", Outcome.FAIL, f"server {name!r} declares no authentication")
        for decl, name, server, _raw in _remote_servers(ctx)
        if not _declares_auth(server)
    ]


AUDITS = {
    "remote-uses-tls": _check_tls,
    "remote-declares-auth": _check_auth,
}
