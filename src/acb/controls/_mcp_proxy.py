"""Recognise MCP declarations that reach a remote server through a stdio proxy."""

from __future__ import annotations

from dataclasses import dataclass

_PACKAGES = ("mcp-remote-client", "mcp-remote", "supergateway", "mcp-proxy")
_SUPERGATEWAY_URL_FLAGS = ("--sse", "--streamableHttp")
# Number of values each flag consumes, so that a value is never read as the server URL.
_VALUE_FLAGS = {
    "mcp-remote": dict.fromkeys(
        (
            "--header",
            "--header-file",
            "--resource",
            "--authorize-param",
            "--authorization-server",
            "--token-endpoint",
            "--static-oauth-client-metadata",
            "--static-oauth-client-info",
            "--client-metadata-url",
            "--host",
            "--bind-host",
            "--callback-path",
            "--auth-success-url",
            "--ignore-tool",
            "--auth-timeout",
            "--connect-timeout",
            "--headers-timeout",
            "--body-timeout",
            "--ping-interval",
            "--transport",
            "--protocol",
        ),
        1,
    ),
    "mcp-proxy": {
        "-H": 2,
        "--headers": 2,
        "-e": 2,
        "--env": 2,
        "--named-server": 2,
        **dict.fromkeys(
            (
                "--transport",
                "--client-id",
                "--client-secret",
                "--token-url",
                "--username",
                "--password",
                "--cwd",
                "--log-level",
                "--named-server-config",
                "--port",
                "--host",
                "--sse-port",
                "--sse-host",
                "--allow-origin",
                "--allowed-host",
                "--expose-header",
                "--initialization-timeout",
                "--auth-bearer-token",
            ),
            1,
        ),
    },
}


@dataclass(frozen=True)
class ProxyLaunch:
    """A proxy package named in a server's launch command."""

    package: str
    version: str | None
    args: tuple[str, ...]


def _split_spec(word: str) -> tuple[str, str | None]:
    """Split an executable path, package specifier or image reference into name and version."""
    spec = word.removeprefix("--package=")
    # A scoped npm package is a different package, whatever its last segment says.
    if spec.startswith("@"):
        return spec, None
    spec = spec.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    spec = spec.split("@sha256:", 1)[0]
    for separator in ("==", "@", ":"):
        name, found, version = spec.partition(separator)
        if found:
            return name, version
    return spec.removesuffix(".cmd").removesuffix(".exe"), None


def proxy_launch(server: dict) -> ProxyLaunch | None:
    """Return the proxy a server entry launches, with the arguments that follow its name."""
    command = server.get("command")
    args = server.get("args")
    words = [word for word in [command, *(args if isinstance(args, list) else [])] if isinstance(word, str)]
    found: ProxyLaunch | None = None
    for index, word in enumerate(words):
        # Once the proxy has its URL, a later word repeating a package name is only an argument.
        if "://" in word:
            if found is not None:
                break
            continue
        name, version = _split_spec(word)
        if name not in _PACKAGES:
            continue
        package = "mcp-remote" if name == "mcp-remote-client" else name
        # npx --package=mcp-remote@1 mcp-remote-client names it twice: keep the version, take the later arguments.
        if found is not None and found.package != package:
            break
        found = ProxyLaunch(package, version or (found.version if found else None), tuple(words[index + 1 :]))
    return found


def _flag_values(args: tuple[str, ...], flag: str, count: int = 1) -> list[tuple[str, ...]]:
    """Return the values of every occurrence of a flag, given as separate words or as flag=value."""
    values: list[tuple[str, ...]] = []
    for index, arg in enumerate(args):
        if arg == flag:
            values.append(args[index + 1 : index + 1 + count])
        elif arg.startswith(f"{flag}="):
            values.append((arg.split("=", 1)[1],))
    return [value for value in values if value]


def proxy_url(launch: ProxyLaunch) -> str | None:
    """Return the remote server URL the proxy connects to, or None if it names none."""
    if launch.package == "supergateway":
        urls = (value[0] for flag in _SUPERGATEWAY_URL_FLAGS for value in _flag_values(launch.args, flag))
        return next((url for url in urls if "://" in url), None)
    value_flags = _VALUE_FLAGS[launch.package]
    skip = 0
    for arg in launch.args:
        if skip:
            skip -= 1
        elif arg == "--":
            break
        elif arg.startswith("-"):
            skip = value_flags.get(arg, 0)
        else:
            # The first positional decides: for mcp-proxy anything but a URL is a local command.
            return arg if "://" in arg else None
    return None


def _has_auth_header(values: list[tuple[str, ...]], headers: frozenset[str]) -> bool:
    return any(value[0].split(":", 1)[0].strip().lower() in headers for value in values)


def proxy_declares_auth(launch: ProxyLaunch, server: dict, headers: frozenset[str]) -> bool:
    """Whether the launch declares a credential or OAuth client configuration for the remote server."""
    args = launch.args
    names = {arg.split("=", 1)[0] for arg in args}
    if launch.package == "mcp-remote":
        oauth = {
            "--header-file",
            "--static-oauth-client-info",
            "--static-oauth-client-metadata",
            "--client-metadata-url",
            "--client-credentials",
            "--device-code",
        }
        return bool(names & oauth) or _has_auth_header(_flag_values(args, "--header"), headers)
    if launch.package == "supergateway":
        return "--oauth2Bearer" in names or _has_auth_header(_flag_values(args, "--header"), headers)
    env = server.get("env")
    if isinstance(env, dict) and env.get("API_ACCESS_TOKEN"):
        return True
    pairs = _flag_values(args, "-H", 2) + _flag_values(args, "--headers", 2)
    return bool(names & {"--client-id", "--username"}) or _has_auth_header(pairs, headers)
