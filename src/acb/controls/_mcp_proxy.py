"""Recognise MCP declarations that reach a remote server through a stdio proxy."""

from __future__ import annotations

import shlex
from dataclasses import dataclass

_PACKAGES = ("mcp-remote-client", "mcp-remote", "supergateway", "mcp-proxy")
_SUPERGATEWAY_URL_FLAGS = ("--sse", "--streamableHttp")
# Runner options that name a package to install, as opposed to the executable to run.
_PACKAGE_FLAGS = frozenset({"--package", "-p", "--from", "--spec"})
_CALL_FLAGS = frozenset({"--call", "-c"})
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
        # None marks a flag that takes every following word up to the next option.
        "--allow-origin": None,
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
    # A scoped npm package is a different package, whatever its last segment says.
    if word.startswith("@"):
        return word, None
    spec = word.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    spec = spec.split("@sha256:", 1)[0]
    for separator in ("@", "==", ":"):
        name, found, version = spec.partition(separator)
        if found:
            return name, version
    return spec.removesuffix(".cmd").removesuffix(".exe"), None


def _package(name: str) -> str | None:
    if name not in _PACKAGES:
        return None
    return "mcp-remote" if name == "mcp-remote-client" else name


def _call_words(call: str) -> list[str]:
    try:
        return shlex.split(call)
    except ValueError:
        return []


def proxy_launch(server: dict) -> ProxyLaunch | None:
    """Return the proxy a server entry executes, with the arguments that follow its name."""
    command = server.get("command")
    args = server.get("args")
    words = [word for word in [command, *(args if isinstance(args, list) else [])] if isinstance(word, str)]
    versions: dict[str, str] = {}
    index = 0
    while index < len(words):
        word = words[index]
        flag, equals, value = word.partition("=")
        following = words[index + 1] if index + 1 < len(words) else ""
        if flag in _PACKAGE_FLAGS:
            name, version = _split_spec(value if equals else following)
            if (package := _package(name)) and version:
                versions[package] = version
            index += 1 if equals else 2
        elif flag in _CALL_FLAGS and " " in (call := value if equals else following):
            # npx --call carries the whole command line in one string.
            words[index : index + (1 if equals else 2)] = _call_words(call)
        elif word == "--name":
            index += 2
        else:
            name, version = _split_spec(word)
            if package := _package(name):
                return ProxyLaunch(package, version or versions.get(package), tuple(words[index + 1 :]))
            index += 1
    return None


def _flag_values(args: tuple[str, ...], flag: str, count: int = 1) -> list[tuple[str, ...]]:
    """Return the values of every occurrence of a flag, given as separate words or as flag=value."""
    values: list[tuple[str, ...]] = []
    for index, arg in enumerate(args):
        if arg == flag:
            values.append(args[index + 1 : index + 1 + count])
        elif arg.startswith(f"{flag}="):
            values.append((arg.split("=", 1)[1],))
    return [value for value in values if value]


def _values_taken(flag: str, value_flags: dict, following: tuple[str, ...]) -> int:
    """Return how many of the following words belong to a flag."""
    if flag == "--verify-ssl":
        # argparse would take a URL here too, but checking that URL is safer than dropping the server.
        return int(bool(following) and not following[0].startswith("-") and "://" not in following[0])
    count = value_flags.get(flag, 0)
    if count is None:
        return next((i for i, word in enumerate(following) if word.startswith("-")), len(following))
    return count


def _first_positional(args: tuple[str, ...], value_flags: dict) -> str | None:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return args[index + 1] if index + 1 < len(args) else None
        if not arg.startswith("-"):
            return arg
        index += 1 + _values_taken(arg, value_flags, args[index + 1 :])
    return None


def proxy_url(launch: ProxyLaunch, server: dict) -> str | None:
    """Return the remote endpoint the proxy is given, which may not be a valid URL, or None."""
    if launch.package == "supergateway":
        return next((v[0] for flag in _SUPERGATEWAY_URL_FLAGS for v in _flag_values(launch.args, flag)), None)
    endpoint = _first_positional(launch.args, _VALUE_FLAGS[launch.package])
    if launch.package == "mcp-remote":
        return endpoint
    env = server.get("env")
    if endpoint is None and isinstance(env, dict):
        endpoint = env.get("SSE_URL")
    # For mcp-proxy anything but a URL is a local command.
    return endpoint if isinstance(endpoint, str) and "://" in endpoint else None


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
