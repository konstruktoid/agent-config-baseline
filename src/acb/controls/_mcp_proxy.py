"""Recognise MCP declarations that reach a remote server through a stdio proxy."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

_PACKAGES = ("mcp-remote-client", "mcp-remote", "supergateway", "mcp-proxy")
_SUPERGATEWAY_URL_FLAGS = ("--sse", "--streamableHttp")
# Runner options that name a package to install, as opposed to the executable to run.
_PACKAGE_FLAGS = frozenset({"--package", "-p", "--from", "--spec"})
_CALL_FLAGS = frozenset({"--call", "-c"})
_CONTAINER_ENGINES = frozenset({"docker", "podman", "nerdctl"})
# Options of docker run that take no value; any other option is assumed to take one.
_CONTAINER_BOOLEAN_FLAGS = frozenset(
    {
        "--detach",
        "--disable-content-trust",
        "--help",
        "--init",
        "--interactive",
        "--no-healthcheck",
        "--oom-kill-disable",
        "--privileged",
        "--publish-all",
        "--quiet",
        "--read-only",
        "--replace",
        "--rm",
        "--sig-proxy",
        "--tty",
        "--use-api-socket",
    }
)
_CONTAINER_BOOLEAN_LETTERS = frozenset("ditPq")
_IDENTIFIERS = r"[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*"
# npm reads versions loosely, so leading =, v and spaces still name one exact version.
_EXACT_VERSION_RE = re.compile(rf"^[\s=v]*(\d+)\.(\d+)\.(\d+)(?:-{_IDENTIFIERS})?(?:\+{_IDENTIFIERS})?\s*$")
# mcp-remote options that count as authentication in every version checked.
_REMOTE_AUTH_FLAGS = frozenset({"--static-oauth-client-info", "--static-oauth-client-metadata"})
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


def exact_version(version: str | None) -> tuple[int, ...] | None:
    """Return the numbers of an exact version, or None for a tag, a range or no version."""
    match = _EXACT_VERSION_RE.match(version or "")
    return tuple(map(int, match.groups())) if match else None


def _takes_next_word(option: str) -> bool:
    if "=" in option:
        return False
    if option.startswith("--"):
        return option not in _CONTAINER_BOOLEAN_FLAGS
    # In a cluster such as -ite, the first letter that takes a value uses the rest of the word, if there is any.
    for position, letter in enumerate(option[1:], start=1):
        if letter not in _CONTAINER_BOOLEAN_LETTERS:
            return position == len(option) - 1
    return False


def _from_image(words: list[str]) -> list[str]:
    """For a container run command, return the words from what the container executes onwards."""
    engine = None
    for index, word in enumerate(words):
        name = _split_spec(word)[0]
        if name in _PACKAGES:
            break
        if name in _CONTAINER_ENGINES:
            engine = index
            break
    if engine is None or "run" not in words[engine + 1 :]:
        return words
    index = words.index("run", engine + 1) + 1
    entrypoint = None
    while index < len(words) and words[index].startswith("-"):
        option, equals, value = words[index].partition("=")
        takes_next = _takes_next_word(words[index])
        if option == "--entrypoint":
            entrypoint = value if equals else "".join(words[index + 1 : index + 2])
        index += 2 if takes_next else 1
    if entrypoint:
        return [entrypoint, *words[index + 1 :]]
    return words[index:]


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
    words = _from_image(words)
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
        elif flag in _CALL_FLAGS:
            # npx --call carries the whole command line in one string.
            words[index : index + (1 if equals else 2)] = _call_words(value if equals else following)
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


def _has_auth_header(values: list[str], headers: frozenset[str]) -> bool:
    return any(value.split(":", 1)[0].strip().lower() in headers for value in values)


def _words_after(args: tuple[str, ...], flag: str) -> list[str]:
    """Return the next word after each occurrence of a flag; the flag=value form does not count."""
    return [args[index + 1] for index, arg in enumerate(args[:-1]) if arg == flag]


def _array_values(args: tuple[str, ...], flag: str) -> list[str]:
    """Return every value of a flag that takes several words up to the next option."""
    values = [arg.split("=", 1)[1] for arg in args if arg.startswith(f"{flag}=")]
    for index, arg in enumerate(args):
        if arg == flag:
            values += args[index + 1 : index + 1 + _values_taken(flag, {flag: None}, args[index + 1 :])]
    return values


def proxy_declares_auth(launch: ProxyLaunch, server: dict, headers: frozenset[str]) -> bool:
    """Whether the launch declares a credential or OAuth client configuration for the remote server."""
    args = launch.args
    names = {arg.split("=", 1)[0] for arg in args}
    if launch.package == "mcp-remote":
        # mcp-remote matches whole words only, so --flag=value is ignored by the proxy.
        version = exact_version(launch.version)
        later = version is None or version > (0, 1, 16)
        valued = _REMOTE_AUTH_FLAGS | ({"--header-file", "--client-metadata-url"} if later else set())
        boolean = {"--client-credentials", "--device-code"} if later else set()
        return (
            any(_words_after(args, flag) for flag in valued)
            or bool(boolean & set(args))
            or _has_auth_header(_words_after(args, "--header"), headers)
        )
    if launch.package == "supergateway":
        return "--oauth2Bearer" in names or _has_auth_header(_array_values(args, "--header"), headers)
    env = server.get("env")
    if isinstance(env, dict) and env.get("API_ACCESS_TOKEN"):
        return True
    pairs = _flag_values(args, "-H", 2) + _flag_values(args, "--headers", 2)
    return bool(names & {"--client-id", "--username"}) or _has_auth_header([pair[0] for pair in pairs], headers)
