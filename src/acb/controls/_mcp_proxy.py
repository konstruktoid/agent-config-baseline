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
# The only mcp-remote options besides --header that both 0.1.16 and the main branch read.
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
    env: dict


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


def _value_letter(option: str) -> int | None:
    """Return the position of the first letter in a short option cluster, such as -ite, that takes a value."""
    return next((i for i, c in enumerate(option[1:], start=1) if c not in _CONTAINER_BOOLEAN_LETTERS), None)


def _container_option(words: list[str], index: int) -> tuple[str, str, int]:
    """Return the name and value of the run option at index, and how many words it occupies."""
    word = words[index]
    following = words[index + 1] if index + 1 < len(words) else ""
    if word.startswith("--"):
        name, equals, value = word.partition("=")
        if equals:
            return name, value, 1
        return (name, "", 1) if name in _CONTAINER_BOOLEAN_FLAGS else (name, following, 2)
    position = _value_letter(word)
    if position is None:
        return word, "", 1
    attached = word[position + 1 :]
    return f"-{word[position]}", attached.removeprefix("=") if attached else following, 1 if attached else 2


def _from_image(words: list[str], host_env: dict) -> tuple[list[str], dict]:
    """Return the words that are executed and the environment they receive.

    For a container run command that is everything from the image or entrypoint on, with only the
    variables the command passes into the container.
    """
    engine = None
    for index, word in enumerate(words):
        name = _split_spec(word)[0]
        if name in _PACKAGES:
            break
        if name in _CONTAINER_ENGINES:
            engine = index
            break
    if engine is None or "run" not in words[engine + 1 :]:
        return words, host_env
    index = words.index("run", engine + 1) + 1
    entrypoint = None
    env: dict = {}
    while index < len(words) and words[index].startswith("-"):
        name, value, width = _container_option(words, index)
        if name == "--entrypoint":
            entrypoint = value
        elif name in ("-e", "--env"):
            variable, equals, assigned = value.partition("=")
            # Without =, the engine copies the variable from its own environment.
            passed = assigned if equals else host_env.get(variable)
            if passed is not None:
                env[variable] = passed
        index += width
    if entrypoint:
        return [entrypoint, *words[index + 1 :]], env
    return words[index:], env


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
    env = server.get("env")
    words, env = _from_image(words, env if isinstance(env, dict) else {})
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
                return ProxyLaunch(package, version or versions.get(package), tuple(words[index + 1 :]), env)
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


def proxy_url(launch: ProxyLaunch) -> str | None:
    """Return the remote endpoint the proxy is given, which may not be a valid URL, or None."""
    if launch.package == "supergateway":
        return next((v[0] for flag in _SUPERGATEWAY_URL_FLAGS for v in _flag_values(launch.args, flag)), None)
    endpoint = _first_positional(launch.args, _VALUE_FLAGS[launch.package])
    if launch.package == "mcp-remote":
        return endpoint
    if endpoint is None:
        endpoint = launch.env.get("SSE_URL")
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


def proxy_declares_auth(launch: ProxyLaunch, headers: frozenset[str]) -> bool:
    """Whether the launch declares a credential or OAuth client configuration for the remote server."""
    args = launch.args
    names = {arg.split("=", 1)[0] for arg in args}
    if launch.package == "mcp-remote":
        # mcp-remote matches whole words only, so --flag=value is ignored by the proxy.
        return any(_words_after(args, flag) for flag in _REMOTE_AUTH_FLAGS) or _has_auth_header(
            _words_after(args, "--header"), headers
        )
    if launch.package == "supergateway":
        return "--oauth2Bearer" in names or _has_auth_header(_array_values(args, "--header"), headers)
    if launch.env.get("API_ACCESS_TOKEN"):
        return True
    pairs = _flag_values(args, "-H", 2) + _flag_values(args, "--headers", 2)
    return bool(names & {"--client-id", "--username"}) or _has_auth_header([pair[0] for pair in pairs], headers)
