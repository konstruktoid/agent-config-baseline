"""`acb check PATH [options]`; build_parser lists the options.

PATH is untrusted content. Configuration comes from the operator: the
exceptions file and operator config default to files in the current working
directory, client data defaults to acb's bundled set. Nothing inside PATH
can change how PATH is judged.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from acb import __version__
from acb.clients import ClientDataError, load_clients
from acb.config import CONFIG_FILENAME, ConfigError, load_config
from acb.controls import CheckContext
from acb.discovery import discover
from acb.exceptions import (
    EXCEPTIONS_FILENAME,
    ExceptionsFileError,
    apply_exceptions,
    load_exceptions,
)
from acb.loader import (
    ControlLoadError,
    active_controls,
    default_clients_dir,
    default_controls_dir,
    default_schema_path,
    load_controls,
)
from acb.provenance import OperatorFileError, load_operator_records, load_trust_root, unused_operator_records
from acb.report import FORMATTERS, RunInfo
from acb.runner import all_pass, run


class UsageError(Exception):
    """Raised for invalid command-line usage."""


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(prog="acb")
    parser.add_argument("--version", action="version", version=f"acb {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="evaluate PATH against the strict-general baseline")
    check.add_argument("path", type=Path)
    check.add_argument("--format", choices=sorted(FORMATTERS), default="text")
    check.add_argument(
        "--exceptions",
        type=Path,
        default=None,
        help=f"reviewed exceptions file (default: ./{EXCEPTIONS_FILENAME} in the working directory, if present)",
    )
    check.add_argument(
        "--clients", type=Path, default=None, help="client data directory (default: acb's bundled clients/)"
    )
    check.add_argument(
        "--config",
        type=Path,
        default=None,
        help=f"operator configuration (default: ./{CONFIG_FILENAME} in the working directory, if present)",
    )
    # No working-directory default for either: a scanned repository must not be able to supply its own.
    check.add_argument(
        "--provenance-records",
        type=Path,
        default=None,
        help="operator provenance records that replace the in-directory .acb-provenance.yaml (no default)",
    )
    check.add_argument(
        "--trust-root",
        type=Path,
        default=None,
        help="operator trust root (schema/trust-root.schema.json); reports record its SHA-256 (no default)",
    )
    check.add_argument(
        "--sigstore-verifier",
        type=Path,
        default=None,
        help="absolute path of the Sigstore verifier program ACB-PROV-003 runs on each bundle (no default)",
    )
    check.add_argument(
        "--run-validators",
        action="store_true",
        help="run the capability validator client data names (a third-party binary) on extension packages; "
        "without it, validator-based audit procedures are not evaluated",
    )
    check.add_argument(
        "--require-artifacts",
        action="store_true",
        help="exit 1 when PATH holds no artifact to evaluate, instead of passing every control as not applicable",
    )
    return parser


def _operator_file(explicit: Path | None, default_name: str | None) -> Path | None:
    if explicit is not None:
        if not explicit.is_file():
            msg = f"{explicit}: no such file"
            raise UsageError(msg)
        return explicit
    if default_name is None:
        return None
    default = Path(default_name)
    return default if default.is_file() else None


def _uri_prefix(root: Path) -> str:
    relative = os.path.relpath(root, Path.cwd())
    if relative == "." or relative.startswith(".."):
        return ""
    return Path(relative).as_posix()


def _verifier(path: Path | None) -> str | None:
    """Return the verifier's path, which must be absolute so that no PATH lookup or working directory picks it."""
    if path is None:
        return None
    if not path.is_absolute():
        msg = f"{path}: --sigstore-verifier must be an absolute path"
        raise UsageError(msg)
    if not path.is_file() or not os.access(path, os.X_OK):
        msg = f"{path}: not an executable file"
        raise UsageError(msg)
    return str(path)


def _require_directory(path: Path | None) -> None:
    """Raise UsageError when an operator-supplied directory is not one."""
    if path is not None and not path.is_dir():
        msg = f"{path}: not a directory"
        raise UsageError(msg)


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface and return the exit status."""
    args = build_parser().parse_args(argv)

    root = args.path.resolve()
    if not root.is_dir():
        print(f"error: {args.path} is not a directory", file=sys.stderr)
        return 2

    try:
        all_controls = load_controls(default_controls_dir(), default_schema_path())
        controls = active_controls(all_controls)

        _require_directory(args.clients)
        clients = load_clients(args.clients if args.clients is not None else default_clients_dir())

        config = load_config(_operator_file(args.config, CONFIG_FILENAME))
        exceptions_path = _operator_file(args.exceptions, EXCEPTIONS_FILENAME)
        entries = load_exceptions(exceptions_path, {c.id for c in all_controls})
        records_path = _operator_file(args.provenance_records, None)
        records = load_operator_records(records_path)
        trust_root_path = _operator_file(args.trust_root, None)
        trust_root = load_trust_root(trust_root_path)
        verifier = _verifier(args.sigstore_verifier)
    except (UsageError, ControlLoadError, ClientDataError, ConfigError, ExceptionsFileError, OperatorFileError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    inventory = discover(root, clients, config)
    findings = run(
        controls,
        inventory,
        clients,
        root,
        run_validators=args.run_validators,
        require_artifacts=args.require_artifacts,
        provenance_records=records,
        trust_root=trust_root,
        sigstore_verifier=verifier,
    )
    unused_records = unused_operator_records(
        CheckContext(inventory=inventory, clients=clients, root=root, provenance_records=records)
    )
    exceptions_display = str(exceptions_path) if exceptions_path is not None else None
    applied = apply_exceptions(findings, entries, {c.id: c for c in controls}, exceptions_display)

    inside = tuple(
        str(path)
        for path in (config.source, exceptions_path, records_path, trust_root_path)
        if path is not None and Path(os.path.realpath(path)).is_relative_to(root)
    )
    info = RunInfo(
        version=__version__,
        target=str(args.path),
        config=config,
        exceptions_file=exceptions_display,
        exception_count=len(entries),
        stale_exceptions=applied.stale,
        clients=clients,
        inventory=inventory,
        uri_prefix=_uri_prefix(root),
        operator_files_inside_path=inside,
        provenance_records=records,
        unused_provenance_records=unused_records,
        trust_root=trust_root,
    )
    print(FORMATTERS[args.format](controls, applied.findings, info))
    return 0 if all_pass(controls, applied.findings, inventory) else 1


if __name__ == "__main__":
    raise SystemExit(main())
