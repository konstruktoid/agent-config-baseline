"""Run the external Sigstore verifier on one bundle and check the in-toto statement it returns.

The verifier (verifier/acb_sigstore_verify.py, named by --sigstore-verifier) checks the certificate, log
entry, signer identity and DSSE signature against the trust root's Sigstore client trust config, and
prints the verified payload with the certificate values this module needs. Everything about the
statement is checked here, as docs/provenance-design.md section 6 question 5 decides: the subject
`dirHash`, the predicate type, and the trust root's signer and builder or verifier rules.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
BUILD_PROVENANCE = "https://slsa.dev/provenance/v1"
SOURCE_VSA = "https://slsa.dev/verification_summary/v1"
# The only buildType whose externalParameters this checker knows, so the only one it accepts.
GITHUB_WORKFLOW = "https://actions.github.io/buildtypes/workflow/v1"
_WORKFLOW_PARAMETERS = frozenset({"ref", "repository", "path"})

REJECTED_EXIT = 3
_TIMEOUT_SECONDS = 60
_MAX_OUTPUT = 4 << 20
_PAYLOAD_TYPE_RE = re.compile(r"application/vnd\.in-toto(\.[A-Za-z0-9._-]+)?\+json")
_SOURCE_LEVEL_RE = re.compile(r"SLSA_SOURCE_LEVEL_([0-9])")
_DIGEST_KEYS = ("dirHash", "dirHash1")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class VerifierError(Exception):
    """The verifier could not give an answer: missing, crashed, timed out or printed malformed output."""


class RejectedError(Exception):
    """The bundle or its statement does not satisfy the trust root for this artifact."""


@dataclass(frozen=True)
class Expected:
    """What a statement must say about one artifact, all taken from its operator record and content."""

    source: str
    commit: str
    dir_hash: str


@dataclass(frozen=True)
class Verified:
    """The verifier's output for a bundle whose signature, log entry and identity it accepted."""

    payload_type: str
    payload: bytes
    issuer: str
    san: tuple[str, ...]
    build_signer_uri: str | None
    source_repository_uri: str | None


def policies(policy: dict, source: str) -> list[tuple[str, str]]:
    """Return every (issuer, identity) pair the trust root allows, with `{source}` filled in."""
    pairs: list[tuple[str, str]] = []
    for signer in policy.get("build_provenance", {}).get("signers", []):
        pairs.extend((signer["issuer"], uri.replace("{source}", source)) for uri in signer["build_signer_uris"])
    pairs.extend((v["issuer"], v["identity"]) for v in policy.get("source_vsa", {}).get("verifiers", []))
    return list(dict.fromkeys(pairs))


def _clean(text: str) -> str:
    return _CONTROL_CHARS.sub("", text.strip()[-300:])


def _optional_str(value: object) -> bool:
    return value is None or isinstance(value, str)


def _parse_verified(stdout: str) -> Verified:
    try:
        data = json.loads(stdout)
        certificate = data["certificate"]
        payload = base64.b64decode(data["payload"], validate=True)
        issuer, san = certificate["issuer"], certificate["san"]
        build_signer_uri = certificate["build_signer_uri"]
        source_repository_uri = certificate["source_repository_uri"]
        payload_type = data["payload_type"]
    except (ValueError, TypeError, KeyError, binascii.Error) as exc:
        msg = f"verifier output is malformed: {exc}"
        raise VerifierError(msg) from exc
    if not (
        isinstance(payload_type, str)
        and isinstance(issuer, str)
        and isinstance(san, list)
        and all(isinstance(name, str) for name in san)
        and _optional_str(build_signer_uri)
        and _optional_str(source_repository_uri)
    ):
        msg = "verifier output is malformed: a certificate field has the wrong type"
        raise VerifierError(msg)
    return Verified(payload_type, payload, issuer, tuple(san), build_signer_uri, source_repository_uri)


def run_verifier(verifier: str, trust_config: str, bundle: str, allowed: list[tuple[str, str]]) -> Verified:
    """Run the verifier on one bundle; RejectedError: it refused the bundle; VerifierError: it could not say."""
    command = [verifier, "--trust-config", trust_config, "--bundle", bundle]
    for issuer, identity in allowed:
        command.extend(["--policy", issuer, identity])
    with tempfile.TemporaryDirectory(prefix="acb-verify-") as cwd:
        try:
            # The verifier is an absolute path the operator named, and its argv is never shell-interpreted.
            proc = subprocess.run(  # noqa: S603
                command,
                cwd=cwd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                env={"PATH": os.environ.get("PATH", os.defpath), "HOME": cwd},
                stdin=subprocess.DEVNULL,
                timeout=_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            msg = f"verifier could not run: {exc}"
            raise VerifierError(msg) from exc
    if len(proc.stdout) > _MAX_OUTPUT:
        msg = f"verifier output exceeds {_MAX_OUTPUT} bytes"
        raise VerifierError(msg)
    if proc.returncode == REJECTED_EXIT:
        try:
            reason = json.loads(proc.stdout)["rejected"]
        except (ValueError, TypeError, KeyError) as exc:
            msg = f"verifier output is malformed: {exc}"
            raise VerifierError(msg) from exc
        msg = f"the verifier rejected the bundle: {_clean(str(reason))}"
        raise RejectedError(msg)
    if proc.returncode != 0:
        msg = f"verifier exited {proc.returncode}: {_clean(proc.stderr)}"
        raise VerifierError(msg)
    return _parse_verified(proc.stdout)


def _mapping(container: dict, key: str, where: str) -> dict:
    value = container.get(key)
    if not isinstance(value, dict):
        msg = f"statement {where} is not an object"
        raise RejectedError(msg)
    return value


def _matching_subject(statement: dict, dir_hash: str) -> dict:
    """Return the digest set of the subject whose dirHash keys all equal dir_hash; a split subject rejects."""
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        msg = "statement has no subject"
        raise RejectedError(msg)
    found = None
    for subject in subjects:
        digest = subject.get("digest") if isinstance(subject, dict) else None
        if not isinstance(digest, dict):
            continue
        values = [digest[key] for key in _DIGEST_KEYS if key in digest]
        matches = [value == dir_hash for value in values]
        if any(matches) and not all(matches):
            msg = "a subject's dirHash and dirHash1 disagree"
            raise RejectedError(msg)
        if values and all(matches) and found is None:
            found = digest
    if found is None:
        msg = f"no subject has a dirHash equal to the artifact's, {dir_hash}"
        raise RejectedError(msg)
    return found


def _check_build_provenance(verified: Verified, predicate: dict, section: dict | None, expected: Expected) -> str:
    if section is None:
        msg = "the trust root has no build_provenance section, so build provenance is not accepted"
        raise RejectedError(msg)
    if verified.source_repository_uri != expected.source:
        msg = f"the certificate's Source Repository URI is {verified.source_repository_uri}, not {expected.source}"
        raise RejectedError(msg)
    signers = [
        signer
        for signer in section["signers"]
        if signer["issuer"] == verified.issuer
        and verified.build_signer_uri
        in {uri.replace("{source}", expected.source) for uri in signer["build_signer_uris"]}
    ]
    if not signers:
        msg = f"no trust root signer has issuer {verified.issuer} and Build Signer URI {verified.build_signer_uri}"
        raise RejectedError(msg)
    definition = _mapping(predicate, "buildDefinition", "buildDefinition")
    builder = _mapping(_mapping(predicate, "runDetails", "runDetails"), "builder", "runDetails.builder")
    pair = {"id": builder.get("id"), "build_type": definition.get("buildType")}
    if not any(pair in signer["builders"] for signer in signers):
        msg = f"builder {pair['id']} with buildType {pair['build_type']} is not listed for this signer"
        raise RejectedError(msg)
    if pair["build_type"] != GITHUB_WORKFLOW:
        msg = f"buildType {pair['build_type']} has externalParameters this checker cannot check"
        raise RejectedError(msg)
    parameters = _mapping(definition, "externalParameters", "buildDefinition.externalParameters")
    workflow = _mapping(parameters, "workflow", "externalParameters.workflow")
    if set(parameters) != {"workflow"} or set(workflow) != _WORKFLOW_PARAMETERS:
        msg = "externalParameters has fields the workflow/v1 buildType does not define, or lacks required ones"
        raise RejectedError(msg)
    if workflow["repository"] != expected.source:
        msg = f"externalParameters.workflow.repository is {workflow['repository']}, not {expected.source}"
        raise RejectedError(msg)
    return f"build provenance from {pair['id']}, signed by {verified.build_signer_uri}"


def _check_source_vsa(verified: Verified, predicate: dict, section: dict | None, expected: Expected) -> str:
    if section is None:
        msg = "the trust root has no source_vsa section, so a source VSA is not accepted"
        raise RejectedError(msg)
    verifier_id = _mapping(predicate, "verifier", "verifier").get("id")
    entries = [
        entry
        for entry in section["verifiers"]
        if entry["issuer"] == verified.issuer and entry["identity"] in verified.san and entry["id"] == verifier_id
    ]
    if not entries:
        msg = f"no trust root verifier has id {verifier_id}, issuer {verified.issuer} and the signing identity"
        raise RejectedError(msg)
    if predicate.get("resourceUri") != f"git+{expected.source}":
        msg = f"resourceUri is {predicate.get('resourceUri')}, not git+{expected.source}"
        raise RejectedError(msg)
    if predicate.get("verificationResult") != "PASSED":
        msg = f"verificationResult is {predicate.get('verificationResult')}, not PASSED"
        raise RejectedError(msg)
    levels = predicate.get("verifiedLevels")
    reached = [
        int(match.group(1))
        for level in (levels if isinstance(levels, list) else [])
        if isinstance(level, str) and (match := _SOURCE_LEVEL_RE.fullmatch(level))
    ]
    required = min(entry["min_source_level"] for entry in entries)
    if not reached or max(reached) < required:
        msg = f"verifiedLevels does not reach SLSA_SOURCE_LEVEL_{required}"
        raise RejectedError(msg)
    return f"source VSA at SLSA_SOURCE_LEVEL_{max(reached)} from {verifier_id}"


def check_statement(verified: Verified, policy: dict, expected: Expected) -> str:
    """Check the verified statement against the trust root and the artifact; return what was accepted."""
    if not _PAYLOAD_TYPE_RE.fullmatch(verified.payload_type):
        msg = f"payload type {verified.payload_type} is not an in-toto statement"
        raise RejectedError(msg)
    try:
        statement = json.loads(verified.payload)
    except (ValueError, RecursionError) as exc:
        msg = f"statement is not JSON: {exc}"
        raise RejectedError(msg) from exc
    if not isinstance(statement, dict) or statement.get("_type") != STATEMENT_TYPE:
        msg = f"statement _type is not {STATEMENT_TYPE}"
        raise RejectedError(msg)
    subject = _matching_subject(statement, expected.dir_hash)
    predicate_type = statement.get("predicateType")
    predicate = _mapping(statement, "predicate", "predicate")
    if predicate_type == BUILD_PROVENANCE:
        return _check_build_provenance(verified, predicate, policy.get("build_provenance"), expected)
    if predicate_type == SOURCE_VSA:
        if subject.get("gitCommit") != expected.commit:
            msg = f"the matching subject's gitCommit is {subject.get('gitCommit')}, not {expected.commit}"
            raise RejectedError(msg)
        return _check_source_vsa(verified, predicate, policy.get("source_vsa"), expected)
    msg = f"predicateType {predicate_type} is neither {BUILD_PROVENANCE} nor {SOURCE_VSA}"
    raise RejectedError(msg)
