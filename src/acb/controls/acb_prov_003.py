"""ACB-PROV-003: A signed attestation binds each skill and extension package to its recorded source."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from acb.attestation import Expected, RejectedError, VerifierError, check_statement, policies, run_verifier
from acb.model import Finding, Outcome
from acb.provenance import DIGEST_PREFIX, DigestError, artifact_digest, artifacts

if TYPE_CHECKING:
    from acb.controls import CheckContext

CONTROL_ID = "ACB-PROV-003"


def _finding(outcome: Outcome, message: str, path: str) -> Finding:
    return Finding(control_id=CONTROL_ID, audit_id="signature-verifies", outcome=outcome, message=message, path=path)


def _missing_input(ctx: CheckContext) -> str | None:
    if ctx.trust_root.trust_config is None:
        return f"no trust root ({ctx.trust_root.reason})"
    if ctx.sigstore_verifier is None:
        return "no verifier (--sigstore-verifier not given)"
    return None


def _check_signature_verifies(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    missing = _missing_input(ctx)
    for relative, directory in artifacts(ctx).items():
        record = ctx.provenance_records.records.get(relative)
        if record is None:
            # The expected source must come from the operator: whoever changes an artifact can change its own record.
            message = "no operator record in --provenance-records names the source to verify against"
            findings.append(_finding(Outcome.NOT_EVALUATED, message, relative))
            continue
        bundles = ctx.provenance_records.bundles.get(relative, ())
        if not bundles:
            message = f"the operator record in {ctx.provenance_records.source} names no Sigstore bundle"
            findings.append(_finding(Outcome.FAIL, message, relative))
            continue
        if missing is not None:
            findings.append(_finding(Outcome.NOT_EVALUATED, f"signature not checked: {missing}", relative))
            continue
        try:
            digest = artifact_digest(directory)
        except DigestError as exc:
            findings.append(_finding(Outcome.NOT_EVALUATED, f"digest cannot be computed: {exc}", relative))
            continue
        dir_hash = base64.b64decode(digest[len(DIGEST_PREFIX) :]).hex()
        expected = Expected(source=record["source"], commit=record["commit"], dir_hash=dir_hash)
        finding = _verify_bundles(ctx, relative, bundles, expected)
        if finding is not None:
            findings.append(finding)
    return findings


def _verify_bundles(ctx: CheckContext, relative: str, bundles: tuple[str, ...], expected: Expected) -> Finding | None:
    """Pass when any bundle is accepted; otherwise fail, unless a verifier failure leaves the result unknown."""
    policy = ctx.trust_root.policy
    allowed = policies(policy, expected.source)
    if not allowed:
        return _finding(Outcome.FAIL, "no bundle verifies against the trust root: it allows no signer", relative)
    rejected: list[str] = []
    unknown: list[str] = []
    for bundle in bundles:
        try:
            verified = run_verifier(str(ctx.sigstore_verifier), str(ctx.trust_root.trust_config), bundle, allowed)
            check_statement(verified, policy, expected)
        except RejectedError as exc:
            rejected.append(f"{bundle}: {exc}")
        except VerifierError as exc:
            unknown.append(f"{bundle}: {exc}")
        else:
            return None
    if unknown:
        return _finding(Outcome.NOT_EVALUATED, "the verifier gave no result for " + "; ".join(unknown), relative)
    return _finding(Outcome.FAIL, "no bundle verifies against the trust root: " + "; ".join(rejected), relative)


AUDITS = {
    "signature-verifies": _check_signature_verifies,
}
