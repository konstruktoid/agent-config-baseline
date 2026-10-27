"""ACB-PROV-002: Skill and extension package content matches its recorded digest."""

from __future__ import annotations

from typing import TYPE_CHECKING

from acb.model import Finding, Outcome
from acb.provenance import DigestError, artifact_digest, artifacts, is_digest, record_path, resolve_record

if TYPE_CHECKING:
    from acb.controls import CheckContext

CONTROL_ID = "ACB-PROV-002"


def _check_digest_matches(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for relative, directory in artifacts(ctx).items():
        data, problem, from_operator = resolve_record(ctx, relative, directory)
        recorded = data.get("digest") if problem is None and isinstance(data, dict) else None
        if not is_digest(recorded):
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="digest-matches",
                    outcome=Outcome.NOT_EVALUATED,
                    message="no well-formed recorded digest to compare (see ACB-PROV-001)",
                    path=relative,
                )
            )
            continue
        try:
            actual = artifact_digest(directory)
        except DigestError as exc:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="digest-matches",
                    outcome=Outcome.NOT_EVALUATED,
                    message=f"digest cannot be computed: {exc}",
                    path=relative,
                )
            )
            continue
        if actual != recorded:
            origin = f"operator record in {ctx.provenance_records.source}" if from_operator else "recorded"
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="digest-matches",
                    outcome=Outcome.FAIL,
                    message=f"{origin} digest {recorded} does not match the content, which hashes to {actual}",
                    # The operator file lies outside PATH, so the finding names the artifact instead.
                    path=relative if from_operator else record_path(relative),
                )
            )
    return findings


AUDITS = {
    "digest-matches": _check_digest_matches,
}
