"""Sign a SLSA build provenance statement for one artifact directory with the ambient GitHub Actions identity.

Run by .github/workflows/sign-test-bundle.yml to produce a real Sigstore bundle that ACB-PROV-003 and
acb-sigstore-verify can be tested against. The statement's subject carries only `dirHash`, the acb artifact
digest in the lowercase hex form the in-toto digest set defines, and its predicate uses the GitHub Actions
workflow/v1 buildType that acb checks.

    python sign_test_statement.py --name NAME --digest h1:BASE64 --out FILE
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path

from sigstore.dsse import Statement
from sigstore.models import ClientTrustConfig
from sigstore.oidc import IdentityToken, detect_credential
from sigstore.sign import SigningContext


def _statement(name: str, dir_hash: str) -> bytes:
    """Return the statement JSON, describing the workflow run from the GitHub Actions environment."""
    server = os.environ["GITHUB_SERVER_URL"]
    workflow_ref = os.environ["GITHUB_WORKFLOW_REF"]
    path = workflow_ref.split("@", 1)[0].removeprefix(f"{os.environ['GITHUB_REPOSITORY']}/")
    run = f"{os.environ['GITHUB_RUN_ID']}/attempts/{os.environ['GITHUB_RUN_ATTEMPT']}"
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": name, "digest": {"dirHash": dir_hash}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {
                    "workflow": {
                        "ref": os.environ["GITHUB_REF"],
                        "repository": f"{server}/{os.environ['GITHUB_REPOSITORY']}",
                        "path": path,
                    },
                },
                "resolvedDependencies": [
                    {
                        "uri": f"git+{server}/{os.environ['GITHUB_REPOSITORY']}@{os.environ['GITHUB_REF']}",
                        "digest": {"gitCommit": os.environ["GITHUB_SHA"]},
                    },
                ],
            },
            "runDetails": {
                "builder": {"id": f"{server}/actions/runner/github-hosted"},
                "metadata": {"invocationId": f"{server}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{run}"},
            },
        },
    }
    return json.dumps(statement, separators=(",", ":")).encode()


def _unvalidated(contents: bytes) -> Statement:
    """Wrap statement bytes without sigstore-python's validation, which rejects a `dirHash` subject digest."""
    statement = object.__new__(Statement)
    statement._contents = contents
    return statement


def main(argv: list[str] | None = None) -> int:
    """Sign the statement and write the bundle; return the exit status."""
    parser = argparse.ArgumentParser(prog="sign_test_statement")
    parser.add_argument("--name", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    token = detect_credential()
    if token is None:
        print("no ambient OIDC credential; the job needs id-token: write", file=sys.stderr)
        return 1
    context = SigningContext.from_trust_config(ClientTrustConfig.production())
    # cache=False makes sigstore-python 4.5.1 sign with a different key than the one Fulcio certified.
    with context.signer(IdentityToken(token)) as signer:
        dir_hash = base64.b64decode(args.digest.removeprefix("h1:"), validate=True).hex()
        bundle = signer.sign_dsse(_unvalidated(_statement(args.name, dir_hash)))
    args.out.write_text(bundle.to_json(), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
