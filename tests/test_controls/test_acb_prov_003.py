import base64
import copy
import json
import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from acb.attestation import BUILD_PROVENANCE, GITHUB_WORKFLOW, SOURCE_VSA, STATEMENT_TYPE
from acb.controls import CheckContext
from acb.controls.acb_prov_003 import AUDITS
from acb.model import Outcome
from acb.provenance import OperatorRecords, TrustRoot, artifact_digest, load_operator_records, load_trust_root
from tests._harness import context_for

SOURCE = "https://github.com/example/skills"
COMMIT = "ab" * 20
ISSUER = "https://token.actions.githubusercontent.com"
SIGNER = f"{SOURCE}/.github/workflows/release.yml@refs/heads/main"
BUILDER = "https://github.com/actions/runner/github-hosted"
VSA_ID = "https://example.com/source-verifier"
VSA_IDENTITY = "https://example.com/verifier/.github/workflows/vsa.yml@refs/heads/main"
POLICY = {
    "version": 1,
    "sigstore": {"trust_config": "trust-config.json", "sha256": "0" * 64},
    "build_provenance": {
        "signers": [
            {
                "issuer": ISSUER,
                "build_signer_uris": ["{source}/.github/workflows/release.yml@refs/heads/main"],
                "builders": [{"id": BUILDER, "build_type": GITHUB_WORKFLOW}],
            }
        ]
    },
    "source_vsa": {"verifiers": [{"id": VSA_ID, "issuer": ISSUER, "identity": VSA_IDENTITY, "min_source_level": 2}]},
}

# Prints the canned response stored beside it for the bundle it is given, and records its arguments.
_FAKE = """#!{python}
import json, pathlib, sys
here = pathlib.Path(__file__).parent
(here / "args.json").write_text(json.dumps(sys.argv[1:]))
responses = json.loads((here / "response.json").read_text())
response = responses.get(sys.argv[sys.argv.index("--bundle") + 1], responses["*"])
sys.stdout.write(response["stdout"])
sys.stderr.write(response.get("stderr", ""))
sys.exit(response["exit"])
"""


def _skill(root: Path) -> Path:
    directory = root / "skills" / "a"
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text("---\nname: a\ndescription: A test skill for provenance.\n---\n\nBody.\n")
    return directory


def _dir_hash(directory: Path) -> str:
    return base64.b64decode(artifact_digest(directory)[3:]).hex()


def _build_statement(dir_hash: str) -> dict:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "a", "digest": {"dirHash": dir_hash}}],
        "predicateType": BUILD_PROVENANCE,
        "predicate": {
            "buildDefinition": {
                "buildType": GITHUB_WORKFLOW,
                "externalParameters": {
                    "workflow": {
                        "ref": "refs/heads/main",
                        "repository": SOURCE,
                        "path": ".github/workflows/release.yml",
                    }
                },
            },
            "runDetails": {"builder": {"id": BUILDER}},
        },
    }


def _vsa_statement(dir_hash: str) -> dict:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"digest": {"dirHash": dir_hash, "gitCommit": COMMIT}}],
        "predicateType": SOURCE_VSA,
        "predicate": {
            "verifier": {"id": VSA_ID},
            "resourceUri": f"git+{SOURCE}",
            "verificationResult": "PASSED",
            "verifiedLevels": ["SLSA_SOURCE_LEVEL_3"],
        },
    }


def _verified(statement: dict, **certificate: object) -> dict:
    cert = {"issuer": ISSUER, "san": [SIGNER], "build_signer_uri": SIGNER, "source_repository_uri": SOURCE}
    cert.update(certificate)
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    return {
        "exit": 0,
        "stdout": json.dumps({"payload_type": "application/vnd.in-toto+json", "payload": payload, "certificate": cert}),
    }


class Setup:
    def __init__(self, tmp_path: Path) -> None:
        """Lay out a skill, a fake verifier and an empty bundle under tmp_path."""
        self.root = tmp_path / "target"
        self.directory = _skill(self.root)
        self.dir_hash = _dir_hash(self.directory)
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.verifier = self.bin / "verify"
        self.verifier.write_text(_FAKE.format(python=sys.executable))
        self.verifier.chmod(0o755)
        self.bundle = tmp_path / "a.sigstore.json"
        self.bundle.write_text("{}")
        self.policy = copy.deepcopy(POLICY)

    def respond(self, response: dict, **by_bundle: dict) -> None:
        responses = {"*": response, **{str(self.bundle.parent / name): r for name, r in by_bundle.items()}}
        (self.bin / "response.json").write_text(json.dumps(responses))

    def args(self) -> list[str]:
        return json.loads((self.bin / "args.json").read_text())

    def context(self, *, bundles: tuple[str, ...] | None = None, verifier: bool = True) -> CheckContext:
        records = OperatorRecords(
            source="records.yaml",
            records={"skills/a": {"source": SOURCE, "commit": COMMIT, "digest": artifact_digest(self.directory)}},
            bundles={"skills/a": (str(self.bundle),) if bundles is None else bundles},
        )
        trust_root = TrustRoot(
            file="root.yaml", sha256="0" * 64, reason=None, policy=self.policy, trust_config="tc.json"
        )
        return replace(
            context_for(self.root),
            provenance_records=records,
            trust_root=trust_root,
            sigstore_verifier=str(self.verifier) if verifier else None,
        )

    def findings(self, *, bundles: tuple[str, ...] | None = None, verifier: bool = True) -> list[tuple[Outcome, str]]:
        ctx = self.context(bundles=bundles, verifier=verifier)
        return [(f.outcome, f.message) for f in AUDITS["signature-verifies"](ctx)]


@pytest.fixture
def setup(tmp_path: Path) -> Setup:
    return Setup(tmp_path)


def test_build_provenance_passes_and_the_verifier_gets_every_policy(setup: Setup) -> None:
    setup.respond(_verified(_build_statement(setup.dir_hash)))
    assert setup.findings() == []
    assert setup.args() == [
        "--trust-config", "tc.json", "--bundle", str(setup.bundle),
        "--policy", ISSUER, SIGNER, "--policy", ISSUER, VSA_IDENTITY,
    ]  # fmt: skip


def test_source_vsa_passes(setup: Setup) -> None:
    setup.respond(_verified(_vsa_statement(setup.dir_hash), san=[VSA_IDENTITY], build_signer_uri=None))
    assert setup.findings() == []


def test_one_accepted_bundle_is_enough(setup: Setup, tmp_path: Path) -> None:
    rejected = {"exit": 3, "stdout": json.dumps({"rejected": "no"})}
    setup.respond(_verified(_build_statement(setup.dir_hash)), **{"other.json": rejected})
    assert setup.findings(bundles=(str(tmp_path / "other.json"), str(setup.bundle))) == []
    [(outcome, _)] = setup.findings(bundles=(str(tmp_path / "other.json"),))
    assert outcome == Outcome.FAIL


def _mutate(statement: dict, path: str, value: object) -> dict:
    *parents, last = path.split(".")
    node = statement
    for key in parents:
        node = node[int(key)] if isinstance(node, list) else node[key]
    if value is _DELETE:
        del node[last]
    else:
        node[last] = value
    return statement


_DELETE = object()


@pytest.mark.parametrize(
    ("path", "value", "reason"),
    [
        ("subject.0.digest.dirHash", "00" * 32, "no subject has a dirHash equal"),
        ("subject.0.digest.dirHash1", "00" * 32, "dirHash and dirHash1 disagree"),
        ("_type", "https://in-toto.io/Statement/v0.1", "statement _type"),
        ("predicateType", "https://example.com/other", "predicateType https://example.com/other"),
        ("predicate.buildDefinition.buildType", "https://example.com/bt", "is not listed for this signer"),
        ("predicate.runDetails.builder.id", "https://example.com/b", "is not listed for this signer"),
        ("predicate.buildDefinition.externalParameters.inputs", {}, "fields the workflow/v1 buildType does not define"),
        ("predicate.buildDefinition.externalParameters.workflow.path", _DELETE, "lacks required ones"),
        ("predicate.buildDefinition.externalParameters.workflow.repository", f"{SOURCE}.git", "workflow.repository"),
    ],
)
def test_build_provenance_statement_is_rejected(setup: Setup, path: str, value: object, reason: str) -> None:
    setup.respond(_verified(_mutate(_build_statement(setup.dir_hash), path, value)))
    [(outcome, message)] = setup.findings()
    assert outcome == Outcome.FAIL
    assert reason in message


@pytest.mark.parametrize(
    ("certificate", "reason"),
    [
        ({"source_repository_uri": "https://github.com/attacker/skills"}, "Source Repository URI"),
        ({"build_signer_uri": f"{SOURCE}/.github/workflows/other.yml@refs/heads/main"}, "no trust root signer"),
        ({"issuer": "https://example.com/issuer"}, "no trust root signer"),
    ],
)
def test_build_provenance_signer_is_rejected(setup: Setup, certificate: dict, reason: str) -> None:
    setup.respond(_verified(_build_statement(setup.dir_hash), **certificate))
    [(outcome, message)] = setup.findings()
    assert (outcome, reason in message) == (Outcome.FAIL, True)


@pytest.mark.parametrize(
    ("path", "value", "reason"),
    [
        ("subject.0.digest.gitCommit", "cd" * 20, "gitCommit"),
        ("subject.0.digest.gitCommit", _DELETE, "gitCommit"),
        ("predicate.resourceUri", SOURCE, "resourceUri"),
        ("predicate.verificationResult", "FAILED", "verificationResult"),
        ("predicate.verifiedLevels", ["SLSA_SOURCE_LEVEL_1"], "does not reach SLSA_SOURCE_LEVEL_2"),
        ("predicate.verifier.id", "https://example.com/other", "no trust root verifier"),
    ],
)
def test_source_vsa_is_rejected(setup: Setup, path: str, value: object, reason: str) -> None:
    statement = _mutate(_vsa_statement(setup.dir_hash), path, value)
    setup.respond(_verified(statement, san=[VSA_IDENTITY], build_signer_uri=None))
    [(outcome, message)] = setup.findings()
    assert (outcome, reason in message) == (Outcome.FAIL, True)


def test_a_predicate_whose_section_is_absent_is_never_accepted(setup: Setup) -> None:
    del setup.policy["build_provenance"]
    setup.respond(_verified(_build_statement(setup.dir_hash)))
    [(outcome, message)] = setup.findings()
    assert (outcome, "no build_provenance section" in message) == (Outcome.FAIL, True)


def test_an_empty_trust_root_accepts_nothing(setup: Setup) -> None:
    del setup.policy["build_provenance"], setup.policy["source_vsa"]
    assert setup.findings() == [(Outcome.FAIL, "no bundle verifies against the trust root: it allows no signer")]


def test_a_rejection_by_the_verifier_fails(setup: Setup) -> None:
    setup.respond({"exit": 3, "stdout": json.dumps({"rejected": "0 of 2 policies succeeded"})})
    [(outcome, message)] = setup.findings()
    assert outcome == Outcome.FAIL
    assert message.endswith("the verifier rejected the bundle: 0 of 2 policies succeeded")


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        ({"exit": 1, "stdout": "", "stderr": "Traceback"}, "verifier exited 1: Traceback"),
        ({"exit": 0, "stdout": "not json"}, "verifier output is malformed"),
        ({"exit": 0, "stdout": json.dumps({"payload_type": "x", "payload": "!!"})}, "verifier output is malformed"),
        ({"exit": 3, "stdout": "{}"}, "verifier output is malformed"),
    ],
)
def test_a_verifier_without_an_answer_is_not_evaluated(setup: Setup, response: dict, reason: str) -> None:
    setup.respond(response)
    [(outcome, message)] = setup.findings()
    assert (outcome, reason in message) == (Outcome.NOT_EVALUATED, True)


def test_an_unknown_result_outweighs_a_rejection(setup: Setup, tmp_path: Path) -> None:
    setup.respond({"exit": 3, "stdout": json.dumps({"rejected": "no"})}, **{"x.json": {"exit": 1, "stdout": ""}})
    [(outcome, _)] = setup.findings(bundles=(str(tmp_path / "x.json"), str(setup.bundle)))
    assert outcome == Outcome.NOT_EVALUATED


def test_missing_verifier_binary_is_not_evaluated(setup: Setup) -> None:
    setup.verifier.unlink()
    [(outcome, message)] = setup.findings()
    assert (outcome, "verifier could not run" in message) == (Outcome.NOT_EVALUATED, True)


def test_no_bundles_fail(setup: Setup) -> None:
    assert setup.findings(bundles=()) == [
        (Outcome.FAIL, "the operator record in records.yaml names no Sigstore bundle")
    ]


def test_no_verifier_or_trust_root_is_not_evaluated(setup: Setup) -> None:
    assert setup.findings(verifier=False) == [
        (Outcome.NOT_EVALUATED, "signature not checked: no verifier (--sigstore-verifier not given)")
    ]
    ctx = replace(setup.context(), trust_root=TrustRoot())
    assert [(f.outcome, f.message) for f in AUDITS["signature-verifies"](ctx)] == [
        (Outcome.NOT_EVALUATED, "signature not checked: no trust root (--trust-root not given)")
    ]


def test_an_in_directory_record_alone_is_not_evaluated(tmp_path: Path) -> None:
    directory = _skill(tmp_path)
    (directory / ".acb-provenance.yaml").write_text(f"source: {SOURCE}\ncommit: {COMMIT}\ndigest: x\n")
    [finding] = AUDITS["signature-verifies"](context_for(tmp_path))
    assert finding.outcome == Outcome.NOT_EVALUATED
    assert finding.path == "skills/a"


def test_no_artifacts_means_nothing_to_verify(tmp_path: Path) -> None:
    assert AUDITS["signature-verifies"](context_for(tmp_path)) == []


SIGNED = Path(__file__).parents[1] / "fixtures" / "ACB-PROV-003"
# CI installs the verifier outside the tree and names it here; locally `uv sync --project verifier` provides it.
REAL_VERIFIER = Path(
    os.environ.get("ACB_SIGSTORE_VERIFIER", Path(__file__).parents[2] / "verifier/.venv/bin/acb-sigstore-verify")
)


def _signed_context(policy_change: dict | None = None) -> CheckContext:
    if not os.access(REAL_VERIFIER, os.X_OK):
        pytest.fail(f"{REAL_VERIFIER} is not executable: run `uv sync --locked --project verifier`")
    operator = SIGNED / "signed-operator"
    trust_root = load_trust_root(operator / "trust-root.yaml")
    if policy_change:
        trust_root = replace(trust_root, policy={**trust_root.policy, **policy_change})
    return replace(
        context_for(SIGNED / "signed"),
        provenance_records=load_operator_records(operator / "provenance-records.yaml"),
        trust_root=trust_root,
        sigstore_verifier=str(REAL_VERIFIER),
    )


def test_a_real_bundle_signed_on_github_actions_passes() -> None:
    assert AUDITS["signature-verifies"](_signed_context()) == []


def test_a_real_bundle_from_an_unlisted_workflow_fails() -> None:
    signer = {
        "issuer": ISSUER,
        "build_signer_uris": [SIGNER],
        "builders": [{"id": BUILDER, "build_type": GITHUB_WORKFLOW}],
    }
    [finding] = AUDITS["signature-verifies"](_signed_context({"build_provenance": {"signers": [signer]}}))
    assert finding.outcome == Outcome.FAIL
    assert finding.path == "skills/signed-skill"
