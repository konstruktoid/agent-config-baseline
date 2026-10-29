# Design note: provenance controls

Status: draft. `ACB-PROV-001`, `ACB-PROV-002` and the signature control
`ACB-PROV-003` exist as draft controls, and section 6 records the decisions
behind them. The SLSA, in-toto attestation and Sigstore bundle
specifications were checked on 2026-10-26 and 2026-10-28 (section 6,
question 5).

## 1. Problem

All 22 active controls are `check_type: static`. They judge the content of a
file. None of them can say whether a skill, extension package or MCP server
package is the artifact its publisher released, built from the source the
publisher claims. `ACB-GEN-002` already requires exact pins with an integrity
check, digest verification of fetched content, or a full commit hash, and
`ACB-EXT-*` covers package contents. None of them binds the audited artifact
itself to a claimed source or publisher. The schema
already reserves `check_type: provenance` ("needs release/attestation
metadata") and no control uses it.

## 2. Constraints from the build prompt

- No model calls, and every audit must be pattern matching, parsing or
  inventory (ground rule 5). Cryptographic verification is none of these, so
  it needs an explicit decision, not a quiet exception.
- Vendor neutrality (ground rule 1): evidence formats must be open
  (OCI digests, git commit hashes, in-toto statements, Sigstore bundles), and
  client data may add locations but may not define what counts as evidence.
- Dependencies are the standard library, `PyYAML` and `jsonschema`, pinned
  with hashes. Signature verification would add a dependency, or a subprocess
  to an external verifier.
- One profile, every active control must pass. A control that is
  `not-applicable` when evidence is missing is a bypass: delete the evidence,
  pass the control.

## 3. Proposed split

Separate what the checker can decide from what it cannot.

| Part | Decidable offline with the current dependencies | Proposed `check_type` |
| --- | --- | --- |
| A provenance record exists for each artifact and names source repository, full commit hash and content digest | yes, parsing | `static` |
| The recorded digest equals a digest the checker computes over the artifact | yes, if the hash algorithm is specified (section 4) | `static` |
| The record is signed by an allowed identity and the signature verifies | needs a crypto library and a trust root | `provenance` |
| The signed subject digest equals the recorded digest | yes once the statement is parsed, but meaningless without the line above | `provenance` |
| The signing identity corresponds to the claimed source repository | needs the attestation's certificate claims | `provenance` |

Recommendation: ship the two `static` rows first as draft controls. They close
the gap between "a digest is present" and "the digest matches what is on disk",
cost no dependency, and make the later signature step a strict addition.

## 4. The artifact digest

A skill is a directory, so "its digest" needs a canonical definition: sorted
relative paths, normalised separators, a per-file digest, a digest over that
listing, and a rule for file modes, symlinks (SKILL-003 already forbids
them) and the provenance record itself, which sits in the artifact
directory (section 6, question 1) and so must be excluded from the digest
it records. Without this the digest is not reproducible across tools. The
Agent Skills specification does not define one (checked 2026-10-24, see
section 6, question 5), so this baseline would be defining it, which should be a
separate, versioned document rather than text inside a control.

Decided: [artifact-digest.md](artifact-digest.md) version 1 adopts Go's
`dirhash` `h1:` format rather than defining a new one, so an existing
implementation and a coreutils pipeline both reproduce it. The digest
leaves out only its own record and a `.git` entry, with its contents,
directly in the artifact directory; symlinks, special files and unencodable
names make the digest not computable, and file modes are not covered.

## 5. Proposed draft controls

IDs are placeholders. The existing prefixes are `CFG`, `EXT`, `GEN`, `INSTR`,
`MCP` and `SKILL`; `PROV` would be new. Both start as `status: draft`.

- `ACB-PROV-001` — every inventoried skill and extension package has a
  provenance record with source repository, full commit hash and content
  digest. Missing record fails; it is not `not-applicable`. MCP server
  packages are deferred, see section 7.
- `ACB-PROV-002` — each record's digest equals the digest computed from the
  artifact under the section 4 definition. An artifact without a
  well-formed recorded digest is not evaluated rather than failed, because
  `ACB-PROV-001` already fails it.
- `ACB-PROV-003` — an artifact with an operator record passes when one of
  the Sigstore bundles that record lists verifies and its statement matches
  the operator trust root and the artifact (section 6, questions 2, 3 and
  5). It is `check_type: provenance`: the signature result comes from an
  external verifier, and the checker relays it.

The audit of `konstruktoid/agent-instructions-skills` at `db098c2` would fail
`ACB-PROV-001` for all 10 skills if the record lives in the repository (a file
in the skill or a repository-level lock file): by file name, that commit
contains no such record. If the record is an operator file (section 6,
question 1), the result depends on what the operator supplies. A failure here
is a finding about missing evidence rather than evidence of tampering; the
report text would need to say so.

## 6. Questions that need an answer before implementation

1. Where does a record live: a file in the skill directory (excluded from its
   own hash), a repository-level lock file, or an operator file passed on the
   command line like `--exceptions`? Decided: a `.acb-provenance.yaml` in
   each skill directory and extension package root, because it is the only
   option that travels with a copied or vendored artifact; a
   repository-level file is lost when one skill is copied out. The cost is
   that whoever can change the artifact can change its record, so
   `ACB-PROV-001` shows only that evidence exists. An operator file remains
   the only option an attacker who controls the skill cannot rewrite, and
   could be added later as an override rather than a replacement. Decided:
   that operator file is added together with the trust root (question 3),
   and keys each record by the artifact's path relative to the audited
   root, as findings report it. A record there replaces the in-directory
   record as a whole, with no merging of fields. Every `PROV-*` control reads
   that one resolved record, so an operator record also satisfies
   `ACB-PROV-001`; the controls change when the operator file ships.
   Implemented as `--provenance-records FILE`
   (`schema/provenance-records.schema.json`), with no working-directory
   default because the reusable workflow runs with the pull request head as
   its working directory. An invalid file stops the run, and keys that name
   no inventoried artifact are reported. Decided 2026-10-28: an operator
   record may list `bundles`, Sigstore bundle paths relative to the records
   file and inside its directory. Only an operator record can name bundles,
   which keeps `.acb-provenance.yaml` the only file the artifact digest
   leaves out.
2. Is the checker allowed a verifier dependency or an external verifier
   subprocess? Decided: no new dependency. A signature control runs an
   external verifier as a subprocess, its result is a claim the checker
   relays, and the report labels it as that tool's result. The checker's own
   dependencies stay the standard library, `PyYAML` and `jsonschema`. The
   operator names the verifier by absolute path, never by a `PATH` lookup,
   and the checker runs it without a shell and with a timeout. Only a zero
   exit with well-formed output that names the expected subject digest and
   a signer identity matching the record's `source` repository passes; a
   different signer or a verifier that reports a failed verification fails
   the control, and a missing verifier, a timeout, a crash or malformed
   output leave it not evaluated, so no path through the verifier passes by
   default. The expected `source` comes only from an operator record
   (question 1), because whoever can change an artifact can also change its
   in-directory record and sign from a repository they chose; an artifact
   with only an in-directory record leaves the signature control not
   evaluated. A source VSA is signed by its verifier rather than the source
   repository, so for that predicate the binding to `source` moves to the
   VSA's `resourceUri` (question 5). Implemented as `--sigstore-verifier
   PATH`, which must be absolute and executable, with no default. The
   verifier ships in this repository as `verifier/acb_sigstore_verify.py`,
   with its own `pyproject.toml` and hash-locked `uv.lock` pinning
   sigstore-python, so it runs from an environment separate from acb's. Exit
   0 prints the verified payload and certificate values as JSON. Exit 3
   reports a rejected bundle, which fails the artifact unless another bundle
   is accepted. Any other exit, a timeout or malformed output leaves the
   artifact not evaluated.
3. How is the trust root pinned, and who owns updating it? Decided: the
   operator supplies it as a file on the command line, as with
   `--exceptions`, and the checker never bundles one, so the person running
   the audit owns updating it. The checker does not pin its content, since
   any pin would sit where the same operator controls it; instead each report
   records the trust root file's SHA-256, so the evidence names the root that
   was used, and rotating it means replacing the file, which changes that
   digest in the next report. Without a trust root the report records the
   trust root as absent, `null` with the reason, rather than a digest, and
   the signature control is not evaluated, never passed. Implemented as
   `--trust-root FILE`, with no default: reports record its SHA-256, or
   `null` with the reason. Its format is decided in question 5
   (`schema/trust-root.schema.json`). The checker parses it against that
   schema and refuses to run when the file is invalid or the trust config
   differs from its pinned SHA-256.
4. Should `PROV-*` apply to the repository under audit only, or also to
   third-party skills it vendors? Decided: to every skill and extension
   package the inventory finds, vendored or not, which is what both draft
   controls already do; MCP server packages stay deferred (section 7). A
   copied third-party skill is the supply-chain case these controls exist
   for.
5. Verify before implementing, with the command that would check each:
   Sigstore bundle field names and offline verification support (read the
   current sigstore bundle specification); in-toto statement and SLSA
   provenance predicate versions (read the current in-toto and SLSA
   specifications). The Agent Skills specification at agentskills.io was
   checked on 2026-10-24: it permits "any files and directories beyond the
   required `SKILL.md`" and defines no digest, hash or provenance field; its
   only extension point is the string-to-string `metadata` frontmatter map,
   which would place the record inside the content it hashes.

   SLSA, checked on 2026-10-26 against v1.2, the current version:
   - Build provenance keeps `predicateType` `https://slsa.dev/provenance/v1`
     across minor versions, inside an in-toto statement with `_type`
     `https://in-toto.io/Statement/v1`. Required fields are
     `buildDefinition.buildType`, `buildDefinition.externalParameters` and
     `runDetails.builder.id`.
   - The verification steps are: verify the envelope signature against the
     roots of trust, check that a statement `subject` digest matches the
     artifact, check `predicateType`, look up `builder.id` in the trusted
     builder map to get the build level, then compare `buildType` and
     `externalParameters` with expected values, rejecting unrecognized
     `externalParameters` fields.
   - Build provenance assumes a build platform. A skill copied from a
     repository has none, so most skills cannot produce it. The v1.2 Source
     track fits better: it attests a source revision through a verification
     summary attestation (`predicateType`
     `https://slsa.dev/verification_summary/v1`, level in `verifiedLevels`)
     whose subject digest must include the revision (`gitCommit`) and may
     include `dirHash`. SLSA leaves the source provenance format undefined.
   - The in-toto digest set defines `dirHash` as Go's `h1:` hash written as
     lowercase hex without the prefix, so the
     [artifact digest](artifact-digest.md) can be a subject digest after a
     base64-to-hex conversion. The two values agree only when the artifact
     root holds neither `.acb-provenance.yaml` nor `.git`; entries with those
     names below the root count in both. The spec's own example
     uses the key `dirHash1`, contradicting its heading; a verifier has to
     decide whether to accept both.

   Sigstore, checked on 2026-10-26 against `sigstore/protobuf-specs` `main`
   (latest tag `v0.5.2`) and the sigstore-python README:
   - The bundle media type is `application/vnd.dev.sigstore.bundle.v0.3+json`;
     verifiers must also accept the older
     `application/vnd.dev.sigstore.bundle+json;version=0.1` to `0.3` forms.
     `verificationMaterial` is required, and the content is either
     `messageSignature` or `dsseEnvelope`. An attestation is a DSSE envelope
     carrying an in-toto statement, and a verifier must reject an envelope
     that does not have exactly one signature.
   - `verificationMaterial` carries a public key hint, a certificate chain or,
     for keyless v0.3 bundles on the public instance, a single leaf
     certificate. It also holds `tlogEntries` with an inclusion proof and a
     signed checkpoint, plus optional RFC 3161 timestamps.
   - Offline verification works when the bundle carries the inclusion proof
     and the verifier supplies the trusted root
     (`application/vnd.dev.sigstore.trustedroot.v0.2+json`: transparency logs,
     certificate authorities, CT logs, timestamp authorities). sigstore-python
     offers `verify identity --bundle FILE --offline --cert-identity ID
     --cert-oidc-issuer URL FILE_OR_DIGEST` and a global `--trust-config FILE`,
     which takes a `ClientTrustConfig` wrapping a trusted root rather than a bare one.
     cosign's offline and trusted-root flags are unverified; check with
     `cosign verify-blob-attestation --help`.
   - The signer identity (certificate identity and OIDC issuer) is policy the
     verifier supplies. The bundle does not decide it.
   - sigstore-python takes the artifact as a file path or a `sha256:` digest.
     A skill is a directory with a `dirHash` subject, so the checker
     cannot hand it to the verifier as the artifact. A likely split: the
     external verifier checks signature, log inclusion and identity, and the
     checker parses the verified statement and compares `dirHash` itself.
     Checked on 2026-10-28 with sigstore-python 4.5.1 by signing a statement
     whose only subject digest is `dirHash` against production Sigstore:
     `Verifier.verify_dsse()` with `offline=True` and an identity policy
     accepts the bundle and returns the raw payload, because it checks the
     certificate, log entry, identity and DSSE signature but never parses
     the statement. `sigstore verify identity --offline` rejects the same
     bundle after those checks pass, with "malformed in-toto statement",
     because the library's `DigestSet` accepts only `sha256`, `sha384`,
     `sha512` and `sha3_*` keys. The same model makes `StatementBuilder`
     unable to build such a statement. The split above therefore holds
     with the library API rather than the CLI: the checker calls
     `verify_dsse()` and parses the returned payload with its own in-toto
     code, without `sigstore.dsse.Statement`.
   - The operator trust root from question 3 then has three parts: a
     Sigstore client trust configuration, the allowed signer identities, and
     the allowed `builder.id` or source control identities. SLSA requires
     consumers to accept only specific signer and builder pairs.

   in-toto attestation framework, checked on 2026-10-26 against
   `in-toto/attestation` `main` (spec v1.2, latest tag `v1.2.0`):
   - A statement has `_type` `https://in-toto.io/Statement/v1`, a required
     `subject` array whose elements must each set `digest`, a required
     `predicateType` and an optional `predicate`. Subjects are matched purely
     by digest; `name` semantics are left to producer and consumer. So the
     checker should match on `dirHash` alone and not trust `name` or `uri`
     to identify the skill.
   - Consumers must ignore unrecognized statement fields unless a predicate
     says otherwise. SLSA does say otherwise for `externalParameters`.
   - Policies should be monotonic: ignoring an attestation must never turn a
     deny into an allow. "Fail unless a verified attestation matches" meets
     this and is the same rule as the one-profile constraint in section 2.
   - With DSSE, `payload` is the base64-encoded statement and `payloadType` is
     `application/vnd.in-toto+json` or a predicate-specific
     `application/vnd.in-toto.<predicate>+json`. Consumers must take the
     predicate type from the statement's `predicateType`, not from the media
     type, and must parse only a payload whose signature has been verified.
   - The in-toto envelope spec notes that the Sigstore bundle is not ITE-5
     compliant because it allows only one signature. This does not block
     anything here; one signer per bundle fits the signer-to-source binding
     from question 2.

   Decided: a signature control accepts both SLSA build provenance and a
   source verification summary attestation. Either one, once verified and
   matched, passes the artifact. Ignoring one never turns a fail into a pass,
   so the policy stays monotonic. Most skills have no build platform, so build
   provenance alone would fail them, and a VSA alone would refuse skills that
   ship build provenance.

   Decided: a subject digest matches under the key `dirHash` or `dirHash1`.
   When a subject carries both keys, both values must equal the computed
   digest, and any mismatch rejects the statement rather than choosing a
   key. Output and documentation from this baseline use `dirHash`.

   Decided: a VSA subject must carry `gitCommit`, as the Source track
   requires, and its value must equal the operator record's `commit`; a
   missing or different value rejects the VSA. A vendored skill usually has
   no `.git`, so the checker cannot recompute the revision, but the record
   names it, so the comparison needs no repository.

   Decided: the trust root lists the identities for each predicate in this
   format (`schema/trust-root.schema.json`):

   ```yaml
   version: 1
   sigstore:
     trust_config: sigstore-trust-config.json
     sha256: "<hex SHA-256 of that file>"
   build_provenance:
     signers:
       - issuer: https://token.actions.githubusercontent.com
         build_signer_uris:
           - "{source}/.github/workflows/release.yml@refs/heads/main"
         builders:
           - id: https://github.com/actions/runner/github-hosted
             build_type: https://actions.github.io/buildtypes/workflow/v1
   source_vsa:
     verifiers:
       - id: https://example.com/source-verifier
         issuer: https://token.actions.githubusercontent.com
         identity: https://example.com/verifier/.github/workflows/vsa.yml@refs/heads/main
         min_source_level: 2
   ```

   - `sigstore.trust_config` is a `ClientTrustConfig` path relative to the
     trust root file and inside its directory, pinned by `sha256`. The
     checker refuses to run the verifier when the digest differs, so the one
     SHA-256 in the report
     covers the Sigstore roots too, and rotating them changes that digest.
   - Every identity is an exact string. No patterns or prefixes, because a
     pattern that matches too much shows no error and still widens trust.
     The one substitution is `{source}`, which is filled in from the
     operator record and nothing else.
   - Build provenance: the signing certificate's OIDC issuer must equal
     `issuer`. Its Source Repository URI extension
     (`1.3.6.1.4.1.57264.1.12`, `OIDCSourceRepositoryURI` in
     sigstore-python 4.5.1) must equal the record's `source`; this is the
     signer-to-source binding from question 2. Its Build Signer URI
     extension (`…1.9`) must equal one of that signer's required
     `build_signer_uris`, which binds the signer to one workflow path and
     ref rather than to any workflow in the repository. The statement's
     `builder.id` and `buildType` must match a pair listed under that same
     signer, since SLSA requires accepting only specific signer and builder
     pairs. The checker accepts only `buildType` values whose
     `externalParameters` it knows how to check, and rejects any other
     value, since SLSA requires rejecting unrecognised `externalParameters`.
     For the GitHub Actions workflow type, `externalParameters.workflow.repository`
     must equal `source`. Checked on 2026-10-28 against
     https://github.com/actions/buildtypes/blob/main/workflow/v1/: the field
     is the repository's `https://` URL without a `.git` suffix, the same
     form as the certificate's Source Repository URI. So `source` is written
     in that form, for example `https://github.com/foo/hello-world`.
   - Source VSA, checked on 2026-10-28 against SLSA v1.2: the verifier signs
     the VSA, not the skill repository, and SLSA requires `verifier.id` to
     match the signing identity. So the signer-to-source binding from
     question 2 cannot hold for a VSA. Each entry instead pins the signer
     (`issuer`, `identity`) to one `verifier.id`, and the source binding
     moves to `resourceUri`, which must equal `git+` followed by the
     record's `source`. SLSA asks for `resourceUri` in SPDX Download Location
     form, such as `git+https://github.com/foo/hello-world`, and the
     reference producer (slsa-framework/source-tool `pkg/attest/vsa.go`)
     writes exactly that. The comparison is exact, with no optional prefix,
     in keeping with exact identity strings. This was checked against the
     spec and that tool's source, not against a VSA found in the wild. The
     checker also requires `verificationResult` `PASSED` and a
     `verifiedLevels` entry `SLSA_SOURCE_LEVEL_<n>` with `n` at least
     `min_source_level`. `min_source_level` is capped at 4: the source track
     defines levels 1 to 4, and although the VSA requirements list only
     levels 0 to 3 as values, the VSA format itself shows
     `SLSA_SOURCE_LEVEL_4`.
   - Either section may be absent. A predicate whose section is absent is
     never accepted, which keeps the policy monotonic. An empty trust root
     accepts nothing.
   - Question 2 requires an external verifier with no new dependency, and
     the decision below requires `verify_dsse()`, which is a library call.
     Both hold if the external verifier is a small program, run from its
     own environment with sigstore-python installed, that takes the bundle,
     the `ClientTrustConfig` and an exact issuer and identity policy. It
     prints the verified payload and the certificate's extension values as
     JSON, and the checker does all in-toto and predicate checks itself.

   Decided: the checker verifies bundles with sigstore-python's
   `Verifier.verify_dsse()` and parses the statement itself, since the CLI
   and `sigstore.dsse.Statement` reject a `dirHash`-only subject (section 6,
   Sigstore).

## 7. Out of scope and deferred

MCP server packages. Section 1 names them as artifacts the problem covers, but
an MCP declaration names a launch command or a remote URL, not a directory, so
there is no artifact path for a record to key on. `ACB-PROV-001` is limited to
skills and extension packages until the record format can identify a package
by registry coordinates or image digest.

Reputation, vulnerability status of dependencies, and runtime attestation
of the agent itself (README: agent identity is out of scope).
