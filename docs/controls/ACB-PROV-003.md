# ACB-PROV-003: A signed attestation binds each skill and extension package to its recorded source

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `medium` |
| Check type | `provenance` |
| Applies to | `skill`, `extension-package` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

Every skill and extension package has a Sigstore-signed in-toto statement, SLSA build provenance or a source verification summary attestation, whose subject digest equals the artifact's content digest and whose signer the operator's trust root allows for the source in the operator's provenance record.

## Rationale

ACB-PROV-002 shows that content matches its record, but whoever can change the content can rewrite the record. A signature from an identity the operator trusts, checked against a source the operator recorded outside PATH, shows who published the content and from which repository. The signature check is the result of an external verifier, which the report relays rather than performs.

## Audit procedures

### `signature-verifies` (structure)

For every discovered skill directory and extension package root with an entry in `--provenance-records`, run the `--sigstore-verifier` program on each bundle the entry lists, with the Sigstore client trust config from `--trust-root` and every signer identity the trust root allows. Parse the statement it returns and accept it when a subject's `dirHash` (or `dirHash1`) equals the artifact digest of docs/artifact-digest.md, and either it is SLSA build provenance whose certificate issuer, Build Signer URI and Source Repository URI, `builder.id`, `buildType` and `externalParameters.workflow.repository` match a trust root signer and the record's `source`, or it is a source VSA whose signer and `verifier.id` match a trust root verifier, whose `resourceUri` is `git+` followed by the record's `source`, whose `verificationResult` is `PASSED`, whose level reaches the verifier's `min_source_level`, and whose matching subject has `gitCommit` equal to the record's `commit`. One accepted bundle passes the artifact. An entry with no bundles, or bundles that are all rejected, fails. The artifact is not evaluated when it has no operator record, when the trust root or verifier is not given, when its digest cannot be computed, or when the verifier is missing, times out, crashes or prints malformed output.

## Remediation

Add the artifact's Sigstore bundle to its operator record under `bundles`. If the bundle is rejected, check that it was signed from the recorded `source` by an identity the trust root lists, and that its subject digest is the artifact digest of the content as it is now.

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP Agentic Skills Top 10: [AST02](https://owasp.org/www-project-agentic-skills-top-10/ast02.html)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9)
- NIST CSF 2.0: [ID.RA-09](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24)
- https://slsa.dev/spec/v1.2/
- https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
- https://github.com/sigstore/protobuf-specs
- https://github.com/konstruktoid/agent-config-baseline/blob/main/docs/provenance-design.md
