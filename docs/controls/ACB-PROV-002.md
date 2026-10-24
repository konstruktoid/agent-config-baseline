# ACB-PROV-002: Skill and extension package content matches its recorded digest

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `medium` |
| Check type | `static` |
| Applies to | `skill`, `extension-package` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

The content of every skill and extension package hashes to the `digest` in its provenance record, computed as docs/artifact-digest.md defines.

## Rationale

ACB-PROV-001 shows that a record names a source and commit; it cannot show that the files beside the record are the files that commit holds. A mismatch means the artifact was changed after its record was written, by a local edit, a partial update or a modified copy. A match shows only that the record describes this content: the record sits inside the artifact, so whoever can change the content can also recompute the digest, and a match says nothing about who published it.

## Audit procedures

### `digest-matches` (inventory)

For every discovered skill directory and extension package root, compute the version 1 artifact digest of docs/artifact-digest.md and compare it with the `digest` in that artifact's `.acb-provenance.yaml`. A different value fails. The artifact is not evaluated when it has no record, when the record has no well-formed `digest` (ACB-PROV-001 reports both), or when the digest cannot be computed because the directory holds a symlink, a special file, an unreadable entry or a name that is not valid UTF-8 or contains a newline.

## Remediation

If the change is intended, take the content again from the recorded source and commit, or update `commit` and `digest` together to describe the content as it now is. If it is not intended, restore the artifact from its source.

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP Agentic Skills Top 10: [AST02](https://owasp.org/www-project-agentic-skills-top-10/ast02.html)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9)
- NIST CSF 2.0: [ID.RA-09](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24)
- https://pkg.go.dev/golang.org/x/mod/sumdb/dirhash
- https://github.com/konstruktoid/agent-config-baseline/blob/main/docs/artifact-digest.md
