# ACB-PROV-001: Skills and extension packages carry a provenance record

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `medium` |
| Check type | `static` |
| Applies to | `skill`, `extension-package` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

Every skill and extension package carries a provenance record in its own directory naming its source repository, the full commit hash it was taken from and a content digest.

## Rationale

Pins and digests elsewhere in this baseline say that something is fixed, not where it came from. Without a record of source and commit, a reviewer cannot tell whether a skill is the artifact its publisher released or a modified copy. The record is evidence the repository ships about itself, so this control establishes that the evidence exists and is well formed; it does not show that the digest matches the content or that anyone signed it. The record sits inside the artifact so that it travels with a copied or vendored skill, which also means whoever can change the artifact can change its record.

## Audit procedures

### `record-present` (inventory)

Every discovered skill directory and extension package root contains a regular file named `.acb-provenance.yaml`. A missing file fails for that artifact; a record elsewhere, such as at the repository root, does not cover it. A symlinked record is not evaluated. An artifact that the operator's `--provenance-records` file names by its path relative to PATH is covered by that record instead, which replaces the in-directory record as a whole.

### `record-fields` (structure)

Each artifact's `.acb-provenance.yaml` parses as a YAML mapping with a `source` that is an `https://` URL with a hostname, a valid port if any and a repository path, a `commit` that is a full 40 or 64 character lowercase hexadecimal hash, and a `digest` that is `h1:` followed by the padded standard base64 encoding of a SHA-256, the format docs/artifact-digest.md defines. Whether the digest matches the content is ACB-PROV-002. An operator record is validated against the same rules when its file is loaded, and an invalid one stops the run.

Illustrative failing indicators (non-exhaustive):

- `commit: main`
- `commit: 1a2b3c4`
- `digest: md5:0123456789abcdef0123456789abcdef`
- `source: git@github.com:example/skills.git`

## Remediation

Add `.acb-provenance.yaml` to each skill directory, next to `SKILL.md`, and to each extension package root, with `source`, `commit` and `digest`. Record the commit the content was taken from, not a branch or tag name, and compute the digest as docs/artifact-digest.md describes.

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP Agentic Skills Top 10: [AST02](https://owasp.org/www-project-agentic-skills-top-10/ast02.html)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9)
- NIST CSF 2.0: [ID.RA-09](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24)
- https://slsa.dev/
- https://github.com/konstruktoid/agent-config-baseline/blob/main/docs/provenance-design.md
- https://github.com/konstruktoid/agent-config-baseline/blob/main/docs/artifact-digest.md
