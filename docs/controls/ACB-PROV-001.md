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

Every skill and extension package has an entry in the repository's provenance record naming its source repository, the full commit hash it was taken from and a SHA-256 content digest.

## Rationale

Pins and digests elsewhere in this baseline say that something is fixed, not where it came from. Without a record of source and commit, a reviewer cannot tell whether a skill is the artifact its publisher released or a modified copy. The record is evidence the repository ships about itself, so this control establishes that the evidence exists and is well formed; it does not show that the digest matches the content or that anyone signed it.

## Audit procedures

### `record-present` (inventory)

The scanned root contains `.acb-provenance.yaml`, and its `artifacts` list has an entry whose `path` names the directory of every discovered skill and extension package, relative to the scanned root with `/` separators. A missing file fails once for every skill and extension package; a missing entry fails for that artifact.

### `record-fields` (structure)

`.acb-provenance.yaml` parses as a YAML mapping with an `artifacts` list. Each entry has a `path` that is unique in the list, a `source` that is an `https://` URL, a `commit` that is a full 40 or 64 character lowercase hexadecimal hash, and a `digest` of the form `sha256:` followed by 64 lowercase hexadecimal characters.

Illustrative failing indicators (non-exhaustive):

- `commit: main`
- `commit: 1a2b3c4`
- `digest: md5:0123456789abcdef0123456789abcdef`
- `source: git@github.com:example/skills.git`

## Remediation

Add `.acb-provenance.yaml` at the repository root with one `artifacts` entry per skill or extension package: `path`, `source`, `commit` and `digest`. Record the commit the content was taken from, not a branch or tag name.

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP Agentic Skills Top 10: [AST02](https://owasp.org/www-project-agentic-skills-top-10/ast02.html)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9)
- NIST CSF 2.0: [ID.RA-09](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24)
- https://slsa.dev/
- https://github.com/konstruktoid/agent-config-baseline/blob/main/docs/provenance-design.md
