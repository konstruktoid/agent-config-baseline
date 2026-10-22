# ACB-SKILL-003: Bundled skill content is transparent, referenced and contained

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `skill` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

Every file bundled in a skill is human-reviewable text, every executable file is referenced from SKILL.md or a file SKILL.md references, and no reference resolves outside the skill directory.

## Rationale

Reviewers read SKILL.md; agents may execute anything in the directory. Unreferenced scripts, compiled binaries, archives and encoded blobs are content a reviewer is unlikely to inspect but an agent can still reach. Path references that escape the skill directory let a skill pull in files its reviewer never saw.

## Audit procedures

### `text-only` (inventory)

Every file under the skill directory is valid UTF-8 text, except files under `assets/` whose detected media type is an image format. No executable binaries, archives, compiled bytecode or packed formats are present anywhere.

Illustrative failing indicators (non-exhaustive):

- `scripts/helper (ELF executable)`
- `scripts/tool.pyc`
- `assets/bundle.tar.gz`

### `no-encoded-payloads` (pattern)

No text file contains a base64, hex or similar encoded run longer than 256 characters, and no script is minified (any line over 500 characters in a script file fails).

### `executables-referenced` (inventory)

Every file under `scripts/`, and every file anywhere with an executable bit or a shebang, is referenced by relative path from SKILL.md or from a file directly referenced by SKILL.md.

### `references-contained` (pattern)

A file reference is a Markdown link or reference-definition target, a file URI, a home-directory path, or a relative path. No file reference in SKILL.md or bundled files is absolute, names a home directory or another host, contains a `..` segment, or resolves (after symlink resolution) outside the skill directory. An absolute path outside a link, such as /dev/null in an example, describes the host rather than skill content and is not a file reference. The skill directory contains no symlinks.

## Remediation

Replace binaries and archives with source. Decode embedded payloads into reviewable files. Reference every script from SKILL.md or delete it. Copy needed files into the skill rather than referencing outside paths.

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [ASI05](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP Agentic Skills Top 10: [AST02](https://owasp.org/www-project-agentic-skills-top-10/ast02.html)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9), [accountability](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=12)
- NIST CSF 2.0: [ID.RA-09](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24), [PR.PS-05](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25)
- Specification: https://agentskills.io/specification
