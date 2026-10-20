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

No file reference in SKILL.md or bundled files is absolute, contains `..` segments, or resolves (after symlink resolution) outside the skill directory. The skill directory contains no symlinks.

## Remediation

Replace binaries and archives with source. Decode embedded payloads into reviewable files. Reference every script from SKILL.md or delete it. Copy needed files into the skill rather than referencing outside paths.

## References

- OWASP Top 10 for Agentic Applications 2026: ASI04, ASI05
- OWASP Agentic Skills Top 10: AST02
- Careful Adoption of Agentic AI Services risk areas: design-and-configuration, accountability
- NIST CSF 2.0: ID.RA-09, PR.PS-05
- Specification: https://agentskills.io/specification
