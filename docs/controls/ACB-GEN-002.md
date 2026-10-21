# ACB-GEN-002: External code and dependencies are pinned immutably

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `skill`, `instruction-file`, `mcp-server-declaration` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

Every package, tool, container image or remote file that an artifact installs, runs or instructs the agent to install or run is pinned to an immutable reference: an exact version with an integrity digest, a content digest, or a full commit hash.

## Rationale

Agent artifacts are executed long after review. A floating reference (latest, a branch, a version range, an unversioned package name) means the code that runs is not the code that was reviewed. MCP server declarations that launch unpinned packages through a package runner are a common case: every client start may fetch a different release.

## Audit procedures

### `package-runners-pinned` (pattern)

Invocations of package runners and installers specify an exact version. Version ranges, dist-tags and bare package names fail.

Illustrative failing indicators (non-exhaustive):

- `npx -y @example/mcp-server`
- `npx @example/tool@latest`
- `uvx example-tool`
- `pip install example`
- `go install example.com/tool@latest`

### `lockfile-or-hash` (pattern)

Where an exact version is given, an integrity mechanism is also present: a lockfile with hashes bundled in the artifact, a --require-hashes style flag, or an explicit digest check.

### `images-by-digest` (pattern)

Container image references include an @sha256: digest.

Illustrative failing indicators (non-exhaustive):

- `docker run example/server:latest`
- `docker run example/server:1.2`

### `downloads-verified` (pattern)

Every fetched URL (curl, wget, Invoke-WebRequest, language HTTP clients in scripts) is followed by a digest verification against a value in the artifact, or the URL itself contains a full 40 or 64 character commit hash.

Illustrative failing indicators (non-exhaustive):

- `curl -o tool https://example.com/releases/latest/tool`
- `https://raw.githubusercontent.com/example/repo/main/script.sh`

## Remediation

Pin every reference to an exact version and add an integrity check: bundle a hashed lockfile, pin images by digest, reference repository content by commit hash, and verify downloaded files with a pinned SHA-256 before use.

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP Agentic Skills Top 10: [AST02](https://owasp.org/www-project-agentic-skills-top-10/ast02.html)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9)
- NIST CSF 2.0: [ID.RA-09](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24), [PR.PS-01](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25)
- https://slsa.dev/
