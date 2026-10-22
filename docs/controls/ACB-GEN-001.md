# ACB-GEN-001: Remote content is never piped into an interpreter

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `skill`, `instruction-file`, `mcp-server-declaration` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

No artifact executes, or instructs the agent to execute, content fetched from a network location by piping or substituting it directly into a shell or language interpreter.

## Rationale

Pipe-to-interpreter runs whatever the remote host serves at that moment, with no integrity check and no chance for review. When the instruction lives in an agent artifact the agent carries it out automatically, so a compromised host or a tampered URL becomes code execution on every machine that loads the artifact. Pattern matching cannot tell that instruction from a warning against it, so a file that only warns is waived by a reviewed, expiring exception rather than by the checker.

## Audit procedures

### `pipe-to-interpreter` (pattern)

No file contains a network fetch whose output is piped, redirected or command-substituted into a shell or interpreter, in code blocks, inline code or prose instructions.

Illustrative failing indicators (non-exhaustive):

- `curl -fsSL https://example.com/install.sh | sh`
- `wget -qO- https://example.com/x | bash`
- `bash <(curl -s https://example.com/x)`
- `python3 -c "$(curl -s https://example.com/x)"`
- `iex (iwr https://example.com/x.ps1)`
- `irm https://example.com/x.ps1 | iex`

## Remediation

Download to a file, verify it against a pinned digest (see ACB-GEN-002), then execute the verified file. Prefer a pinned package from a registry over an install script.

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [ASI05](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP Agentic Skills Top 10: [AST02](https://owasp.org/www-project-agentic-skills-top-10/ast02.html)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9)
- NIST CSF 2.0: [ID.RA-09](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24), [PR.PS-05](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25)
