# ACB-MCP-004: The mcp-remote proxy is not pinned to a known-vulnerable version

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `mcp-server-declaration` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

No MCP server declaration launches a version of the mcp-remote proxy that is affected by CVE-2025-6514 (0.0.5 through 0.1.15). Proxy detection is best-effort, so a pass does not show that no affected version can run.

## Rationale

A pinned version is not a safe version. An affected mcp-remote passes a server-supplied authorization endpoint to the operating system, so a malicious or hijacked server can run commands or programs on the client (CVSS 9.6, fixed in 0.1.16).

## Audit procedures

### `mcp-remote-not-vulnerable` (structure)

For each server entry whose command or args name mcp-remote with an exact version, including npm's loose forms such as =0.1.15 or v0.1.15, the version is not between 0.0.5 and 0.1.15 inclusive. Unpinned and ranged specifiers are left to ACB-GEN-002. Image digests and lockfile-resolved versions are not examined.

Illustrative failing indicators (non-exhaustive):

- `"mcp-remote@0.1.15"`

## Remediation

Pin mcp-remote to 0.1.16 or a later reviewed release, and connect only to trusted servers over https.

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI05](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP MCP Top 10: [MCP05](https://github.com/OWASP/www-project-mcp-top-10/blob/165fe0f78ef104459237b4a8e0f6e78db9b02391/2025/MCP05-2025%E2%80%93Command-Injection%26Execution.md)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9)
- NIST CSF 2.0: [PR.PS-01](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25)
- https://nvd.nist.gov/vuln/detail/CVE-2025-6514
- https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/
