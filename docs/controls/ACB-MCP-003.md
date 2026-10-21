# ACB-MCP-003: MCP server environment does not set process-startup hijack variables

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `mcp-server-declaration` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

A local MCP server declaration does not set, in its environment block, a variable that makes the launched process load code the declaration does not name: LD_PRELOAD, BASH_ENV, or NODE_OPTIONS carrying a code-loading option (--require, -r, --import, --loader, --experimental-loader).

## Rationale

The environment block is passed to the spawned server process as written. A repository that ships an MCP declaration can use it to make the server load attacker-chosen code at start-up, before the server's own code runs and without that code appearing in command or args. OpenClaw fixed this by filtering such variables from workspace MCP stdio configuration (advisory GHSA-mj59-h3q9-ghfh, which lists no known CVE and names NODE_OPTIONS, LD_PRELOAD and BASH_ENV). VulnCheck assigned the issue CVE-2026-44995 and CWE-829.

## Audit procedures

### `no-hijack-env` (structure)

For each server entry with an env (or environment) mapping, or a list of name and value pairs, no entry sets LD_PRELOAD or BASH_ENV to a non-empty value, and NODE_OPTIONS does not contain a --require, -r, --import, --loader or --experimental-loader option. The same holds for NAME=value arguments of a wrapper command such as env. Names are compared case-insensitively.

Illustrative failing indicators (non-exhaustive):

- `"env": {"LD_PRELOAD": "/tmp/hook.so"}`
- `"NODE_OPTIONS": "--require ./hook.js"`
- `"args": ["LD_PRELOAD=/tmp/hook.so", "node", "server.js"]`

## Remediation

Remove the variable from the declaration. If the server needs code preloaded, make that part of the server's own package, where it is reviewed and pinned (see ACB-GEN-002), and keep NODE_OPTIONS to non-loading options such as --max-old-space-size.

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI05](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP MCP Top 10: [MCP05](https://github.com/OWASP/www-project-mcp-top-10/blob/165fe0f78ef104459237b4a8e0f6e78db9b02391/2025/MCP05-2025%E2%80%93Command-Injection%26Execution.md)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9)
- NIST CSF 2.0: [PR.PS-01](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25), [PR.PS-05](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25)
- https://github.com/openclaw/openclaw/security/advisories/GHSA-mj59-h3q9-ghfh
- https://www.vulncheck.com/advisories/openclaw-arbitrary-code-execution-via-mcp-stdio-environment-variables
