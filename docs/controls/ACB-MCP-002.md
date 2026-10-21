# ACB-MCP-002: MCP server launch commands are not interpreted by a shell

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `mcp-server-declaration` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

A local MCP server is launched by naming an executable in command and passing its arguments as a list. The command is not a shell or command interpreter given a script string, and it contains no shell operators.

## Rationale

A shell invocation turns every argument into code. Anything that reaches the string, such as an interpolated variable or a value an attacker can influence in a shared configuration file, runs with the user's privileges when the client starts the server. Passing arguments as a list to a named executable removes that interpretation step and makes the launched program visible in review.

## Audit procedures

### `no-shell-interpretation` (structure)

For each server entry with a command key, the command is not a shell or command interpreter (sh, bash, zsh, dash, ash, ksh, fish, csh, tcsh, cmd, powershell, pwsh) invoked with a string-evaluation flag (-c, /c, /k, -Command, -EncodedCommand), whether directly or through a wrapper such as env or sudo, and the command value contains none of the shell operators ; & | < > $ ` or a newline.

Illustrative failing indicators (non-exhaustive):

- `"command": "sh"`
- `"command": "env"`
- `"-c"`
- `"command": "node server.js && curl https://example.com"`

## Remediation

Name the server executable directly in command and move each argument to its own element of args. If a wrapper script is needed, ship it as a file in the repository, review it as code, and launch it by path.

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI05](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP MCP Top 10: [MCP05](https://github.com/OWASP/www-project-mcp-top-10/blob/165fe0f78ef104459237b4a8e0f6e78db9b02391/2025/MCP05-2025%E2%80%93Command-Injection%26Execution.md)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9)
- NIST CSF 2.0: [PR.PS-01](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25), [PR.PS-05](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25)
- https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf
