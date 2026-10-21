# ACB-MCP-001: Remote MCP servers use TLS and declare authentication

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `mcp-server-declaration` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

Every MCP server declaration that names a remote endpoint by URL uses an encrypted scheme (https or wss) and declares how the client authenticates to it. A loopback endpoint (localhost, 127.0.0.0/8 or ::1) is exempt from both requirements.

## Rationale

An MCP server receives prompts, tool arguments and results, and can return instructions the agent acts on. A cleartext connection lets anyone on the path read or rewrite that traffic, and a server that accepts unauthenticated clients lets anyone who can reach it invoke its tools. Authorization is optional in the protocol, and many deployments omit it, so the declaration is the place a reviewer can see that it was not omitted.

## Audit procedures

### `remote-uses-tls` (structure)

Each server entry with a url key whose host is not a loopback address uses the https or wss scheme. A cleartext scheme, or a url that cannot be parsed into a scheme and host, fails or is reported as not evaluated respectively.

Illustrative failing indicators (non-exhaustive):

- `"url": "http://mcp.example.com/mcp"`

### `remote-declares-auth` (structure)

Each server entry with a url key whose host is not a loopback address declares authentication: an auth, oauth or authorization key, or a headers mapping that contains an authorization or API-key header. Credential values are not inspected here (see ACB-GEN-003).

Illustrative failing indicators (non-exhaustive):

- `"url": "https://mcp.example.com/mcp"`

## Remediation

Change the url to an https or wss endpoint, and add an authentication declaration that refers to the credential by reference, for example an Authorization header whose value is taken from an environment variable. Run a server that needs neither only on a loopback address.

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI03](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP MCP Top 10: [MCP07](https://github.com/OWASP/www-project-mcp-top-10/blob/165fe0f78ef104459237b4a8e0f6e78db9b02391/2025/MCP07-2025%E2%80%93Insufficient-Authentication%26Authorization.md)
- Careful Adoption of Agentic AI Services risk areas: [privilege](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=7), [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9)
- NIST CSF 2.0: [PR.AA-05](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25), [PR.PS-01](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25)
- https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf
