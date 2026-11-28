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

Every MCP server declaration that names a remote endpoint by URL uses an encrypted scheme (https or wss) and declares how the client authenticates to it. The same applies to a remote server reached through a stdio proxy (mcp-remote, supergateway or mcp-proxy) named in a launch command. A loopback endpoint (localhost, 127.0.0.0/8 or ::1) is exempt from both requirements. Proxy detection is best-effort: it reads common launch forms without running them, so a pass does not show that a launch command reaches no remote server.

## Rationale

An MCP server receives prompts, tool arguments and results, and can return instructions the agent acts on. A cleartext connection lets anyone on the path read or rewrite that traffic, and a server that accepts unauthenticated clients lets anyone who can reach it invoke its tools. Authorization is optional in the protocol, and many deployments omit it, so the declaration is the place a reviewer can see that it was not omitted.

## Audit procedures

### `remote-uses-tls` (structure)

Each server entry with a url key whose host is not a loopback address uses the https or wss scheme. A cleartext scheme, or a url that cannot be parsed into a scheme and host, fails or is reported as not evaluated respectively. The same applies to the endpoint a server entry passes to a proxy named in command or args: the first positional argument of mcp-remote or mcp-proxy, or the --sse or --streamableHttp value of supergateway. For mcp-proxy, only a value containing :// is an endpoint, since anything else is a local command, and the SSE_URL environment entry is read when no positional argument is given. Abbreviated option names, other proxies and proxy configuration files are not read.

Illustrative failing indicators (non-exhaustive):

- `"url": "http://mcp.example.com/mcp"`
- `"mcp-remote@0.1.16", "http://mcp.example.com/mcp"`

### `remote-declares-auth` (structure)

Each server entry with a url key whose host is not a loopback address declares authentication: an auth, oauth or authorization key, or a headers mapping that contains an authorization or API-key header. Credential values are not inspected here (see ACB-GEN-003). A proxied server declares it with an authorization or API-key header argument; for mcp-remote also a static OAuth client information or metadata option, each as separate words because it ignores --flag=value, and no other mcp-remote option counts; for supergateway also --oauth2Bearer; for mcp-proxy also --client-id, --username or an API_ACCESS_TOKEN environment entry. For a container launch, only environment variables passed with -e or --env are read, not environment files. Interactive OAuth that the declaration does not mention does not count.

Illustrative failing indicators (non-exhaustive):

- `"url": "https://mcp.example.com/mcp"`
- `"mcp-remote@0.1.16", "https://mcp.example.com/mcp"`

## Remediation

Change the url to an https or wss endpoint, and add an authentication declaration that refers to the credential by reference, for example an Authorization header whose value is taken from an environment variable. For a proxied server, make both changes in the proxy's arguments. Run a server that needs neither only on a loopback address.

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI03](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP MCP Top 10: [MCP07](https://github.com/OWASP/www-project-mcp-top-10/blob/165fe0f78ef104459237b4a8e0f6e78db9b02391/2025/MCP07-2025%E2%80%93Insufficient-Authentication%26Authorization.md)
- Careful Adoption of Agentic AI Services risk areas: [privilege](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=7), [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9)
- NIST CSF 2.0: [PR.AA-05](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25), [PR.PS-01](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25)
- https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf
- https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/
- https://arxiv.org/abs/2605.22333
