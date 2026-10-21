# ACB-GEN-003: Artifacts contain no embedded secrets

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `skill`, `instruction-file`, `mcp-server-declaration` |
| Profiles | strict-general |
| Exceptions | `not-permitted` |

## Description

No artifact contains credentials, tokens, private keys or connection strings with embedded passwords. MCP server declarations reference secrets through environment variable indirection or a secret store, never as literal values.

## Rationale

Agent artifacts are designed to be shared, forked and published to registries, and their contents are loaded into model context where they can be echoed, logged or exfiltrated. A secret in an artifact is a secret disclosed to every consumer and every agent session that reads it.

## Audit procedures

### `secret-scan` (pattern)

Run a secret scanner with high-confidence provider rules and generic high-entropy detection over all files. Any finding fails.

Illustrative failing indicators (non-exhaustive):

- `-----BEGIN OPENSSH PRIVATE KEY-----`
- `postgres://admin:hunter2@db.example.com/prod`

### `mcp-env-indirection` (structure)

In MCP server declarations, values of `env`, `headers` and argument fields whose key or flag name suggests a credential (token, key, secret, password, auth) are environment-variable references or placeholders, not literals.

Illustrative failing indicators (non-exhaustive):

- `"env": {"API_TOKEN": "sk-live-..."}`
- `"Authorization": "Bearer eyJ..."`

## Remediation

Remove the secret, rotate it, and purge it from version history. Replace literals with environment variable references and document the variable name the consumer must provide.

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI03](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- Careful Adoption of Agentic AI Services risk areas: [privilege](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=7)
- NIST CSF 2.0: [PR.AA-01](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24)
