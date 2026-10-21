# ACB-CFG-005: Tool server tools are pre-approved by name, never server-wide

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `medium` |
| Check type | `static` |
| Applies to | `agent-settings`, `managed-settings` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

An allow rule in the agent's committed permission configuration that pre-approves a tool server's tools names one tool exactly. No allow rule approves every tool a server offers, or every tool whose name matches a pattern.

## Rationale

A reviewer who approves a tool server approves the tools it offered at that moment. A server-wide or pattern allow rule also approves every tool the server adds or redefines later, so a server whose package, endpoint or operator is compromised after review can introduce a tool that runs without anyone being asked. Naming each tool keeps a new tool behind the host's approval prompt and turns widening the approval into a reviewed change to the settings file.

## Audit procedures

### `tools-allowed-by-name` (structure)

Collect the allow rules from every agent settings file in the repository. No allow rule matches a form the client defines as approving more than one named tool of a tool server: a rule naming only the server, or a rule with a wildcard in the tool name. Not evaluated when the client defines no such forms.

Illustrative failing indicators (non-exhaustive):

- `"allow": ["mcp__github"]`
- `"allow": ["mcp__github__*"]`
- `"allow": ["mcp__github__get_*"]`

## Remediation

Replace each server-wide or pattern allow rule with one rule per tool the agent needs without a prompt, and leave every other tool of the server to the host's approval prompt.

## Implementation notes

Client-specific facts from `clients/`; the control above is the requirement.

### claude-code: `tools-allowed-by-name`

MCP tools are named mcp__<server>__<tool>. As an allow rule, mcp__<server> and mcp__<server>__* match every tool of the server, and a glob after the mcp__<server>__ prefix, such as mcp__github__get_*, matches every tool whose name fits it. Unanchored allow globs such as mcp__* are skipped and approve nothing. Allow rules in a project's .claude/settings.json apply only after the workspace trust dialog, which lists them, is accepted.

- https://code.claude.com/docs/en/permissions

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI02](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP MCP Top 10: [MCP02](https://github.com/OWASP/www-project-mcp-top-10/blob/165fe0f78ef104459237b4a8e0f6e78db9b02391/2025/MCP02-2025%E2%80%93Privilege-Escalation-via-Scope-Creep.md), [MCP03](https://github.com/OWASP/www-project-mcp-top-10/blob/165fe0f78ef104459237b4a8e0f6e78db9b02391/2025/MCP03-2025%E2%80%93Tool-Poisoning.md)
- Careful Adoption of Agentic AI Services risk areas: [privilege](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=7)
- NIST CSF 2.0: [PR.AA-05](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25)
- https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf
