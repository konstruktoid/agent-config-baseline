# ACB-CFG-004: Human approval requirements are defined by configuration

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `medium` |
| Check type | `static` |
| Applies to | `agent-settings`, `managed-settings`, `extension-package` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

The actions that need human approval are enumerated in the agent's permission configuration as ask or deny rules, enforced by the host. They are not left to instructions the model may or may not follow, and no extension code in the repository handles the host's tool-approval event, where it could approve an action before the user is asked.

## Rationale

Designers and operators, not the agent, decide which actions need human sign-off. An instruction such as "ask before deleting" is a request to a model that injected content can override; a permission rule is enforced by the host. Extension code that answers the approval event moves that decision into code that is rarely reviewed as policy and, depending on the host's configuration, can approve calls other rules would stop.

## Audit procedures

### `approval-rules-present` (structure)

Every agent settings file in the repository defines at least one ask or deny rule. Not applicable when the repository contains no agent settings file.

### `approval-not-delegated` (pattern)

No in-process module in any extension package registers a handler for an event the client defines as a tool-approval event.

## Remediation

Write the approval requirements as ask and deny rules in the committed settings, or in managed policy. Remove approval handling from extension code; an extension that must refuse calls can do so from a guard event that cannot approve.

## Implementation notes

Client-specific facts from `clients/`; the control above is the requirement.

### claude-code: `approval-not-delegated`

A mod that handles tool.check gives its answer after permission rules and PreToolUse hooks; where the built-in guard does not load, its approval can skip ask rules, PreToolUse hooks and deny rules. Source matching is best effort (a handler registered through an alias is not seen); the validator's hooks: line, checked by ACB-EXT-003 record-current, is the authoritative list.

- https://code.claude.com/docs/en/permissions
- https://code.claude.com/docs/en/plugins/mods/admin

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI02](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [ASI09](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9), [accountability](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=12)
- NIST CSF 2.0: [PR.AA-05](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25), [GV.RR-02](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=22)
- https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf
