# ACB-CFG-003: Blocking policy is enforced in a layer user-installed extensions cannot override

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `managed-settings` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

Where the agent host supports organization-managed policy, the managed layer restricts in-process extension loading to organization-managed extensions and does not let any other extension approve an action a deny rule refuses. A repository that cannot carry managed policy is not the subject of this control: audit the deployed managed settings instead by running the checker on the directory that holds them.

## Rationale

Deny rules, ask rules and blocking hooks are only as strong as the layer that evaluates them. In-process extension code that can approve a tool call can make a rule the user set, or a hook the user installed, ineffective. Policy that must hold has to live where user-installed extension code cannot reach it, and the decision about which actions need human sign-off belongs to the system's designers and operators, not to the agent or to code it loads.

## Audit procedures

### `managed-extension-restriction` (structure)

Every managed settings file holds the client's extension restriction values: in-process extension code limited to managed extensions, no option that lets other extensions approve calls a deny rule refuses, and the host's own policy guard kept in any explicit load order.

## Remediation

Set the extension restriction values in managed policy and deploy them through the organization's settings management, then confirm on an endpoint that a user-installed extension is refused.

## Implementation notes

Client-specific facts from `clients/`; the control above is the requirement.

### claude-code: `managed-extension-restriction`

Set pluginConfigs."cc-plugin-sec-default@builtin".options.allowManagedModsOnly to true in managed settings, leave allowModsToOverrideDenyRules unset, and if prependPlugins is set, list sec-default@builtin in it. Without managed settings or a Team or Enterprise login, a mod can approve a call that a deny rule refuses or a PreToolUse hook blocked. Confirm on an endpoint with `claude --debug` and the guard's refusal line.

- https://code.claude.com/docs/en/plugins/mods/admin
- https://code.claude.com/docs/en/permissions

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI03](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9), [structural](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=11)
- NIST CSF 2.0: [PR.PS-01](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25), [PR.PS-05](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25)
- https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf
