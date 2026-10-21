# ACB-CFG-002: The agent cannot install, enable or sideload extensions

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `agent-settings`, `managed-settings` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

Installing or enabling an extension requires a human action outside the agent's own tool calls. The committed permission configuration denies the agent the client's extension install and management commands, and managed policy, where present, stops extensions from loading outside the managed install path, including extension code the agent writes itself.

## Rationale

An agent that can install or load extensions can give itself new code running in its own host with the user's privileges, and an agent that can write extension code and have it loaded can do the same without any install step. Either way the agent decides what oversees it. Extension installation is a privilege decision that belongs to a person.

## Audit procedures

### `install-commands-denied` (structure)

Collect the deny rules from every agent settings file in the repository. For every extension install rule group the client defines, at least one of its rules is present.

### `managed-sideload-disabled` (structure)

Every managed settings file holds the client's sideload restriction values. Not applicable when the repository contains no managed settings file.

## Remediation

Deny the extension install and management commands in committed settings, and set the sideload restriction in managed policy so that extensions load only from the managed install path.

## Implementation notes

Client-specific facts from `clients/`; the control above is the requirement.

### claude-code: `install-commands-denied`

Plugins, including mods, install with `claude plugin install` from a shell or `/plugin install` in a session. Bash rule patterns match the command as written, so a deny rule does not catch every spelling (for example an absolute path to the binary); the managed sideload restriction is the stronger layer.

- https://code.claude.com/docs/en/plugins/mods/overview
- https://code.claude.com/docs/en/permissions

### claude-code: `managed-sideload-disabled`

disableSideloadFlags in managed settings rejects --plugin-dir and --plugin-url and keeps mods that Claude writes during a session from loading.

- https://code.claude.com/docs/en/plugins/mods/admin

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI03](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP Agentic Skills Top 10: [AST02](https://owasp.org/www-project-agentic-skills-top-10/ast02.html)
- Careful Adoption of Agentic AI Services risk areas: [privilege](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=7), [structural](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=11)
- NIST CSF 2.0: [PR.PS-05](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25), [PR.AA-05](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25)
- https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf
