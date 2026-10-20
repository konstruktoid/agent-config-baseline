# ACB-CFG-001: The agent cannot modify its own configuration, extensions or instructions

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `agent-settings`, `managed-settings` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

The agent's committed permission configuration denies its own file-writing tools access to the agent's settings and hook definitions, its extension and plugin directories, its instruction files and its tool server declarations.

## Rationale

Settings, hooks, extensions and instruction files are the agent's controls and part of its monitoring. An agent that can write them can widen its permissions, disable or rewrite a guard, install code that runs in its own host, or change the instructions every later session starts from, all through ordinary file edits. Agents must not be able to access or interfere with the mechanisms that oversee them; a deny rule enforced by the host, rather than an instruction to the model, is what makes that hold.

## Audit procedures

### `self-protection-rules` (structure)

Collect the deny rules from every agent settings file in the repository. For every protected target the client defines (project and user configuration directories, instruction files, tool server declarations), at least one of the client's equivalent deny rules is present. Allow and ask rules, and instructions to the model, do not count.

## Remediation

Add deny rules for the file-writing tools covering each protected target to the committed settings, and enable the host's sandbox so that commands the agent runs cannot write those paths either.

## Implementation notes

Client-specific facts from `clients/`; the control above is the requirement.

### claude-code: `self-protection-rules`

Only Edit(path) and Read(path) rules govern file tools; a Write(path) rule is accepted but never consulted. Edit deny rules also cover file commands Claude Code recognizes in Bash and redirection targets, but not arbitrary subprocesses, so pair them with the sandbox. Deny and ask rules in a committed .claude/settings.json apply before workspace trust.

- https://code.claude.com/docs/en/permissions
- https://code.claude.com/docs/en/settings

## References

- OWASP Top 10 for Agentic Applications 2026: ASI03, ASI10
- Careful Adoption of Agentic AI Services risk areas: privilege, accountability
- NIST CSF 2.0: PR.AA-05, PR.PS-01
- https://www.nist.gov/system/files/documents/2026/10/16/Key_Practices_for_Incident_Readiness_and_Response_in_Super_Intelligence%20_Training_and_Evaluation.pdf
- https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf
