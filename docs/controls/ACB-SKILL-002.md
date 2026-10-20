# ACB-SKILL-002: Skills do not pre-approve tools

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `skill` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

The experimental `allowed-tools` frontmatter field is absent. A skill does not grant itself permission to run tools without the confirmation the user or operator has configured.

## Rationale

`allowed-tools` lets a skill author decide, at install time, which tool calls skip human approval. That moves an authorization decision from the person running the agent to whoever wrote the skill, and it travels with the skill through every registry and fork. Support for the field varies between clients, so its effect on any given installation is also hard to predict. A strict baseline keeps approval decisions with the operator.

## Audit procedures

### `no-allowed-tools` (structure)

The parsed frontmatter of SKILL.md does not contain a key that pre-approves tools, at the top level or nested under `metadata`. This includes the specified `allowed-tools` key and common variant spellings of it (`allowed_tools`, `allowedTools`): the intent this control blocks is self-granted tool approval, and that intent does not depend on which casing or separator a client happens to read.

Illustrative failing indicators (non-exhaustive):

- `allowed-tools: Bash Read Write`
- `allowed-tools: Bash(*)`
- `allowedTools: Bash Read Write`

## Remediation

Remove `allowed-tools`. Document the tools the skill needs in the body or in `compatibility` so the operator can decide whether to grant them in their own client configuration.

## References

- OWASP Top 10 for Agentic Applications 2026: ASI02, ASI03
- Specification: https://agentskills.io/specification
