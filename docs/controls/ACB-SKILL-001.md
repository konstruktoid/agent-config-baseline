# ACB-SKILL-001: SKILL.md frontmatter conforms to the Agent Skills specification

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `skill` |
| Profiles | strict-general |
| Exceptions | `not-permitted` |

## Description

Every skill directory contains a SKILL.md whose YAML frontmatter is parseable and satisfies the field constraints of the Agent Skills specification. Unknown top-level keys are not permitted; client-specific data belongs under `metadata`.

## Rationale

The name and description are the only content an agent reads before deciding to load a skill, so they are the skill's attack surface at discovery time. Malformed or non-conforming frontmatter is parsed differently by different clients, which makes behaviour unpredictable and lets metadata smuggle content that one client renders and another ignores. Strict conformance makes the same skill mean the same thing everywhere.

## Audit procedures

### `frontmatter-parses` (structure)

SKILL.md begins with a YAML frontmatter block delimited by `---` lines that parses as a mapping using a safe YAML loader (no tags, no anchors resolving to non-scalar types, no duplicate keys).

### `required-fields` (structure)

`name` is 1-64 characters, matches ^[a-z0-9]+(-[a-z0-9]+)*$ (no leading, trailing or consecutive hyphens), and equals the parent directory name. `description` is a non-empty string of at most 1024 characters.

### `optional-fields` (structure)

If present: `license` is a string; `compatibility` is 1-500 characters; `metadata` is a mapping of string keys to string values; `allowed-tools` is a string. No other top-level keys exist.

## Remediation

Correct the frontmatter to match the specification. Rename the skill directory or the `name` field so they match. Move any non-standard top-level keys under `metadata` as string values.

## References

- OWASP Top 10 for Agentic Applications 2026: ASI04
- Specification: https://agentskills.io/specification
