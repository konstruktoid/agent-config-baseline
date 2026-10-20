# ACB-GEN-004: Artifacts contain no invisible or bidirectional control characters

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `skill`, `instruction-file`, `mcp-server-declaration` |
| Profiles | strict-general |
| Exceptions | `not-permitted` |

## Description

No artifact contains Unicode characters that are invisible or that reorder displayed text, so that what a human reviewer sees is what the model reads.

## Rationale

Models read code points, reviewers read rendered glyphs. Zero-width characters, Unicode tag characters and bidirectional overrides let an author hide instructions that render as nothing, or as something else, in diffs, editors and registry pages. This is a cheap, reliable way to get unreviewed instructions into model context.

## Audit procedures

### `forbidden-code-points` (pattern)

No file contains any of: U+200B-U+200F, U+202A-U+202E, U+2060-U+2064, U+2066-U+2069, U+FEFF (except as the first code point of a file), U+00AD, U+180E, U+034F, U+061C, U+3164, U+2800, U+FFF9, U+FE00-U+FE0F (variation selectors), U+E0100-U+E01EF (supplementary variation selectors), any code point in U+E0000-U+E007F (tag characters), or any code point in Unicode private use areas.

### `confusable-identifiers` (pattern)

Skill names, file names and command names in code blocks contain only ASCII, so mixed-script look-alikes cannot impersonate a trusted name.

## Remediation

Strip the characters, review the decoded content to determine what was hidden, and treat the artifact as potentially malicious until the origin of the characters is explained.

## References

- OWASP Top 10 for Agentic Applications 2026: ASI01
- https://www.unicode.org/reports/tr36/
- https://trojansource.codes/
