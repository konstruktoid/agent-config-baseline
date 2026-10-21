# ACB-EXT-003: Extension capabilities are recorded and high-risk ones are justified

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `medium` |
| Check type | `static` |
| Applies to | `extension-package` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

A package that ships in-process modules commits a capability record, extension-capabilities.txt at the package root, listing the events each module handles and the host API calls it makes in the form the client's validator prints. Every high-risk capability the modules use (approving tool calls, rewriting prompts or tool calls, starting processes, making network requests, calling a model, reading secrets) is named and justified in the package README.

## Rationale

What in-process code can do is decided by the events it handles and the host calls it makes, not by its description. A committed record turns a new capability into a line in a diff that a reviewer sees, instead of a change buried in module source. Capabilities that let extension code approve actions, rewrite what the model reads or reach outside the host are the ones that defeat other controls, so each needs a stated reason.

## Audit procedures

### `record-present` (inventory)

If the package ships in-process modules, extension-capabilities.txt exists at the package root, is readable text, and names every module by file name.

### `high-risk-documented` (pattern)

Every event a module registers a handler for and every host API call it makes, as found in module source, that the client lists as high risk appears in the package README.

### `record-current` (structure)

When the operator enables validators and the client defines one, the validator's event and call lines for the package equal the lines in extension-capabilities.txt. Without an enabled, installed validator, this procedure is not evaluated rather than passed.

## Remediation

Generate the record with the client's validator, commit it at the package root, and regenerate it in CI so a stale record fails review. Justify each high-risk capability in the README, or remove it.

## Implementation notes

Client-specific facts from `clients/`; the control above is the requirement.

### claude-code: `record-current`

Generate the record with `claude plugin validate <package-dir>` and keep its `hooks:` and `calls:` lines in extension-capabilities.txt. Run `acb check --run-validators` where the claude CLI is installed to compare the record with the validator; without it this procedure is not evaluated. In the `hooks:` line, tool.check means the mod can approve or deny a tool call before a permission prompt, and tool.call and prompt.submit mean it sees and can change every tool call and prompt.

- https://code.claude.com/docs/en/plugins/mods/admin
- https://code.claude.com/docs/en/plugins/mods/reference

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI02](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP Agentic Skills Top 10: [AST02](https://owasp.org/www-project-agentic-skills-top-10/ast02.html)
- Careful Adoption of Agentic AI Services risk areas: [privilege](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=7), [accountability](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=12)
- NIST CSF 2.0: [ID.AM-02](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=23), [ID.RA-09](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24)
- https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf
