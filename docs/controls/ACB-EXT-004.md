# ACB-EXT-004: Blocking guards have tests that prove they deny

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `extension-package`, `agent-settings`, `managed-settings` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

Every committed guard that is meant to stop an agent action, whether a lifecycle hook registered for an event that can block or an in-process module that handles a tool-call guard event, has an automated test that shows the guarded action does not happen, not only that a warning is printed.

## Rationale

A guard that reports failure the wrong way, or that crashes, can let every action through while appearing to work: hosts commonly treat an unexpected exit status or an exception in extension code as a non-blocking error and continue. A published case had a blocking hook print "BLOCKED" and allow every write because it signalled failure with the wrong exit code. Only a test that asserts the denial catches this.

## Audit procedures

### `guards-have-tests` (inventory)

For each handler registered for a blocking event in an agent settings file or a package hook configuration, the handler runs a script file in the repository and at least one test file (a file under a tests, test, spec or __tests__ directory, or named test_*, *_test.*, *.test.*, *.spec.* or *.bats) references that script by file name. A handler with no script file fails, because no test can exercise it. For each package with an in-process module that handles a guard event, the package contains at least one module test file.

Illustrative failing indicators (non-exhaustive):

- `hooks/block-writes.sh (blocking hook script no test references)`

## Remediation

Move the guard's logic into a script, and add a test that feeds it a request it must refuse and asserts the refusal the host acts on (the exit status or decision output), not the text it prints. For in-process guards, add a module test that fires the guarded event and asserts the denial, including when the guard's own check fails.

## Implementation notes

Client-specific facts from `clients/`; the control above is the requirement.

### claude-code: `guards-have-tests`

A PreToolUse command hook blocks only by exiting with code 2 or by printing a deny decision; exit code 1 is a non-blocking error and the tool call goes ahead. A mod hook that throws or times out is skipped, so the event goes ahead unless the hook has a .catch handler that refuses. Mod tests are files ending in .test.ts or .test.tsx, run with `claude plugin test`.

- https://code.claude.com/docs/en/hooks
- https://code.claude.com/docs/en/plugins/mods/admin
- https://code.claude.com/docs/en/plugins/mods/reference

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI02](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9), [behaviour](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9)
- NIST CSF 2.0: [ID.IM-02](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24), [PR.PS-06](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25)
- https://www.nist.gov/system/files/documents/2026/10/16/Key_Practices_for_Incident_Readiness_and_Response_in_Super_Intelligence%20_Training_and_Evaluation.pdf
