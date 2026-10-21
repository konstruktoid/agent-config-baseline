# ACB-EXT-001: In-process extension code is declared in package documentation

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `medium` |
| Check type | `static` |
| Applies to | `extension-package` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

An extension package that ships in-process modules, code the agent host loads and runs inside its own process, names every such module in the package README. Modules are found wherever the host can load them: the package's hook configuration files and its module directory.

## Rationale

In-process extension code runs with the user's privileges, outside any sandbox that isolates the agent's own commands, and can see and change every prompt and tool call. The same package format also carries skills and instructions, so a consumer who believes they are installing content can be installing code. Declaring each module in the documentation a consumer reads before installing makes that code visible at the point of decision, and makes a newly added module a documentation change a reviewer sees.

## Audit procedures

### `modules-documented` (inventory)

Enumerate the package's in-process modules: every module a hook configuration file lists, and every file with a module suffix in the package's module directory, excluding test files. Each module's package-relative path appears in the README at the package root. A package with in-process modules and no README fails.

## Remediation

Add a section to the package README that names each in-process module by its package-relative path and states what it does. If the package is meant to ship content only, remove the modules (see ACB-EXT-002).

## Implementation notes

Client-specific facts from `clients/`; the control above is the requirement.

### claude-code: `modules-documented`

A mod is a plugin whose hooks/hooks.json lists a hooks module under `modules` (for example ./register.js, or .mjs, .cjs, .jsx, .ts, .mts, .cts or .tsx). The plugin manifest's `hooks` field can name further hook files. Mods run inside Claude Code with the user's permissions and are not sandboxed.

- https://code.claude.com/docs/en/plugins/mods/reference
- https://code.claude.com/docs/en/plugins/manifest-reference
- https://code.claude.com/docs/en/plugins/mods/overview

## References

- OWASP Top 10 for Agentic Applications 2026: [ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- OWASP Agentic Skills Top 10: [AST02](https://owasp.org/www-project-agentic-skills-top-10/ast02.html)
- Careful Adoption of Agentic AI Services risk areas: [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9), [accountability](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=12)
- NIST CSF 2.0: [ID.AM-02](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=23), [ID.RA-09](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24)
- https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf
