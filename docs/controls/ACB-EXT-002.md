# ACB-EXT-002: Content packages contain no executable extension components

| Field | Value |
| --- | --- |
| Status | `draft` |
| Severity | `high` |
| Check type | `static` |
| Applies to | `extension-package` |
| Profiles | strict-general |
| Exceptions | `permitted` |

## Description

An extension package that ships agent content (skills, commands, subagent definitions or other instructions) does not also ship executable components: lifecycle hooks, in-process modules, tool servers, language servers, background processes, or executables placed on the agent's command path. Code and content are distributed as separate packages.

## Rationale

Installing a package grants every component in it at once. A consumer who reviews a package as instructions ("it is just a skills package") does not review it as code, yet a hook, server or in-process module in the same package runs with the user's privileges, and an in-process module can approve tool calls and rewrite prompts. Separating content from code keeps the install decision honest: a content package can be trusted by reading it, and a code package is reviewed as code.

## Audit procedures

### `no-executable-components` (inventory)

If the package ships agent content (a content directory or file the client defines, or a manifest field that declares content), it contains no executable component: no component file or directory the client defines, no manifest field that declares one, and no in-process module as enumerated by ACB-EXT-001.

## Remediation

Move the executable components into a separate package with its own documentation and capability record (ACB-EXT-001, ACB-EXT-003), and publish the content on its own.

## Implementation notes

Client-specific facts from `clients/`; the control above is the requirement.

### claude-code: `no-executable-components`

A plugin that ships skills can also ship hooks (hooks/hooks.json or the manifest `hooks` field), a mod, MCP servers (.mcp.json or `mcpServers`), LSP servers (.lsp.json or `lspServers`), monitors (monitors/monitors.json or `experimental.monitors`) and executables on the shell tool's PATH (bin/). Any of these fails a package that ships skills, commands or agents.

- https://code.claude.com/docs/en/plugins/manifest-reference
- https://code.claude.com/docs/en/plugins/mods/overview

## References

- OWASP Top 10 for Agentic Applications 2026: ASI04
- OWASP Agentic Skills Top 10: AST02
- Careful Adoption of Agentic AI Services risk areas: privilege, design-and-configuration
- NIST CSF 2.0: ID.RA-09, PR.PS-05
- https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf
