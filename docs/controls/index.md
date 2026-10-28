# Control index

Generated from controls/*.yaml. Do not hand-edit.

| ID | Title | Applies to | Severity | OWASP ASI | OWASP AST |
| --- | --- | --- | --- | --- | --- |
| [ACB-CFG-001](ACB-CFG-001.md) | The agent cannot modify its own configuration, extensions or instructions | agent-settings, managed-settings | high | ASI03, ASI10 | - |
| [ACB-CFG-002](ACB-CFG-002.md) | The agent cannot install, enable or sideload extensions | agent-settings, managed-settings | high | ASI03, ASI04 | AST02 |
| [ACB-CFG-003](ACB-CFG-003.md) | Blocking policy is enforced in a layer user-installed extensions cannot override | managed-settings | high | ASI03, ASI04 | - |
| [ACB-CFG-004](ACB-CFG-004.md) | Human approval requirements are defined by configuration | agent-settings, managed-settings, extension-package | medium | ASI02, ASI09 | - |
| [ACB-CFG-005](ACB-CFG-005.md) | Tool server tools are pre-approved by name, never server-wide | agent-settings, managed-settings | medium | ASI02 | - |
| [ACB-EXT-001](ACB-EXT-001.md) | In-process extension code is declared in package documentation | extension-package | medium | ASI04 | AST02 |
| [ACB-EXT-002](ACB-EXT-002.md) | Content packages contain no executable extension components | extension-package | high | ASI04 | AST02 |
| [ACB-EXT-003](ACB-EXT-003.md) | Extension capabilities are recorded and high-risk ones are justified | extension-package | medium | ASI02, ASI04 | AST02 |
| [ACB-EXT-004](ACB-EXT-004.md) | Blocking guards have tests that prove they deny | extension-package, agent-settings, managed-settings | high | ASI02 | - |
| [ACB-GEN-001](ACB-GEN-001.md) | Remote content is never piped into an interpreter | skill, instruction-file, mcp-server-declaration | high | ASI04, ASI05 | AST02 |
| [ACB-GEN-002](ACB-GEN-002.md) | External code and dependencies are pinned immutably | skill, instruction-file, mcp-server-declaration | high | ASI04 | AST02 |
| [ACB-GEN-003](ACB-GEN-003.md) | Artifacts contain no embedded secrets | skill, instruction-file, mcp-server-declaration | high | ASI03 | - |
| [ACB-GEN-004](ACB-GEN-004.md) | Artifacts contain no invisible or bidirectional control characters | skill, instruction-file, mcp-server-declaration | high | ASI01 | - |
| [ACB-INSTR-001](ACB-INSTR-001.md) | Instructions do not direct the agent to bypass human oversight | skill, instruction-file | high | ASI02, ASI09 | - |
| [ACB-INSTR-002](ACB-INSTR-002.md) | Instructions do not modify agent configuration or instruction files | skill, instruction-file | high | ASI06, ASI10 | AST02 |
| [ACB-INSTR-003](ACB-INSTR-003.md) | Instructions do not elevate trust in untrusted content | skill, instruction-file | high | ASI01, ASI06 | - |
| [ACB-MCP-001](ACB-MCP-001.md) | Remote MCP servers use TLS and declare authentication | mcp-server-declaration | high | ASI03 | - |
| [ACB-MCP-002](ACB-MCP-002.md) | MCP server launch commands are not interpreted by a shell | mcp-server-declaration | high | ASI05 | - |
| [ACB-MCP-003](ACB-MCP-003.md) | MCP server environment does not set process-startup hijack variables | mcp-server-declaration | high | ASI05 | - |
| [ACB-PROV-001](ACB-PROV-001.md) | Skills and extension packages carry a provenance record | skill, extension-package | medium | ASI04 | AST02 |
| [ACB-PROV-002](ACB-PROV-002.md) | Skill and extension package content matches its recorded digest | skill, extension-package | medium | ASI04 | AST02 |
| [ACB-PROV-003](ACB-PROV-003.md) | A signed attestation binds each skill and extension package to its recorded source | skill, extension-package | medium | ASI04 | AST02 |
| [ACB-SKILL-001](ACB-SKILL-001.md) | SKILL.md frontmatter conforms to the Agent Skills specification | skill | high | ASI04 | - |
| [ACB-SKILL-002](ACB-SKILL-002.md) | Skills do not pre-approve tools | skill | high | ASI02, ASI03 | - |
| [ACB-SKILL-003](ACB-SKILL-003.md) | Bundled skill content is transparent, referenced and contained | skill | high | ASI04, ASI05 | AST02 |
