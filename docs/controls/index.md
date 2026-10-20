# Control index

Generated from controls/*.yaml. Do not hand-edit.

| ID | Title | Applies to | Severity | OWASP ASI | OWASP AST |
| --- | --- | --- | --- | --- | --- |
| [ACB-GEN-001](ACB-GEN-001.md) | Remote content is never piped into an interpreter | skill, instruction-file, mcp-server-declaration | high | ASI04, ASI05 | AST02 |
| [ACB-GEN-002](ACB-GEN-002.md) | External code and dependencies are pinned immutably | skill, instruction-file, mcp-server-declaration | high | ASI04 | AST02 |
| [ACB-GEN-003](ACB-GEN-003.md) | Artifacts contain no embedded secrets | skill, instruction-file, mcp-server-declaration | high | ASI03 | - |
| [ACB-GEN-004](ACB-GEN-004.md) | Artifacts contain no invisible or bidirectional control characters | skill, instruction-file, mcp-server-declaration | high | ASI01 | - |
| [ACB-INSTR-001](ACB-INSTR-001.md) | Instructions do not direct the agent to bypass human oversight | skill, instruction-file | high | ASI02, ASI09 | - |
| [ACB-INSTR-002](ACB-INSTR-002.md) | Instructions do not modify agent configuration or instruction files | skill, instruction-file | high | ASI06, ASI10 | AST02 |
| [ACB-INSTR-003](ACB-INSTR-003.md) | Instructions do not elevate trust in untrusted content | skill, instruction-file | high | ASI01, ASI06 | - |
| [ACB-SKILL-001](ACB-SKILL-001.md) | SKILL.md frontmatter conforms to the Agent Skills specification | skill | high | ASI04 | - |
| [ACB-SKILL-002](ACB-SKILL-002.md) | Skills do not pre-approve tools | skill | high | ASI02, ASI03 | - |
| [ACB-SKILL-003](ACB-SKILL-003.md) | Bundled skill content is transparent, referenced and contained | skill | high | ASI04, ASI05 | AST02 |
