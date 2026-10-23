# Coverage mappings

Generated from controls/*.yaml. Do not hand-edit. Mapping is by ID
only; control text does not reproduce OWASP prose (PROMPT.md ground
rule 4).

## OWASP Top 10 for Agentic Applications 2026 (ASI)

Source: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

| ASI ID | Controls |
| --- | --- |
| [ASI01](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | ACB-GEN-004, ACB-INSTR-003 |
| [ASI02](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | ACB-CFG-004, ACB-CFG-005, ACB-EXT-003, ACB-EXT-004, ACB-INSTR-001, ACB-SKILL-002 |
| [ASI03](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | ACB-CFG-001, ACB-CFG-002, ACB-CFG-003, ACB-GEN-003, ACB-MCP-001, ACB-SKILL-002 |
| [ASI04](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | ACB-CFG-002, ACB-CFG-003, ACB-EXT-001, ACB-EXT-002, ACB-EXT-003, ACB-GEN-001, ACB-GEN-002, ACB-PROV-001, ACB-SKILL-001, ACB-SKILL-003 |
| [ASI05](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | ACB-GEN-001, ACB-MCP-002, ACB-MCP-003, ACB-SKILL-003 |
| [ASI06](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | ACB-INSTR-002, ACB-INSTR-003 |
| [ASI09](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | ACB-CFG-004, ACB-INSTR-001 |
| [ASI10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | ACB-CFG-001, ACB-INSTR-002 |

## OWASP Agentic Skills Top 10 (AST)

| AST ID | Controls | Verified |
| --- | --- | --- |
| [AST02](https://owasp.org/www-project-agentic-skills-top-10/ast02.html) | ACB-CFG-002, ACB-EXT-001, ACB-EXT-002, ACB-EXT-003, ACB-GEN-001, ACB-GEN-002, ACB-INSTR-002, ACB-PROV-001, ACB-SKILL-003 | yes |

## TODO: unverified AST mappings

None open: every `owasp_ast` reference currently in controls/ is verified.

## OWASP MCP Top 10

Source: https://owasp.org/projects/mcp-top-10

| MCP ID | Title | Controls |
| --- | --- | --- |
| [MCP02](https://github.com/OWASP/www-project-mcp-top-10/blob/165fe0f78ef104459237b4a8e0f6e78db9b02391/2025/MCP02-2025%E2%80%93Privilege-Escalation-via-Scope-Creep.md) | Privilege Escalation via Scope Creep | ACB-CFG-005 |
| [MCP03](https://github.com/OWASP/www-project-mcp-top-10/blob/165fe0f78ef104459237b4a8e0f6e78db9b02391/2025/MCP03-2025%E2%80%93Tool-Poisoning.md) | Tool Poisoning | ACB-CFG-005 |
| [MCP05](https://github.com/OWASP/www-project-mcp-top-10/blob/165fe0f78ef104459237b4a8e0f6e78db9b02391/2025/MCP05-2025%E2%80%93Command-Injection%26Execution.md) | Command Injection & Execution | ACB-MCP-002, ACB-MCP-003 |
| [MCP07](https://github.com/OWASP/www-project-mcp-top-10/blob/165fe0f78ef104459237b4a8e0f6e78db9b02391/2025/MCP07-2025%E2%80%93Insufficient-Authentication%26Authorization.md) | Insufficient Authentication & Authorization | ACB-MCP-001 |

## Careful Adoption of Agentic AI Services (ASD's ACSC, CISA, NSA, CCCS, NCSC-NZ, NCSC-UK, May 2026)

Source: https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf

| Risk area | Controls |
| --- | --- |
| [accountability](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=12) | ACB-CFG-001, ACB-CFG-004, ACB-EXT-001, ACB-EXT-003, ACB-GEN-004, ACB-SKILL-003 |
| [behaviour](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9) | ACB-EXT-004, ACB-GEN-004, ACB-INSTR-001, ACB-INSTR-003 |
| [design-and-configuration](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=9) | ACB-CFG-003, ACB-CFG-004, ACB-EXT-001, ACB-EXT-002, ACB-EXT-004, ACB-GEN-001, ACB-GEN-002, ACB-INSTR-001, ACB-INSTR-002, ACB-MCP-001, ACB-MCP-002, ACB-MCP-003, ACB-PROV-001, ACB-SKILL-001, ACB-SKILL-003 |
| [privilege](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=7) | ACB-CFG-001, ACB-CFG-002, ACB-CFG-005, ACB-EXT-002, ACB-EXT-003, ACB-GEN-003, ACB-INSTR-002, ACB-MCP-001, ACB-SKILL-002 |
| [structural](https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf#page=11) | ACB-CFG-002, ACB-CFG-003, ACB-INSTR-003 |

## NIST Cybersecurity Framework 2.0 (NIST CSWP 29)

Source: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf. Each subcategory's text was checked against that publication.

| Subcategory | Outcome | Controls |
| --- | --- | --- |
| [GV.RR-02](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=22) | Roles, responsibilities, and authorities related to cybersecurity risk management are established, communicated, understood, and enforced | ACB-CFG-004 |
| [ID.AM-02](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=23) | Inventories of software, services, and systems managed by the organization are maintained | ACB-EXT-001, ACB-EXT-003 |
| [ID.IM-02](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24) | Improvements are identified from security tests and exercises, including those done in coordination with suppliers and relevant third parties | ACB-EXT-004 |
| [ID.RA-09](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24) | The authenticity and integrity of hardware and software are assessed prior to acquisition and use | ACB-EXT-001, ACB-EXT-002, ACB-EXT-003, ACB-GEN-001, ACB-GEN-002, ACB-GEN-004, ACB-PROV-001, ACB-SKILL-003 |
| [PR.AA-01](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=24) | Identities and credentials for authorized users, services, and hardware are managed by the organization | ACB-GEN-003 |
| [PR.AA-05](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25) | Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties | ACB-CFG-001, ACB-CFG-002, ACB-CFG-004, ACB-CFG-005, ACB-INSTR-001, ACB-INSTR-002, ACB-INSTR-003, ACB-MCP-001, ACB-SKILL-002 |
| [PR.PS-01](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25) | Configuration management practices are established and applied | ACB-CFG-001, ACB-CFG-003, ACB-GEN-002, ACB-INSTR-002, ACB-MCP-001, ACB-MCP-002, ACB-MCP-003, ACB-SKILL-001 |
| [PR.PS-05](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25) | Installation and execution of unauthorized software are prevented | ACB-CFG-002, ACB-CFG-003, ACB-EXT-002, ACB-GEN-001, ACB-MCP-002, ACB-MCP-003, ACB-SKILL-003 |
| [PR.PS-06](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf#page=25) | Secure software development practices are integrated, and their performance is monitored throughout the software development life cycle | ACB-EXT-004 |
