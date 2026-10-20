# Coverage mappings

Generated from controls/*.yaml. Do not hand-edit. Mapping is by ID
only; control text does not reproduce OWASP prose (PROMPT.md ground
rule 4).

## OWASP Top 10 for Agentic Applications 2026 (ASI)

| ASI ID | Controls |
| --- | --- |
| ASI01 | ACB-GEN-004, ACB-INSTR-003 |
| ASI02 | ACB-CFG-004, ACB-EXT-003, ACB-EXT-004, ACB-INSTR-001, ACB-SKILL-002 |
| ASI03 | ACB-CFG-001, ACB-CFG-002, ACB-CFG-003, ACB-GEN-003, ACB-SKILL-002 |
| ASI04 | ACB-CFG-002, ACB-CFG-003, ACB-EXT-001, ACB-EXT-002, ACB-EXT-003, ACB-GEN-001, ACB-GEN-002, ACB-SKILL-001, ACB-SKILL-003 |
| ASI05 | ACB-GEN-001, ACB-SKILL-003 |
| ASI06 | ACB-INSTR-002, ACB-INSTR-003 |
| ASI09 | ACB-CFG-004, ACB-INSTR-001 |
| ASI10 | ACB-CFG-001, ACB-INSTR-002 |

## OWASP Agentic Skills Top 10 (AST)

| AST ID | Controls | Verified |
| --- | --- | --- |
| AST02 | ACB-CFG-002, ACB-EXT-001, ACB-EXT-002, ACB-EXT-003, ACB-GEN-001, ACB-GEN-002, ACB-INSTR-002, ACB-SKILL-003 | yes |

## TODO: unverified AST mappings

None open: every `owasp_ast` reference currently in controls/ is verified.

## Careful Adoption of Agentic AI Services (ASD's ACSC, CISA, NSA, CCCS, NCSC-NZ, NCSC-UK, May 2026)

Source: https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf

| Risk area | Controls |
| --- | --- |
| accountability | ACB-CFG-001, ACB-CFG-004, ACB-EXT-001, ACB-EXT-003, ACB-GEN-004, ACB-SKILL-003 |
| behaviour | ACB-EXT-004, ACB-GEN-004, ACB-INSTR-001, ACB-INSTR-003 |
| design-and-configuration | ACB-CFG-003, ACB-CFG-004, ACB-EXT-001, ACB-EXT-002, ACB-EXT-004, ACB-GEN-001, ACB-GEN-002, ACB-INSTR-001, ACB-INSTR-002, ACB-SKILL-001, ACB-SKILL-003 |
| privilege | ACB-CFG-001, ACB-CFG-002, ACB-EXT-002, ACB-EXT-003, ACB-GEN-003, ACB-INSTR-002, ACB-SKILL-002 |
| structural | ACB-CFG-002, ACB-CFG-003, ACB-INSTR-003 |

## NIST Cybersecurity Framework 2.0 (NIST CSWP 29)

Source: https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf. Each subcategory's text was checked against that publication.

| Subcategory | Outcome | Controls |
| --- | --- | --- |
| GV.RR-02 | Roles, responsibilities, and authorities related to cybersecurity risk management are established, communicated, understood, and enforced | ACB-CFG-004 |
| ID.AM-02 | Inventories of software, services, and systems managed by the organization are maintained | ACB-EXT-001, ACB-EXT-003 |
| ID.IM-02 | Improvements are identified from security tests and exercises, including those done in coordination with suppliers and relevant third parties | ACB-EXT-004 |
| ID.RA-09 | The authenticity and integrity of hardware and software are assessed prior to acquisition and use | ACB-EXT-001, ACB-EXT-002, ACB-EXT-003, ACB-GEN-001, ACB-GEN-002, ACB-GEN-004, ACB-SKILL-003 |
| PR.AA-01 | Identities and credentials for authorized users, services, and hardware are managed by the organization | ACB-GEN-003 |
| PR.AA-05 | Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, and incorporate the principles of least privilege and separation of duties | ACB-CFG-001, ACB-CFG-002, ACB-CFG-004, ACB-INSTR-001, ACB-INSTR-002, ACB-INSTR-003, ACB-SKILL-002 |
| PR.PS-01 | Configuration management practices are established and applied | ACB-CFG-001, ACB-CFG-003, ACB-GEN-002, ACB-INSTR-002, ACB-SKILL-001 |
| PR.PS-05 | Installation and execution of unauthorized software are prevented | ACB-CFG-002, ACB-CFG-003, ACB-EXT-002, ACB-GEN-001, ACB-SKILL-003 |
| PR.PS-06 | Secure software development practices are integrated, and their performance is monitored throughout the software development life cycle | ACB-EXT-004 |
