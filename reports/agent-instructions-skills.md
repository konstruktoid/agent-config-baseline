# Baseline audit: konstruktoid/agent-instructions-skills

| Field | Value |
| --- | --- |
| Repository | https://github.com/konstruktoid/agent-instructions-skills |
| Commit audited | `db098c2e039c6fc8f0bfc3c0ab5dc4352d31faa0` (2026-10-15T10:26:56+02:00) |
| Checker | `acb` 0.1.0 at `433b53bcee72db62d15cbc466162aeb4a941455c` of this repository; the only uncommitted change was this report |
| Profile | `strict-general` |
| Command | `acb check ../t --format json`, run from an empty directory: no `--config`, no `--exceptions`; the default bundled client data (`claude-code`) was loaded |
| Target | `git archive db098c2` extracted to a fresh directory, so the audited clone was not touched and no `.git` directory was scanned |
| Audited on | 2026-10-24 |
| Inventory | 10 skills, 0 instruction files, 0 MCP declarations, 0 extension packages, 0 agent settings files; nothing unscanned, nothing excluded |

No exceptions were added on behalf of the audited repository. This report
replaces the 2026-10-23 report of the same commit, which was produced when
`ACB-PROV-001` expected one record at the repository root; the difference is
described under "Changes since the previous report".

Instruction files and MCP declarations: none were found, so the controls that
apply to them evaluated this repository's skills only. `ACB-INSTR-001/bypass-flags`
and `ACB-INSTR-002/config-write-scripts` reported `not-applicable`; the
checker's message is "no client-declared … in scope", which means nothing in
the target gave them input to check.

## Summary

| Control | Result |
| --- | --- |
| ACB-GEN-001 | fail |
| ACB-GEN-002 | fail |
| ACB-GEN-003 | pass |
| ACB-GEN-004 | pass |
| ACB-INSTR-001 | fail |
| ACB-INSTR-002 | fail |
| ACB-INSTR-003 | pass |
| ACB-PROV-001 | fail |
| ACB-SKILL-001 | fail |
| ACB-SKILL-002 | pass |
| ACB-SKILL-003 | fail |

7 of 11 applicable controls failed; 33 individual findings in total. The other 12 controls are not applicable to this target. See Observations before reading this as a severity ranking.

## Findings

### ACB-GEN-001 — `fail`

| Audit | File | Line | Message |
| --- | --- | --- | --- |
| `pipe-to-interpreter` | `skills/bash/bash-secure-scripting/SKILL.md` | 117 | remote fetch piped or substituted into an interpreter: 'curl … \| bash' |
| `pipe-to-interpreter` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 146 | remote fetch piped or substituted into an interpreter: 'curl … \| bash' |
| `pipe-to-interpreter` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 146 | remote fetch piped or substituted into an interpreter: 'wget -O - … \| sh' |
| `pipe-to-interpreter` | `skills/github/github-actions-security/references/supply-chain.md` | 91 | remote fetch piped or substituted into an interpreter: 'curl ... \| bash' |

### ACB-GEN-002 — `fail`

| Audit | File | Line | Message |
| --- | --- | --- | --- |
| `lockfile-or-hash` | `skills/github/github-actions-security/SKILL.md` | 249 | pinned install 'uvx "zizmor@1.29.' has no bundled lockfile, hash flag or digest check near this invocation in this artifact |
| `downloads-verified` | `skills/github/github-actions-security/references/untrusted-input.md` | 26 | fetched URL has no nearby digest verification and no commit hash: 'https://attacker.example/$(echo' |

### ACB-GEN-003 — `pass`

No findings.

### ACB-GEN-004 — `pass`

No findings.

### ACB-INSTR-001 — `fail`

| Audit | File | Line | Message |
| --- | --- | --- | --- |
| `safety-disable` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 148 | instruction disables a verification mechanism: 'curl -k' |
| `safety-disable` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 148 | instruction disables a verification mechanism: 'wget --no-check-certificate' |

### ACB-INSTR-002 — `fail`

| Audit | File | Line | Message |
| --- | --- | --- | --- |
| `config-write-directives` | `skills/github/github-actions-security/references/agentic-workflows.md` | 223 | instruction directs writing to agent configuration: 'write` on the agent job\n- [ ] Agent configuration' |
| `config-write-directives` | `skills/github/github-actions-security/references/untrusted-input.md` | 147 | instruction directs writing to agent configuration: 'write access.\n\n## Fork pull request settings' |
| `config-write-directives` | `skills/terraform/terraform-secure-iac/SKILL.md` | 70 | instruction directs writing to agent configuration: 'Write or modify the configuration' |

### ACB-INSTR-003 — `pass`

No findings.

### ACB-PROV-001 — `fail`

| Audit | File | Line | Message |
| --- | --- | --- | --- |
| `record-present` | `skills/ansible/ansible-verification-loop` | - | .acb-provenance.yaml does not exist in the artifact directory |
| `record-present` | `skills/bash/bash-secure-scripting` | - | .acb-provenance.yaml does not exist in the artifact directory |
| `record-present` | `skills/bash/bash-testing` | - | .acb-provenance.yaml does not exist in the artifact directory |
| `record-present` | `skills/github/github-actions-security` | - | .acb-provenance.yaml does not exist in the artifact directory |
| `record-present` | `skills/github/github-organization-governance` | - | .acb-provenance.yaml does not exist in the artifact directory |
| `record-present` | `skills/github/github-repository-security` | - | .acb-provenance.yaml does not exist in the artifact directory |
| `record-present` | `skills/python/python-secure-coding` | - | .acb-provenance.yaml does not exist in the artifact directory |
| `record-present` | `skills/python/python-testing` | - | .acb-provenance.yaml does not exist in the artifact directory |
| `record-present` | `skills/terraform/terraform-secure-iac` | - | .acb-provenance.yaml does not exist in the artifact directory |
| `record-present` | `skills/terraform/terraform-testing` | - | .acb-provenance.yaml does not exist in the artifact directory |

### ACB-SKILL-001 — `fail`

| Audit | File | Line | Message |
| --- | --- | --- | --- |
| `optional-fields` | `skills/ansible/ansible-verification-loop/SKILL.md` | - | unknown top-level frontmatter key 'capabilities' |
| `optional-fields` | `skills/bash/bash-secure-scripting/SKILL.md` | - | unknown top-level frontmatter key 'capabilities' |
| `optional-fields` | `skills/bash/bash-testing/SKILL.md` | - | unknown top-level frontmatter key 'capabilities' |
| `optional-fields` | `skills/github/github-actions-security/SKILL.md` | - | unknown top-level frontmatter key 'capabilities' |
| `optional-fields` | `skills/github/github-organization-governance/SKILL.md` | - | unknown top-level frontmatter key 'capabilities' |
| `optional-fields` | `skills/github/github-repository-security/SKILL.md` | - | unknown top-level frontmatter key 'capabilities' |
| `optional-fields` | `skills/python/python-secure-coding/SKILL.md` | - | unknown top-level frontmatter key 'capabilities' |
| `optional-fields` | `skills/python/python-testing/SKILL.md` | - | unknown top-level frontmatter key 'capabilities' |
| `optional-fields` | `skills/terraform/terraform-secure-iac/SKILL.md` | - | unknown top-level frontmatter key 'capabilities' |
| `optional-fields` | `skills/terraform/terraform-testing/SKILL.md` | - | unknown top-level frontmatter key 'capabilities' |

### ACB-SKILL-002 — `pass`

No findings.

### ACB-SKILL-003 — `fail`

| Audit | File | Line | Message |
| --- | --- | --- | --- |
| `references-contained` | `skills/github/github-repository-security/references/scorecard.md` | 58 | reference '../../github-actions-security/references/supply-chain.md' contains a `..` path segment |
| `references-contained` | `skills/github/github-repository-security/references/scorecard.md` | 151 | reference '../../github-actions-security/references/supply-chain.md' contains a `..` path segment |

## Observations

This target is a library of security-review skills, so its text discusses the
very patterns the baseline looks for. Static pattern matching (PROMPT.md
ground rule 5 forbids model calls) cannot tell an instruction from a warning
against it. All 33 findings were checked against the source.

**Genuine findings under the controls as written**

- `ACB-SKILL-001` `optional-fields` (10): every skill carries a top-level
  `capabilities` frontmatter key. It is systematic, so it reads as a
  deliberate convention of this library, but it is not a key the Agent Skills
  specification defines; the specification's extension point is `metadata`.
- `ACB-GEN-002` `lockfile-or-hash` (1, `skills/github/github-actions-security/SKILL.md:249`):
  `uvx "zizmor@1.29.0"` is pinned to an exact version but nothing in the
  artifact supplies an integrity check.
- `ACB-SKILL-003` `references-contained`, two `..` references
  (`skills/github/github-repository-security/references/scorecard.md:58,151`):
  a relative link into another skill's directory. It resolves and works, but
  it crosses the per-skill boundary the control defines. Whether that is
  acceptable for co-maintained skills in one repository is a reviewer's call.
- `ACB-PROV-001` `record-present` (10, one per skill): no skill directory
  contains a `.acb-provenance.yaml`, so none of the 10 skills has a provenance
  record.
  This is a finding about missing evidence, not evidence of tampering. The
  control is a draft, and it checks that a record exists and is well formed;
  it does not check that the digest matches the content or that anyone signed
  it. The record location, one file in each skill directory, is decided in
  `docs/provenance-design.md` section 6, question 1; a record anywhere else
  would not count.

**False positives (the checker's limitation, not the target's problem)**

- `ACB-GEN-001` `pipe-to-interpreter` (4) and `ACB-INSTR-001` `safety-disable`
  (2): every hit sits in prose telling the reader never to do it ("Never
  `curl … | bash`", "Never disable certificate verification (`curl -k`…)").
  Negation is invisible to pattern matching.
- `ACB-INSTR-002` `config-write-directives` (3): two unrelated words fell
  inside the pattern's window ("Write or modify the configuration" in a
  Terraform workflow; "write access" followed by a heading containing
  "settings"; a permissions checklist next to "Agent configuration").
- `ACB-GEN-002` `downloads-verified` (1,
  `references/untrusted-input.md:26`): `https://attacker.example/$(echo` is
  the payload in an injection example, not a fetch the skill performs.

## Changes since the previous report

The previous report of this commit (2026-10-23) also listed 33 findings, and
the target is unchanged. `ACB-PROV-001` now looks for a record in each skill
directory instead of one at the repository root, so its 10 findings name the
same skills with the message "does not exist in the artifact directory". The
other 23 findings are the same as before, in the same files and lines.

## Limits of this run

- Only skills were evaluated: no instruction files, MCP declarations,
  extension packages or agent settings files exist in this repository, so the
  controls covering those evaluated nothing for them.
- All 23 controls are `check_type: static`. `ACB-PROV-001` checks that a
  provenance record exists and is well formed. Nothing here checks who
  published a skill, whether a release was signed, or whether the content
  matches the recorded digest. A pass says nothing about authenticity.
- The audit is of one commit. The audited repository has moved on (its HEAD
  at the time of this run was `3fd7640b7d4fd07a725453cdbf79b3819861ed27`);
  this report was not re-measured against it.
