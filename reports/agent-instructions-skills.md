# Baseline audit: konstruktoid/agent-instructions-skills

| Field | Value |
| --- | --- |
| Repository | https://github.com/konstruktoid/agent-instructions-skills |
| Commit audited | `db098c2e039c6fc8f0bfc3c0ab5dc4352d31faa0` (2026-10-15T10:26:56+02:00) |
| Checker | `acb` 0.1.0 at `ae50294fd7050b92c817c84c1b8e9239b7459158` of this repository, clean working tree |
| Profile | `strict-general` |
| Command | `acb check ../t --format json`, run from an empty directory: no `--config`, no `--exceptions`; the default bundled client data (`claude-code`) was loaded |
| Target | `git archive db098c2` extracted to a fresh directory, so the audited clone was not touched and no `.git` directory was scanned |
| Audited on | 2026-10-22 |
| Inventory | 10 skills, 0 instruction files, 0 MCP declarations, 0 extension packages, 0 agent settings files; nothing unscanned, nothing excluded |

No exceptions were added on behalf of the audited repository. This report
replaces the 2026-10-19 report of the same commit, which was produced from an
uncommitted checker; the difference is described under "Changes since the
previous report".

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
| ACB-SKILL-001 | fail |
| ACB-SKILL-002 | pass |
| ACB-SKILL-003 | fail |

6 of 10 applicable controls failed; 24 individual findings in total. The other 12 controls are not applicable to this target. See Observations before reading this as a severity ranking.

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
| `references-contained` | `skills/bash/bash-secure-scripting/references/environment.md` | 185 | reference '~/.bashrc' is a home-directory reference, outside the skill directory |
| `references-contained` | `skills/github/github-repository-security/references/scorecard.md` | 58 | reference '../../github-actions-security/references/supply-chain.md' contains a `..` path segment |
| `references-contained` | `skills/github/github-repository-security/references/scorecard.md` | 151 | reference '../../github-actions-security/references/supply-chain.md' contains a `..` path segment |

## Observations

This target is a library of security-review skills, so its text discusses the
very patterns the baseline looks for. Static pattern matching (PROMPT.md
ground rule 5 forbids model calls) cannot tell an instruction from a warning
against it. All 24 findings were checked against the source.

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

**Open question for the control's owner**

- `ACB-SKILL-003` `references-contained` (1,
  `skills/bash/bash-secure-scripting/references/environment.md:185`):
  `~/.bashrc` appears in the sentence "Non-interactive shells do not read
  `~/.bashrc` or `/etc/profile`". It describes the host, not a file the skill
  reads. The procedure lists "a home-directory path" as a file reference and
  exempts only absolute paths outside a link, so by its text this is a
  finding, and `/etc/profile` in the same sentence is not. Either the
  exemption should cover home-directory paths in prose too, or the finding
  stands. It has not been reinterpreted.

## Changes since the previous report

The previous report of this commit (2026-10-19) listed 121 findings; this one
lists 24. The target is unchanged. Both differences are in the checker:

- `ACB-SKILL-003` fell from 100 findings to 3. The control's procedure now
  defines a file reference (a link or reference-definition target, a file URI,
  a home-directory path or a relative path) and exempts absolute paths outside
  links, so the 96 absolute-path examples in hardening prose
  (`/dev/null`, `/etc/profile`, `/var/log`, `/proc/…`, PATH strings, `/tmp`) and
  the two bare `..` tokens in prose about path validation are no longer
  reported. The previous report's request for a decision on this control is
  resolved by that change.
- The other controls report the same 21 findings as before, with the same
  files and lines.
- The checker is now identified by a commit, and the default client data
  (`claude-code`) is loaded instead of an empty `clients/`. Nothing in this
  target is in scope of client data, so this did not change any result.

## Limits of this run

- Only skills were evaluated: no instruction files, MCP declarations,
  extension packages or agent settings files exist in this repository, so the
  controls covering those evaluated nothing for them.
- All 22 controls are `check_type: static`. Nothing here checks who published
  a skill, whether a release was signed, or whether the content matches an
  attested build. A clean result says nothing about provenance.
- The audit is of one commit. The audited repository has moved on (its HEAD
  at the time of this run was `3fd7640b7d4fd07a725453cdbf79b3819861ed27`);
  this report was not re-measured against it.
