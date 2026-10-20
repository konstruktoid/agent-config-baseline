# Baseline audit: konstruktoid/agent-instructions-skills

| Field | Value |
| --- | --- |
| Repository | https://github.com/konstruktoid/agent-instructions-skills |
| Commit audited | `db098c2e039c6fc8f0bfc3c0ab5dc4352d31faa0` (2026-10-15T10:26:56+02:00) |
| Checker | `acb` 0.1.0, from an uncommitted working tree (this repository has no commits yet, so the checker has no commit hash) |
| Profile | `strict-general` |
| Command | `acb check ../repo --format json`, run from an empty directory: no `--config`, no `--exceptions`, no `--clients` (bundled client data is empty) |
| Audited on | 2026-10-19 |
| Inventory | 10 skills, 0 instruction files, 0 MCP declarations; nothing unscanned, nothing excluded |

The audited repository was not modified, and no exceptions were added on its
behalf. This report replaces an earlier run of the same commit made with an
older checker; the difference is described under "Changes since the first run".

Instruction files and MCP declarations: none were found, so the controls that
apply to them evaluated this repository's skills only. The two
client-data-dependent audits (`ACB-INSTR-001/bypass-flags` and the client half
of `ACB-INSTR-002/config-write-scripts`) are not applicable because no client
data is loaded; they checked nothing.

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

6 of 10 controls failed; 121 individual findings in total. See Observations before reading this as a severity ranking.

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
| `downloads-verified` | `skills/github/github-actions-security/references/untrusted-input.md` | 26 | fetched URL has no nearby digest verification and no commit hash: 'https://attacker.example/$(echo' |
| `lockfile-or-hash` | `skills/github/github-actions-security/SKILL.md` | 249 | pinned install 'uvx "zizmor@1.29.' has no bundled lockfile, hash flag or digest check near this invocation in this artifact |

### ACB-GEN-003 — `pass`

No findings.

### ACB-GEN-004 — `pass`

No findings.

### ACB-INSTR-001 — `fail`

| Audit | File | Line | Message |
| --- | --- | --- | --- |
| `safety-disable` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 148 | instruction disables a verification mechanism: 'curl -k' |
| `safety-disable` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 148 | instruction disables a verification mechanism: 'wget --no-check-certificate' |

Not applicable: `bypass-flags` — no client-declared permission-bypass flags in scope (no client data loaded).

### ACB-INSTR-002 — `fail`

| Audit | File | Line | Message |
| --- | --- | --- | --- |
| `config-write-directives` | `skills/github/github-actions-security/references/agentic-workflows.md` | 223 | instruction directs writing to agent configuration: 'write` on the agent job\n- [ ] Agent configuration' |
| `config-write-directives` | `skills/github/github-actions-security/references/untrusted-input.md` | 147 | instruction directs writing to agent configuration: 'write access.\n\n## Fork pull request settings' |
| `config-write-directives` | `skills/terraform/terraform-secure-iac/SKILL.md` | 70 | instruction directs writing to agent configuration: 'Write or modify the configuration' |

Not applicable: `config-write-scripts` — no client-declared configuration locations in scope (no client data loaded); writes to instruction-file names were checked.

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
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 85 | reference '/molecule/' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 85 | reference '/' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 138 | reference '/' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 149 | reference '/' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 151 | reference '/' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 161 | reference '/dev/null' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 161 | reference '/dev/null' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 167 | reference '/dev/null' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 172 | reference '/dev/null' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 204 | reference '/' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 208 | reference '/' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 210 | reference '/' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 221 | reference '/*.tar.gz' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/SKILL.md` | 226 | reference '/$' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/references/artifact-hygiene.md` | 96 | reference '/$' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/references/yaml-quoting.md` | 66 | reference '/' is an absolute path |
| `references-contained` | `skills/ansible/ansible-verification-loop/references/yaml-quoting.md` | 67 | reference '/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/SKILL.md` | 131 | reference '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/SKILL.md` | 138 | reference '/var/backups/logs' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/SKILL.md` | 178 | reference '/var/log/${service}' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/SKILL.md` | 220 | reference '/var/log' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/SKILL.md` | 221 | reference '/var/backups' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/SKILL.md` | 234 | reference '/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/SKILL.md` | 240 | reference '/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/SKILL.md` | 246 | reference '/tmp' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/SKILL.md` | 309 | reference '/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/environment.md` | 22 | reference '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/environment.md` | 31 | reference '/usr/sbin/iptables' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/environment.md` | 61 | reference '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/environment.md` | 62 | reference '/usr/local/sbin/privileged-helper' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/environment.md` | 65 | reference '${HOME}' is a home-directory reference, outside the skill directory |
| `references-contained` | `skills/bash/bash-secure-scripting/references/environment.md` | 131 | reference '/dev/null' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/environment.md` | 168 | reference '/usr/bin:/bin' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/environment.md` | 185 | reference '~/.bashrc' is a home-directory reference, outside the skill directory |
| `references-contained` | `skills/bash/bash-secure-scripting/references/environment.md` | 185 | reference '/etc/profile' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/error-handling.md` | 99 | reference '/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/error-handling.md` | 99 | reference '/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/error-handling.md` | 226 | reference '/var/lock/${0##*/}.lock' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/error-handling.md` | 246 | reference '/dev/null' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 27 | reference '/tmp/build.$$' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 69 | reference '/?*' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 75 | reference '/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 77 | reference '/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 77 | reference '//' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 77 | reference '..' contains a `..` path segment |
| `references-contained` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 77 | reference '${HOME}' is a home-directory reference, outside the skill directory |
| `references-contained` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 77 | reference '/tmp/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/filesystem.md` | 82 | reference '/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/secrets.md` | 18 | reference '/proc/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/secrets.md` | 18 | reference '/cmdline' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/secrets.md` | 39 | reference '/proc/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/secrets.md` | 39 | reference '/environ' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/secrets.md` | 95 | reference '/var/log/script.trace' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/secrets.md` | 95 | reference '/tmp' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/secrets.md` | 135 | reference '/dev/urandom' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/secrets.md` | 138 | reference '/dev/urandom' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/secrets.md` | 143 | reference '/dev/urandom' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/secrets.md` | 148 | reference '/dev/urandom' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/secrets.md` | 175 | reference '/path/to/project' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/secrets.md` | 176 | reference '$HOME' is a home-directory reference, outside the skill directory |
| `references-contained` | `skills/bash/bash-secure-scripting/references/untrusted-input.md` | 42 | reference '/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/untrusted-input.md` | 105 | reference '/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/untrusted-input.md` | 131 | reference '..' contains a `..` path segment |
| `references-contained` | `skills/bash/bash-secure-scripting/references/untrusted-input.md` | 139 | reference '/' is an absolute path |
| `references-contained` | `skills/bash/bash-secure-scripting/references/untrusted-input.md` | 181 | reference '/proc' is an absolute path |
| `references-contained` | `skills/github/github-actions-security/SKILL.md` | 239 | reference '/repo' is an absolute path |
| `references-contained` | `skills/github/github-actions-security/references/permissions-and-secrets.md` | 105 | reference '/home/runner/work/' is an absolute path |
| `references-contained` | `skills/github/github-actions-security/references/permissions-and-secrets.md` | 105 | reference '/' is an absolute path |
| `references-contained` | `skills/github/github-actions-security/references/runners.md` | 138 | reference '/dev/kvm' is an absolute path |
| `references-contained` | `skills/github/github-actions-security/references/runners.md` | 149 | reference '/etc/udev/rules.d/99-kvm.rules' is an absolute path |
| `references-contained` | `skills/github/github-actions-security/references/runners.md` | 149 | reference '/dev/null' is an absolute path |
| `references-contained` | `skills/github/github-actions-security/references/runners.md` | 165 | reference '/dev/kvm' is an absolute path |
| `references-contained` | `skills/github/github-actions-security/references/runners.md` | 165 | reference '/dev/kvm' is an absolute path |
| `references-contained` | `skills/github/github-actions-security/references/supply-chain.md` | 124 | reference '/' is an absolute path |
| `references-contained` | `skills/github/github-actions-security/references/supply-chain.md` | 187 | reference '/' is an absolute path |
| `references-contained` | `skills/github/github-repository-security/references/agent-content.md` | 63 | reference '/.github/CODEOWNERS' is an absolute path |
| `references-contained` | `skills/github/github-repository-security/references/rulesets.md` | 40 | reference '~DEFAULT_BRANCH' is a home-directory reference, outside the skill directory |
| `references-contained` | `skills/github/github-repository-security/references/rulesets.md` | 41 | reference '~ALL' is a home-directory reference, outside the skill directory |
| `references-contained` | `skills/github/github-repository-security/references/rulesets.md` | 226 | reference '~DEFAULT_BRANCH' is a home-directory reference, outside the skill directory |
| `references-contained` | `skills/github/github-repository-security/references/scorecard.md` | 58 | reference '../../github-actions-security/references/supply-chain.md' contains a `..` path segment |
| `references-contained` | `skills/github/github-repository-security/references/scorecard.md` | 151 | reference '../../github-actions-security/references/supply-chain.md' contains a `..` path segment |
| `references-contained` | `skills/python/python-secure-coding/SKILL.md` | 47 | reference '/' is an absolute path |
| `references-contained` | `skills/python/python-secure-coding/SKILL.md` | 60 | reference '/' is an absolute path |
| `references-contained` | `skills/python/python-secure-coding/SKILL.md` | 91 | reference '/' is an absolute path |
| `references-contained` | `skills/python/python-secure-coding/SKILL.md` | 145 | reference '/' is an absolute path |
| `references-contained` | `skills/python/python-secure-coding/SKILL.md` | 145 | reference '/' is an absolute path |
| `references-contained` | `skills/python/python-secure-coding/SKILL.md` | 146 | reference '/' is an absolute path |
| `references-contained` | `skills/python/python-secure-coding/SKILL.md` | 149 | reference '/' is an absolute path |
| `references-contained` | `skills/python/python-secure-coding/references/secrets.md` | 39 | reference '/home/' is an absolute path |
| `references-contained` | `skills/python/python-secure-coding/references/secrets.md` | 39 | reference '/Users/' is an absolute path |
| `references-contained` | `skills/python/python-secure-coding/references/secrets.md` | 52 | reference '/path/to/project' is an absolute path |
| `references-contained` | `skills/python/python-testing/SKILL.md` | 74 | reference '/' is an absolute path |
| `references-contained` | `skills/python/python-testing/SKILL.md` | 142 | reference '/' is an absolute path |
| `references-contained` | `skills/terraform/terraform-secure-iac/SKILL.md` | 59 | reference '/' is an absolute path |
| `references-contained` | `skills/terraform/terraform-secure-iac/SKILL.md` | 59 | reference '/' is an absolute path |
| `references-contained` | `skills/terraform/terraform-secure-iac/SKILL.md` | 88 | reference '/' is an absolute path |
| `references-contained` | `skills/terraform/terraform-secure-iac/SKILL.md` | 95 | reference '/' is an absolute path |
| `references-contained` | `skills/terraform/terraform-secure-iac/SKILL.md` | 95 | reference '/' is an absolute path |
| `references-contained` | `skills/terraform/terraform-testing/SKILL.md` | 82 | reference '/' is an absolute path |
| `references-contained` | `skills/terraform/terraform-testing/SKILL.md` | 82 | reference '/' is an absolute path |

## Observations

This target is a library of security-review skills, so its text discusses the
very patterns the baseline looks for. Static pattern matching (PROMPT.md
ground rule 5 forbids model calls) cannot tell an instruction from a warning
against it. Each finding group below was checked against the source (all of the small groups, and a sample of the 100-row group).

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
**`ACB-SKILL-003` `references-contained` (100 findings, 98 of them false positives)**

All but the two cross-skill links above are false positives: 96 are
absolute-path examples in hardening prose (`/dev/null`, `/etc/profile`, `/var/log`, `/proc/…`, PATH
strings, `/tmp`) and two are a bare `..` quoted in prose about path validation
(`filesystem.md:77`, `untrusted-input.md:131`). The procedure says "no file reference … is absolute", and
the checker reads any slash-containing token as a reference. Whether a path
mentioned in documentation is a "file reference" of the skill is a
question about the procedure's meaning, not something the checker can
settle. **This needs a decision from the control's owner**: either narrow the
procedure to references the skill resolves (markdown links, `scripts/…`
invocations) or accept that skills documenting filesystem hardening cannot
pass. It is not a tuning problem, and it has not been silently reinterpreted.

**Changes since the first run of this commit**

An earlier run reported 168 findings. This one reports 121 for the same commit.
The checker gained detection (GEN-003 token formats and entropy, GEN-002
MCP structure, INSTR-003 link titles, wider GEN-001/INSTR-001 coverage, and
discovery of case-variant, JSONC and nested MCP files), which is why the target
is no longer clean on controls it passed before. The first re-run after those
changes produced 208 findings, and nearly all of the increase over the first run was
false positives that the new patterns introduced. They were fixed in the
checker before this report was written, with a regression test for each:
URL and path fragments read as high-entropy secrets (11); an ellipsis in a code
block read as a non-ASCII command name (21); an inline `` `curl` `` read as a
command substitution (25); `pip install -r requirements.txt` followed by
prose read as several unpinned packages (12); prose such as "image: a" and
Python's `from x import y` read as container images (15); a YAML list of tool
names read as an invocation (2).

## Limits of this run

- Only skills were evaluated: no instruction files or MCP declarations exist
  in this repository, so the controls covering those evaluated nothing for them.
- No client data was loaded, so permission-bypass flags and client
  configuration locations were not checked.
- The checker version is not reproducible from a commit hash because this
  repository has no commits yet.
