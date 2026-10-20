# Build prompt: agent-config-baseline v0.1

Use this prompt with any coding agent working in a clone of
`github.com/konstruktoid/agent-config-baseline`. It assumes `schema/` and
`controls/` already contain the files committed with it.

---

You are implementing v0.1 of **agent-config-baseline**, a strict,
vendor-neutral security baseline for the files that configure AI agents.
It is to agent configuration what a CIS Benchmark is to an operating
system: a set of controls, each with a rationale, an audit procedure and a
remediation, plus a checker that evaluates them.

## Ground rules

1. **Vendor neutrality is a hard requirement.** Controls are defined
   against open specifications only: the Agent Skills specification
   (agentskills.io), the AGENTS.md convention, and the Model Context
   Protocol. No control, field name, profile or default may depend on a
   single product. Client-specific facts (configuration file locations,
   permission-bypass flags, alternative instruction-file names) live in
   data files under `clients/`, one file per client, and every client is
   optional. The checker must produce correct results with `clients/`
   empty.
2. **There is one profile: `strict-general`.** Every active control must
   pass. Severity only maps to SARIF level. Do not add L1/L2 tiers.
3. **Controls are data.** The YAML files in `controls/` are the source of
   truth. Documentation is generated from them; never hand-edit generated
   docs. Do not change control IDs. Do not renumber. Retired controls
   become `status: deprecated` with `deprecated_by`.
4. **Do not invent references.** OWASP ASI IDs in the controls come from
   the OWASP Top 10 for Agentic Applications 2026. OWASP AST IDs come from
   the OWASP Agentic Skills Top 10 (August 2026); only AST02 (supply chain
   compromise) has been verified so far. Before adding any other AST ID,
   read the published document and confirm the mapping. If you cannot
   access it, leave the field out and open a TODO in `docs/mappings.md`.
   Do not copy OWASP prose: it is CC BY-SA 4.0 and would propagate
   share-alike. Map by ID only.
5. **No model calls in the checker.** Every audit procedure must be
   implementable with parsing, inventory and pattern matching. If a
   procedure cannot be implemented that way, report it rather than
   approximating it with a heuristic you cannot test.
6. **This repository must pass its own baseline.** The prompt you are
   reading, the README and every file you add are subject to the controls.
   The only paths excluded from evaluation are `controls/` and
   `tests/fixtures/`, because they contain failing examples by design; the
   exclusion is explicit in the checker's default configuration, not
   hard-coded.

## Deliverables

### 1. Repository scaffolding
- `README.md`. The first paragraph states scope: Agent Skills directories,
  agent instruction files (AGENTS.md and functionally equivalent files
  declared in client data), and MCP server declarations. The second
  paragraph states what is out of scope: model robustness, runtime
  isolation, agent identity, inter-agent protocols.
- `LICENSE` (Apache-2.0) for code and `LICENSE-CONTENT` (CC-BY-4.0) for
  control text, with a note in the README explaining the split.
- `CONTRIBUTING.md` describing the control lifecycle (draft, active,
  deprecated), the ID rules, and that every new audit procedure needs a
  passing and a failing fixture.

### 2. Schema validation
- Validate every file in `controls/` against
  `schema/control.schema.json` in CI. A control that fails validation
  fails the build.
- Add a uniqueness check for control IDs and audit procedure IDs within
  a control.

### 3. Checker (`acb`)
- Python 3.12+, standard library plus `PyYAML` and `jsonschema`, all
  pinned with hashes. Package with `pyproject.toml`.
- CLI: `acb check PATH [--format text|json|sarif] [--exceptions FILE]
  [--clients DIR]`. Exit 0 only if every applicable control passes.
- Discovery:
  - a skill is any directory containing `SKILL.md`;
  - an instruction file is `AGENTS.md` at any depth, plus filenames
    declared in client data;
  - an MCP server declaration is any JSON or YAML file containing a
    top-level `mcpServers` or `servers` mapping whose entries have a
    `command` or `url` field, plus locations declared in client data.
- One module per control under `acb/controls/`, named by ID, each
  implementing every audit procedure in that control's YAML. A control
  whose procedures are not all implemented is reported as `not-evaluated`,
  never as `pass`.
- Results reference control ID, audit procedure ID, file path and line.
- SARIF 2.1.0 output with one rule per control, `helpUri` pointing at the
  generated docs, and severity mapped high=error, medium=warning,
  low=note.

### 4. Exceptions
- Exceptions live in a single reviewed file, default
  `.acb-exceptions.yaml`. Each entry has control ID, path, justification,
  approver and expiry date.
- Expired exceptions fail the check.
- Controls with `exceptions: not-permitted` ignore exception entries and
  report the attempt.
- There is no inline suppression syntax. Do not add one.

### 5. Tests
- Under `tests/fixtures/<CONTROL-ID>/<audit-id>/pass/` and `.../fail/`,
  at least one minimal artifact each. Every `indicators` entry in a
  control appears in at least one failing fixture.
- Run the test suite and the self-check in CI.

### 6. CI
- A GitHub Actions workflow that runs schema validation, tests and
  `acb check .` on pull requests and pushes. Pin every action by full
  commit SHA. Use least-privilege `permissions`, with
  `security-events: write` only on the job that uploads SARIF.
- A reusable workflow or composite action so other repositories can run
  `acb` and upload SARIF to code scanning.

### 7. Generated documentation
- `docs/controls/<ID>.md` generated from the YAML, plus an index table
  with ID, title, applies-to, severity and OWASP mappings.
- `docs/mappings.md` with an ASI/AST coverage matrix and the TODO list
  for unverified mappings.

## First audited target

After the self-check passes, run `acb check` against a clone of
`github.com/konstruktoid/agent-instructions-skills` and write the results
to `reports/agent-instructions-skills.md`: commit hash audited, checker
version, per-control results, and every failure with file and line.
Publish failures as found. Do not modify the audited repository and do
not add exceptions on its behalf.

## Working method

- Work in small commits, one deliverable per commit.
- When a control's audit procedure is ambiguous, contradictory or not
  implementable as written, stop and report the specific procedure and
  the problem instead of choosing an interpretation silently.
- When you are unsure whether a fact about a client is accurate, leave
  it out of `clients/` and note it in your summary.
- Finish with a summary that lists: implemented controls, any
  `not-evaluated` procedures and why, false-positive cases you observed
  in fixtures or in the audited target, and suggested control changes.
