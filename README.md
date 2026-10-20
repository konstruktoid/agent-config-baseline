# agent-config-baseline

A strict, vendor-neutral security baseline for the files that configure AI
agents: Agent Skills directories (`SKILL.md` and their bundled content),
agent instruction files (`AGENTS.md` and functionally equivalent files
declared per client), and Model Context Protocol server declarations. It is
to agent configuration what a CIS Benchmark is to an operating system: a set
of controls, each with a rationale, an audit procedure and a remediation,
plus a checker (`acb`) that evaluates them.

Out of scope: model robustness, runtime isolation, agent identity, and
inter-agent protocols. This baseline evaluates the configuration artifacts
an agent loads, not the model that interprets them, the sandbox it runs in,
how it authenticates, or how agents communicate with each other.

## Vendor neutrality

Every control is defined against open specifications only: the
[Agent Skills specification](https://agentskills.io/specification), the
[AGENTS.md](https://agents.md/) convention, and the
[Model Context Protocol](https://modelcontextprotocol.io/). No control,
field name, profile or default depends on a single product. Client-specific
facts — configuration file locations, permission-bypass flags, alternative
instruction-file names — live in optional data files under `clients/`, one
file per client. The checker produces correct results with `clients/`
empty; it just evaluates less client-specific surface.

## Profile

There is one profile: `strict-general`. Every active control in it must
pass. Severity only affects how a finding is reported (it maps to SARIF
`level`); it does not create tiers of required vs. optional controls.

## Layout

- `controls/` — the controls themselves, as YAML, validated against
  `schema/control.schema.json`. This is the source of truth; `docs/` is
  generated from it.
- `schema/` — the JSON Schema controls must conform to.
- `clients/` — optional, per-client data (file locations, bypass flags),
  validated against `schema/client.schema.json` and bundled with acb.
  Empty by default.
- `src/acb/` — the checker.
- `tests/fixtures/<CONTROL-ID>/<audit-id>/{pass,fail}/` — minimal artifacts
  exercising each audit procedure.
- `docs/controls/` — generated per-control documentation and index.
- `docs/mappings.md` — generated OWASP coverage matrix and the list of
  unverified mappings.
- `scripts/gen_docs.py` — generates `docs/`; `--check` fails if it is stale.
- `reports/` — audit reports of third-party repositories, published as found.
- `.github/workflows/` — CI for this repository (`ci.yml`) and the reusable
  workflow other repositories call (`acb-check.yml`).
- `.acb-exceptions.yaml` — the single reviewed exceptions file
  (`schema/exceptions.schema.json`).
- `.acb.yaml` — this repository's operator configuration for its own
  self-check (`schema/config.schema.json`).

## Usage

```console
$ uv run acb check PATH [--format text|json|sarif] [--exceptions FILE] [--clients DIR] [--config FILE]
```

Exit status is 0 only if every applicable control passes; a control with no
artifact of the kind it applies to is reported as not applicable. Exit
status 1 means a control failed or could not be evaluated, and 2 means acb
could not run (invalid arguments, configuration or control data).

## Trust model

PATH is untrusted content. Nothing inside it can change how it is judged:

| Input | Source |
| --- | --- |
| Controls and schemas | Bundled with acb. |
| Client data | acb's bundled `clients/`, or `--clients DIR`, which replaces it. |
| Operator configuration (exclusions, extra instruction files) | `--config FILE`, or `.acb.yaml` in the current working directory. |
| Exceptions | `--exceptions FILE`, or `.acb-exceptions.yaml` in the current working directory. |

Operator files are resolved against the working directory, never against
PATH, and a file passed explicitly must exist. Every exclusion needs a
reason, every exception needs a justification, approver and expiry date, and
patterns that match everything are rejected. The output of every format
lists the configuration used, each exclusion with how many entries it
removed, exceptions that matched nothing, and anything that could not be
scanned.

Operator files are only as trustworthy as where they live. When the working
directory is inside PATH (for example `acb check .` in a repository), the
scanned tree supplies its own operator files; acb prints a warning naming
them. Protect those files with review. The reusable workflow
`.github/workflows/acb-check.yml` removes that gap for pull requests by
reading them from the base commit, and refuses `pull_request_target`. It
cannot protect itself: the calling workflow file comes from the pull request
head, so guard that file with a required-workflow ruleset or CODEOWNERS. For
`push`, `merge_group` and `workflow_dispatch` there is no base commit, so use
it on pull requests when gating.

A directory symlink that resolves outside PATH, a file that looks like an MCP
declaration but cannot be parsed, or a location that client data names but acb
cannot read, makes every control not evaluated rather than silently shrinking
what was checked. A file acb cannot read is likewise not evaluated, and no
exception can waive that.

## Dependencies

`pyproject.toml` pins exact versions of `PyYAML` and `jsonschema`; `uv.lock`
records the hashes, and CI installs with `uv sync --locked`.

## Licensing

Code (`src/`, `tests/`, tooling) is licensed under Apache-2.0; see
`LICENSE`. Control content (`controls/*.yaml`, `docs/controls/*.md`,
rationale and remediation text) is licensed under CC-BY-4.0; see
`LICENSE-CONTENT`. The split exists so control text can be freely quoted
and adapted by other benchmarks with attribution, independent of the
code's license.
