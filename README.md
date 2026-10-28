# agent-config-baseline

A strict, vendor-neutral security baseline for the files that configure AI
agents: Agent Skills directories (`SKILL.md` and their bundled content),
agent instruction files (`AGENTS.md` and functionally equivalent files
declared per client), Model Context Protocol server declarations, agent
extension packages, and committed agent permission settings. It is
to agent configuration what a CIS Benchmark is to an operating system: a set
of controls, each with a rationale, an audit procedure and a remediation,
plus a checker (`acb`) that evaluates them.

Out of scope: model robustness, runtime isolation, agent identity, and
inter-agent protocols. This baseline evaluates the configuration artifacts
an agent loads, not the model that interprets them, the sandbox it runs in,
how it authenticates, or how agents communicate with each other. Where a
control depends on the agent's permission configuration, it checks the
configuration file, not the running host.

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

### Vendor-neutral controls, implementation-specific audits

Each control states a requirement in product-neutral terms. How a given
client meets or breaks it (file names, settings keys, rule syntax, event
names, the command that lists an extension's capabilities) lives in that
client's data file, with the documentation URL for every fact. The checker
reads the data; the controls never name a product. The generated page for
each control lists each client's implementation notes under its audit
procedures, so an auditor sees the generic requirement and the concrete
check for their client side by side. `clients/claude-code.yaml` is the
first such file. Extension packages and agent settings have no open
specification, so the EXT and CFG controls find nothing to evaluate unless
client data describes where they live.

## Control families

- `SKILL`, `INSTR`, `GEN`: skills, instruction files, and requirements
  common to skills, instruction files and MCP server declarations.
- `MCP`: MCP server declarations. Remote servers use TLS and declare
  authentication (ACB-MCP-001), and local servers are launched as a named
  executable, not through a shell (ACB-MCP-002), with no process-startup
  hijack variables in the server's environment (ACB-MCP-003).
- `EXT`: extension packages, the plugin or extension bundles an agent host
  installs. Some hosts load extension code into their own process with the
  user's privileges, outside the sandbox that isolates the agent's commands,
  where it can see and rewrite prompts and tool calls and, depending on
  host configuration, approve tool calls other rules would stop. These
  controls require that such code is declared (ACB-EXT-001), kept out of
  packages that present as content (ACB-EXT-002), recorded so a reviewer
  sees capability changes in a diff (ACB-EXT-003), and that blocking guards
  are tested to deny (ACB-EXT-004).
- `CFG`: committed agent settings and managed policy. The agent's own
  configuration, extensions and instructions are protected from its file
  tools (ACB-CFG-001), extension installation stays a human decision
  (ACB-CFG-002), blocking policy lives in a
  managed layer user-installed extensions cannot override (ACB-CFG-003);
  and the actions that need human approval are defined by configuration,
  not by instructions or extension code (ACB-CFG-004), and allow rules
  name tool server tools one by one, never a whole server (ACB-CFG-005).
  ACB-CFG-003 applies
  to managed settings files only: a repository that cannot carry managed
  policy is not its subject, and an organization audits it by running
  `acb check` on the directory that holds its deployed managed settings.

Every control maps to the risk areas of *Careful Adoption of Agentic AI
Services* (ASD's ACSC, CISA, NSA, Canadian Centre for Cyber Security,
NCSC-NZ, NCSC-UK, May 2026) and to NIST Cybersecurity Framework 2.0
subcategories, and to OWASP Top 10 lists by ID; `docs/mappings.md` has every
matrix, each ID linking to its source (a page of the PDF, or the OWASP
entry). ACB-CFG-001 follows
the incident-readiness practice that agents cannot access or interfere with
their own monitoring (NIST CAISSI, NSA SISC and CISA, October 2026).

## Compromised tool servers

A tool server that was benign when it was declared and reviewed can later
come under an attacker's control: its package publishes a malicious release,
its endpoint or domain changes hands, or its operator's credentials are
stolen. The declaration in the repository does not change, so every control
that reads it still passes. The baseline narrows what such a server can do:

- ACB-GEN-002 pins a local server's package, so a malicious release is not
  picked up without a reviewed version change.
- ACB-MCP-001 requires an encrypted endpoint and a declared authentication
  method. It checks the declaration, not whether the server enforces it.
- ACB-MCP-002 and ACB-MCP-003 keep the declaration itself from running
  code the reviewer did not see.
- ACB-CFG-005 keeps allow rules from approving tools the server adds after
  review. A tool approved by name stays approved if the server redefines it.

A static check of configuration files cannot detect the following, and
the baseline does not claim to:

- A change to a server's tool names, descriptions or input schemas after
  approval. Detecting it means starting the server and listing its tools,
  which would make the checker run the code it audits. Review the tool list
  whenever a server's pinned version changes.
- Instructions in a tool description or tool result that steer the agent
  towards another server's tools. Whether the agent follows them is model
  behaviour.
- What a remote server does with the arguments it receives, including
  file contents the agent read earlier in the session.
- What a local server process can reach. It runs with the user's
  privileges unless the host sandboxes it.
- Which servers share a session. A server that reads untrusted content
  (web pages, feeds, email, issues) in the same session as tools that write
  files, run commands or send data gives injected instructions a path to act
  and to exfiltrate; that combination is decided at run time.

Those risks need runtime defences: a sandbox with no network access and a
read-only filesystem for local servers, egress filtering on the host, and
sessions that keep servers reading untrusted content apart from tools that
write, execute or send.

## Profile

There is one profile: `strict-general`. Every active control in it must
pass. Severity only affects how a finding is reported (it maps to SARIF
`level`); it does not create tiers of required vs. optional controls.

A pass on the INSTR controls means no known phrase was found. Phrase lists
are evaded by paraphrase or translation, so treat a pass as weak evidence and
not as a review of the content.

## Layout

- `controls/` — the controls themselves, as YAML, validated against
  `schema/control.schema.json`. This is the source of truth; `docs/` is
  generated from it.
- `schema/` — the JSON Schema controls must conform to.
- `clients/` — optional, per-client data (file locations, bypass flags,
  settings keys, extension layout, implementation notes with sources),
  validated against `schema/client.schema.json` and bundled with acb.
- `src/acb/` — the checker.
- `tests/fixtures/<CONTROL-ID>/<audit-id>/{pass,fail}/` — minimal artifacts
  exercising each audit procedure.
- `docs/controls/` — generated per-control documentation and index.
- `docs/mappings.md` — generated OWASP (ASI, AST, MCP), risk-area and NIST CSF 2.0
  coverage matrices and the list of unverified mappings.
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
$ uv run acb check PATH [--format text|json|sarif] [--exceptions FILE] [--clients DIR] [--config FILE] [--provenance-records FILE] [--trust-root FILE] [--sigstore-verifier PATH] [--run-validators] [--require-artifacts]
```

`--run-validators` lets acb run the capability validator that client data
names (for example a host's own plugin validator) against each extension
package, without a shell and from an empty working directory. Static checks
always run; without the flag, or when the validator is not installed,
procedures that need it are reported as not evaluated, never as passed.

Exit status is 0 only if every applicable control passes; a control with no
artifact of the kind it applies to is reported as not applicable. Exit
status 1 means a control failed or could not be evaluated, and 2 means acb
could not run (invalid arguments, configuration or control data).

A run that finds no artifact at all passes every control as not applicable.
`--require-artifacts` turns that into exit status 1 (every control not
evaluated), so a wrong PATH cannot pass. The reusable workflow sets it by
default; its `require-artifacts` input turns it off.

## Trust model

PATH is untrusted content. Nothing inside it can change how it is judged:

| Input | Source |
| --- | --- |
| Controls and schemas | Bundled with acb. |
| Client data | acb's bundled `clients/`, or `--clients DIR`, which replaces it. |
| Operator configuration (exclusions, extra instruction files) | `--config FILE`, or `.acb.yaml` in the current working directory. |
| Exceptions | `--exceptions FILE`, or `.acb-exceptions.yaml` in the current working directory. |
| Provenance records that replace an artifact's `.acb-provenance.yaml` (`schema/provenance-records.schema.json`) | `--provenance-records FILE` only; there is no default. |
| Trust root for `ACB-PROV-003` (`schema/trust-root.schema.json`); reports record its SHA-256 | `--trust-root FILE` only; there is no default. |
| Sigstore verifier program for `ACB-PROV-003` (`verifier/`) | `--sigstore-verifier PATH` only, an absolute path; there is no default. |

Operator files are resolved against the working directory, never against
PATH, and a file passed explicitly must exist. The provenance records and
trust root have no default file name, so a scanned repository that is also
the working directory cannot supply them. Every exclusion needs a
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
reading them from the base commit, and refuses `pull_request_target`. There
the provenance records and trust root have fixed names,
`.acb-provenance-records.yaml` and `.acb-trust-root.yaml`, and when the trust
root is present the workflow installs the Sigstore verifier from `verifier/`
and passes it to `ACB-PROV-003`. It
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

## FAQ

### How does this relate to Agent Threat Rules (ATR)?

[ATR](https://github.com/Agent-Threat-Rule/agent-threat-rules) is an
MIT-licensed set of detection rules, mostly regular expressions, that match
attack content in prompts, tool calls and tool responses, with a scanner
that also reads skill and MCP files. This baseline is a set of pass/fail
configuration controls that the checker evaluates without model calls or
heuristics. The two answer different questions (is this content an attack, and
is this configuration safe to ship), so they are meant to run side by side.

### Are ATR rules part of this baseline?

No. A control is added only when it is a structural check on a configuration
artifact and cites an established source: an advisory, a CVE or a published
standard. Most ATR rules match exploit payloads for one product at run time,
which is out of scope here. ACB-MCP-003 is the one control derived from an
ATR rule (ATR-2026-02300); it cites the underlying OpenClaw advisory
(GHSA-mj59-h3q9-ghfh) and the VulnCheck record (CVE-2026-44995), not ATR
itself. The advisory says "No known CVE"; the CVE comes from VulnCheck only.

### Where do the mappings come from, and how do I check them?

Every OWASP, Five Eyes and NIST CSF ID in a control links to its source in
`docs/mappings.md` and on each control page. OWASP MCP Top 10 links point to
the entry files, Five Eyes and CSF links point to a PDF page, and OWASP AST
links point to the entry page. The OWASP Agentic Applications (ASI) links
point to the list page only, because it exposes no per-entry URLs, and ASI IDs
are not yet verified entry by entry. Only AST02 is verified (see
`docs/mappings.md`).

## Licensing

Code (`src/`, `tests/`, tooling) is licensed under Apache-2.0; see
`LICENSE`. Control content (`controls/*.yaml`, `docs/controls/*.md`,
rationale and remediation text) is licensed under CC-BY-4.0; see
`LICENSE-CONTENT`. The split exists so control text can be freely quoted
and adapted by other benchmarks with attribution, independent of the
code's license.
