# Design note: provenance controls

Status: draft for discussion. No control, schema change or checker code exists
for this yet. Nothing here has been verified against the Sigstore, in-toto or
SLSA specifications; section 6 lists what to check before any of it is
implemented.

## 1. Problem

All 22 active controls are `check_type: static`. They judge the content of a
file. None of them can say whether a skill, extension package or MCP server
package is the artifact its publisher released, built from the source the
publisher claims. `ACB-GEN-002` already requires exact pins with an integrity
check, digest verification of fetched content, or a full commit hash, and
`ACB-EXT-*` covers package contents. None of them binds the audited artifact
itself to a claimed source or publisher. The schema
already reserves `check_type: provenance` ("needs release/attestation
metadata") and no control uses it.

## 2. Constraints from the build prompt

- No model calls, and every audit must be pattern matching, parsing or
  inventory (ground rule 5). Cryptographic verification is none of these, so
  it needs an explicit decision, not a quiet exception.
- Vendor neutrality (ground rule 1): evidence formats must be open
  (OCI digests, git commit hashes, in-toto statements, Sigstore bundles), and
  client data may add locations but may not define what counts as evidence.
- Dependencies are the standard library, `PyYAML` and `jsonschema`, pinned
  with hashes. Signature verification would add a dependency, or a subprocess
  to an external verifier.
- One profile, every active control must pass. A control that is
  `not-applicable` when evidence is missing is a bypass: delete the evidence,
  pass the control.

## 3. Proposed split

Separate what the checker can decide from what it cannot.

| Part | Decidable offline with the current dependencies | Proposed `check_type` |
| --- | --- | --- |
| A provenance record exists for each artifact and names source repository, full commit hash and content digest | yes, parsing | `static` |
| The recorded digest equals a digest the checker computes over the artifact | yes, if the hash algorithm is specified (section 4) | `static` |
| The record is signed by an allowed identity and the signature verifies | needs a crypto library and a trust root | `provenance` |
| The signed subject digest equals the recorded digest | yes once the statement is parsed, but meaningless without the line above | `provenance` |
| The signing identity corresponds to the claimed source repository | needs the attestation's certificate claims | `provenance` |

Recommendation: ship the two `static` rows first as draft controls. They close
the gap between "a digest is present" and "the digest matches what is on disk",
cost no dependency, and make the later signature step a strict addition.

## 4. Open design point: the artifact digest

A skill is a directory, so "its digest" needs a canonical definition: sorted
relative paths, normalised separators, a per-file digest, a digest over that
listing, and a rule for file modes, symlinks (SKILL-003 already forbids
them) and the provenance record itself, which sits in the artifact
directory (section 6, question 1) and so must be excluded from the digest
it records. Without this the digest is not reproducible across tools. The
Agent Skills specification does not define one (checked 2026-10-24, see
section 6, question 5), so this baseline would be defining it, which should be a
separate, versioned document rather than text inside a control.

## 5. Proposed draft controls

IDs are placeholders. The existing prefixes are `CFG`, `EXT`, `GEN`, `INSTR`,
`MCP` and `SKILL`; `PROV` would be new. Both start as `status: draft`.

- `ACB-PROV-001` — every inventoried skill and extension package has a
  provenance record with source repository, full commit hash and content
  digest. Missing record fails; it is not `not-applicable`. MCP server
  packages are deferred, see section 7.
- `ACB-PROV-002` — each record's digest equals the digest computed from the
  artifact under the section 4 definition.
- A signature control is deferred until the verifier question below is
  settled.

The audit of `konstruktoid/agent-instructions-skills` at `db098c2` would fail
`ACB-PROV-001` for all 10 skills if the record lives in the repository (a file
in the skill or a repository-level lock file): by file name, that commit
contains no such record. If the record is an operator file (section 6,
question 1), the result depends on what the operator supplies. A failure here
is a finding about missing evidence rather than evidence of tampering; the
report text would need to say so.

## 6. Questions that need an answer before implementation

1. Where does a record live: a file in the skill directory (excluded from its
   own hash), a repository-level lock file, or an operator file passed on the
   command line like `--exceptions`? Decided: a `.acb-provenance.yaml` in
   each skill directory and extension package root, because it is the only
   option that travels with a copied or vendored artifact; a
   repository-level file is lost when one skill is copied out. The cost is
   that whoever can change the artifact can change its record, so
   `ACB-PROV-001` shows only that evidence exists. An operator file remains
   the only option an attacker who controls the skill cannot rewrite, and
   could be added later as an override rather than a replacement.
2. Is the checker allowed a verifier dependency or an external verifier
   subprocess? If a subprocess, its result is a claim the checker relays, and
   the report must label it that way.
3. How is the trust root pinned, and who owns updating it?
4. Should `PROV-*` apply to the repository under audit only, or also to
   third-party skills it vendors?
5. Verify before implementing, with the command that would check each:
   Sigstore bundle field names and offline verification support (read the
   current sigstore bundle specification); in-toto statement and SLSA
   provenance predicate versions (read the current in-toto and SLSA
   specifications). The Agent Skills specification at agentskills.io was
   checked on 2026-10-24: it permits "any files and directories beyond the
   required `SKILL.md`" and defines no digest, hash or provenance field; its
   only extension point is the string-to-string `metadata` frontmatter map,
   which would place the record inside the content it hashes.

## 7. Out of scope and deferred

MCP server packages. Section 1 names them as artifacts the problem covers, but
an MCP declaration names a launch command or a remote URL, not a directory, so
there is no artifact path for a record to key on. `ACB-PROV-001` is limited to
skills and extension packages until the record format can identify a package
by registry coordinates or image digest.

Reputation, vulnerability status of dependencies, and runtime attestation
of the agent itself (README: agent identity is out of scope).
