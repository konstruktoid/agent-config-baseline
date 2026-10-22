# Design note: provenance controls

Status: draft for discussion. No control, schema change or checker code exists
for this yet. Nothing here has been verified against the Sigstore, in-toto or
SLSA specifications; section 6 lists what to check before any of it is
implemented.

## 1. Problem

All 22 active controls are `check_type: static`. They judge the content of a
file. None of them can say whether a skill, extension package or MCP server
package is the artifact its publisher released, built from the source the
publisher claims. `ACB-GEN-002` and `ACB-EXT-*` ask for pins and digests, but
only that a digest is present, never that anything is bound to it. The schema
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
them) and the provenance record itself (it cannot be inside the thing it
hashes). Without this the digest is not reproducible across tools. The
Agent Skills specification does not define one as far as I know (unverified);
if it does not, this baseline would be defining it, which should be a
separate, versioned document rather than text inside a control.

## 5. Proposed draft controls

IDs are placeholders. The existing prefixes are `CFG`, `EXT`, `GEN`, `INSTR`,
`MCP` and `SKILL`; `PROV` would be new. Both start as `status: draft`.

- `ACB-PROV-001` — every inventoried skill and extension package has a
  provenance record with source repository, full commit hash and content
  digest. Missing record fails; it is not `not-applicable`.
- `ACB-PROV-002` — each record's digest equals the digest computed from the
  artifact under the section 4 definition.
- A signature control is deferred until the verifier question below is
  settled.

The audit of `konstruktoid/agent-instructions-skills` at `db098c2` would fail
`ACB-PROV-001` for all 10 skills. That is the intended result, and it is a
finding about missing evidence rather than evidence of tampering; the report
text would need to say so.

## 6. Questions that need an answer before implementation

1. Where does a record live: a file in the skill directory (excluded from its
   own hash), a repository-level lock file, or an operator file passed on the
   command line like `--exceptions`? Operator files are the only option that
   an attacker who controls the skill cannot rewrite; the repository-level
   file is the only one that travels with the artifact.
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
   specifications); whether the Agent Skills specification at agentskills.io
   defines any digest or provenance field (fetch and grep the specification).

## 7. Out of scope

Reputation, vulnerability status of dependencies, and runtime attestation
of the agent itself (README: agent identity is out of scope).
