# Design note: provenance controls

Status: draft. `ACB-PROV-001` and `ACB-PROV-002` exist as draft controls and
section 6 records the decisions behind them. Nothing here has been verified
against the Sigstore, in-toto or SLSA specifications; section 6, question 5
lists what to check before a signature control is implemented.

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

## 4. The artifact digest

A skill is a directory, so "its digest" needs a canonical definition: sorted
relative paths, normalised separators, a per-file digest, a digest over that
listing, and a rule for file modes, symlinks (SKILL-003 already forbids
them) and the provenance record itself, which sits in the artifact
directory (section 6, question 1) and so must be excluded from the digest
it records. Without this the digest is not reproducible across tools. The
Agent Skills specification does not define one (checked 2026-10-24, see
section 6, question 5), so this baseline would be defining it, which should be a
separate, versioned document rather than text inside a control.

Decided: [artifact-digest.md](artifact-digest.md) version 1 adopts Go's
`dirhash` `h1:` format rather than defining a new one, so an existing
implementation and a coreutils pipeline both reproduce it. The digest
leaves out only its own record and a `.git` entry, with its contents,
directly in the artifact directory; symlinks, special files and unencodable
names make the digest not computable, and file modes are not covered.

## 5. Proposed draft controls

IDs are placeholders. The existing prefixes are `CFG`, `EXT`, `GEN`, `INSTR`,
`MCP` and `SKILL`; `PROV` would be new. Both start as `status: draft`.

- `ACB-PROV-001` — every inventoried skill and extension package has a
  provenance record with source repository, full commit hash and content
  digest. Missing record fails; it is not `not-applicable`. MCP server
  packages are deferred, see section 7.
- `ACB-PROV-002` — each record's digest equals the digest computed from the
  artifact under the section 4 definition. An artifact without a
  well-formed recorded digest is not evaluated rather than failed, because
  `ACB-PROV-001` already fails it.
- A signature control is deferred until the specifications in section 6,
  question 5 are checked. It would run an external verifier and read an
  operator trust root (section 6, questions 2 and 3).

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
   could be added later as an override rather than a replacement. Decided:
   that operator file is added together with the trust root (question 3),
   and keys each record by the artifact's path relative to the audited
   root, as findings report it. A record there replaces the in-directory
   record as a whole, with no merging of fields. Every `PROV-*` control reads
   that one resolved record, so an operator record also satisfies
   `ACB-PROV-001`; the controls change when the operator file ships.
2. Is the checker allowed a verifier dependency or an external verifier
   subprocess? Decided: no new dependency. A signature control runs an
   external verifier as a subprocess, its result is a claim the checker
   relays, and the report labels it as that tool's result. The checker's own
   dependencies stay the standard library, `PyYAML` and `jsonschema`. The
   operator names the verifier by absolute path, never by a `PATH` lookup,
   and the checker runs it without a shell and with a timeout. Only a zero
   exit with well-formed output that names the expected subject digest and
   a signer identity matching the record's `source` repository passes; a
   different signer or a verifier that reports a failed verification fails
   the control, and a missing verifier, a timeout, a crash or malformed
   output leave it not evaluated, so no path through the verifier passes by
   default. The expected `source` comes only from an operator record
   (question 1), because whoever can change an artifact can also change its
   in-directory record and sign from a repository they chose; an artifact
   with only an in-directory record leaves the signature control not
   evaluated.
3. How is the trust root pinned, and who owns updating it? Decided: the
   operator supplies it as a file on the command line, as with
   `--exceptions`, and the checker never bundles one, so the person running
   the audit owns updating it. The checker does not pin its content, since
   any pin would sit where the same operator controls it; instead each report
   records the trust root file's SHA-256, so the evidence names the root that
   was used, and rotating it means replacing the file, which changes that
   digest in the next report. Without a trust root the report records the
   trust root as absent, `null` with the reason, rather than a digest, and
   the signature control is not evaluated, never passed.
4. Should `PROV-*` apply to the repository under audit only, or also to
   third-party skills it vendors? Decided: to every skill and extension
   package the inventory finds, vendored or not, which is what both draft
   controls already do; MCP server packages stay deferred (section 7). A
   copied third-party skill is the supply-chain case these controls exist
   for.
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
