# Contributing

## Control lifecycle

A control's `status` field tracks its lifecycle:

- **draft** — may change incompatibly, including its audit procedures and
  severity. Not assumed stable by downstream consumers.
- **active** — stable. Breaking changes to an active control's audit
  procedures require a new control ID; the old one moves to `deprecated`.
- **deprecated** — retained for reference and traceability, never
  evaluated. Requires `deprecated_by` pointing at the replacement ID.

## ID rules

- IDs match `^ACB-(SKILL|INSTR|MCP|GEN|EXT|CFG)-[0-9]{3}$` and are
  assigned sequentially within their family.
- IDs are never renumbered and never reused, even after deprecation.
- A retired control becomes `status: deprecated` with `deprecated_by`; it
  is not deleted from `controls/`.
- Audit procedure IDs (`audit[].id`) are unique within their control and
  are snake-case-with-hyphens (`^[a-z0-9]+(-[a-z0-9]+)*$`), matching the
  schema.

## Adding or changing a control

1. Write the YAML in `controls/`, validated against
   `schema/control.schema.json`.
2. Every OWASP reference must be verified against the published source
   before it is added — see ground rule 4 in `PROMPT.md`. Do not copy
   OWASP prose; map by ID only. Every control also maps to at least one
   `five_eyes_risk_areas` value and one `nist_csf` subcategory; add a new
   CSF ID to `CSF_SUBCATEGORIES` in `scripts/gen_docs.py` only after
   checking its text in NIST CSWP 29.
3. Every `audit[].id` needs an implementation in
   `src/acb/controls/<id_lowercased_with_underscores>.py`. A control with
   an unimplemented audit procedure is reported as `not-evaluated`, never
   `pass` — it is not sufficient to add the YAML alone.
4. Add at least one fixture under
   `tests/fixtures/<CONTROL-ID>/<audit-id>/pass/` and one under
   `.../fail/` for every audit procedure. Every `indicators` entry listed
   in the control's YAML must appear in at least one failing fixture.
5. Regenerate `docs/controls/<ID>.md`, `docs/controls/index.md` and `docs/mappings.md` with
   `uv run python scripts/gen_docs.py`. Do not hand-edit either; CI runs
   `scripts/gen_docs.py --check` and fails if they differ from the YAML.
6. Run the full verification gate before opening a PR:
   `uv run python scripts/gen_docs.py --check && uv run pytest -q && uv run acb check .`

## Client data

A file under `clients/` records facts about one client that no open
specification defines. Add a fact only when the client's own documentation
states it, and cite that documentation in the pull request. Files are
validated against `schema/client.schema.json`.

## Vendor neutrality

Client-specific facts (file locations, permission-bypass flags,
alternative instruction-file names, settings keys, extension layout) belong
in `clients/<client>.yaml`, never in a control's YAML or in checker logic
that assumes a single product. The checker must produce correct results
with `clients/` empty. Each structured fact carries a `source` URL, and a
client's implementation-specific audit procedure goes in `audit_notes`
against the control and audit ID it implements.
