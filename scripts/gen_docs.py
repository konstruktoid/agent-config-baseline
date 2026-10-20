#!/usr/bin/env python3
"""Generate docs/controls/*.md and docs/mappings.md from controls/*.yaml.

These files are generated; never hand-edit them (PROMPT.md ground rule 3).
Run after any change to controls/: `uv run python scripts/gen_docs.py`.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from acb.loader import load_controls  # noqa: E402
from acb.model import Control  # noqa: E402

# OWASP AST IDs verified against the published OWASP Agentic Skills Top 10
# (August 2026) so far (PROMPT.md ground rule 4). Any owasp_ast id used by a
# control that is not in this set is flagged in docs/mappings.md as a TODO
# rather than presented as a confirmed mapping.
VERIFIED_AST_IDS = {"AST02"}

DOCS_CONTROLS_DIR = REPO_ROOT / "docs" / "controls"
MAPPINGS_PATH = REPO_ROOT / "docs" / "mappings.md"


def render_control(control: Control) -> str:
    lines = [
        f"# {control.id}: {control.title}",
        "",
        f"| Field | Value |",
        f"| --- | --- |",
        f"| Status | `{control.status}` |",
        f"| Severity | `{control.severity.value}` |",
        f"| Check type | `{control.check_type}` |",
        f"| Applies to | {', '.join(f'`{a}`' for a in control.applies_to)} |",
        f"| Profiles | {', '.join(control.profiles)} |",
        f"| Exceptions | `{control.exceptions}` |",
    ]
    if control.deprecated_by:
        lines.append(f"| Deprecated by | {control.deprecated_by} |")
    lines += ["", "## Description", "", control.description.strip(), "", "## Rationale", "", control.rationale.strip()]

    lines += ["", "## Audit procedures", ""]
    for audit in control.audit:
        lines.append(f"### `{audit.id}` ({audit.method})")
        lines.append("")
        lines.append(audit.procedure.strip())
        if audit.indicators:
            lines.append("")
            lines.append("Illustrative failing indicators (non-exhaustive):")
            lines.append("")
            for indicator in audit.indicators:
                lines.append(f"- `{indicator}`")
        lines.append("")

    lines += ["## Remediation", "", control.remediation.strip(), ""]

    refs = control.references
    if refs:
        lines += ["## References", ""]
        if refs.get("owasp_asi"):
            lines.append("- OWASP Top 10 for Agentic Applications 2026: " + ", ".join(refs["owasp_asi"]))
        if refs.get("owasp_ast"):
            lines.append("- OWASP Agentic Skills Top 10: " + ", ".join(refs["owasp_ast"]))
        for spec in refs.get("specifications", []):
            lines.append(f"- Specification: {spec}")
        for other in refs.get("other", []):
            lines.append(f"- {other}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_index(controls: list[Control]) -> str:
    lines = [
        "# Control index",
        "",
        "Generated from controls/*.yaml. Do not hand-edit.",
        "",
        "| ID | Title | Applies to | Severity | OWASP ASI | OWASP AST |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for control in sorted(controls, key=lambda c: c.id):
        asi = ", ".join(control.references.get("owasp_asi", [])) or "-"
        ast = ", ".join(control.references.get("owasp_ast", [])) or "-"
        applies = ", ".join(control.applies_to)
        lines.append(f"| [{control.id}]({control.id}.md) | {control.title} | {applies} | {control.severity.value} | {asi} | {ast} |")
    lines.append("")
    return "\n".join(lines)


def render_mappings(controls: list[Control]) -> str:
    asi_map: dict[str, list[str]] = {}
    ast_map: dict[str, list[str]] = {}
    todo_ast: list[tuple[str, str]] = []

    for control in sorted(controls, key=lambda c: c.id):
        for asi in control.references.get("owasp_asi", []):
            asi_map.setdefault(asi, []).append(control.id)
        for ast in control.references.get("owasp_ast", []):
            ast_map.setdefault(ast, []).append(control.id)
            if ast not in VERIFIED_AST_IDS:
                todo_ast.append((ast, control.id))

    lines = [
        "# OWASP coverage mappings",
        "",
        "Generated from controls/*.yaml. Do not hand-edit. Mapping is by ID",
        "only; control text does not reproduce OWASP prose (PROMPT.md ground",
        "rule 4).",
        "",
        "## OWASP Top 10 for Agentic Applications 2026 (ASI)",
        "",
        "| ASI ID | Controls |",
        "| --- | --- |",
    ]
    for asi_id in sorted(asi_map):
        lines.append(f"| {asi_id} | {', '.join(asi_map[asi_id])} |")

    lines += ["", "## OWASP Agentic Skills Top 10 (AST)", "", "| AST ID | Controls | Verified |", "| --- | --- | --- |"]
    for ast_id in sorted(ast_map):
        verified = "yes" if ast_id in VERIFIED_AST_IDS else "**TODO**"
        lines.append(f"| {ast_id} | {', '.join(ast_map[ast_id])} | {verified} |")

    lines += ["", "## TODO: unverified AST mappings", ""]
    if todo_ast:
        for ast_id, control_id in todo_ast:
            lines.append(
                f"- {control_id} references {ast_id}, which has not been verified against the "
                "published OWASP Agentic Skills Top 10 (August 2026). Confirm the mapping before "
                "treating it as settled."
            )
    else:
        lines.append("None open: every `owasp_ast` reference currently in controls/ is verified.")
    lines.append("")

    return "\n".join(lines)


def render_all(controls: list[Control]) -> dict[Path, str]:
    docs = {DOCS_CONTROLS_DIR / f"{c.id}.md": render_control(c) for c in controls}
    docs[DOCS_CONTROLS_DIR / "index.md"] = render_index(controls)
    docs[MAPPINGS_PATH] = render_mappings(controls)
    return docs


def main(argv: list[str] | None = None) -> int:
    check = "--check" in (sys.argv[1:] if argv is None else argv)
    controls = load_controls(REPO_ROOT / "controls", REPO_ROOT / "schema" / "control.schema.json")
    docs = render_all(controls)

    if check:
        expected = set(docs)
        on_disk = set(DOCS_CONTROLS_DIR.glob("*.md")) | {MAPPINGS_PATH}
        stale = sorted(
            str(p.relative_to(REPO_ROOT))
            for p in expected | on_disk
            if p not in docs or not p.is_file() or p.read_text(encoding="utf-8") != docs[p]
        )
        if stale:
            print("generated docs are out of date; run `uv run python scripts/gen_docs.py`:", file=sys.stderr)
            for path in stale:
                print(f"  {path}", file=sys.stderr)
            return 1
        print(f"{len(docs)} generated doc(s) are up to date")
        return 0

    DOCS_CONTROLS_DIR.mkdir(parents=True, exist_ok=True)
    for path, text in docs.items():
        path.write_text(text, encoding="utf-8")
    print(f"wrote {len(controls)} control doc(s), index.md and mappings.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
