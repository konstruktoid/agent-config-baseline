#!/usr/bin/env python3
"""Generate docs/controls/*.md, docs/mappings.md and the static site in site/ from controls/*.yaml.

These files are generated; never hand-edit them (PROMPT.md ground rule 3).
Run after any change to controls/: `uv run python scripts/gen_docs.py`.
"""

from __future__ import annotations

import html
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from acb.clients import load_clients  # noqa: E402
from acb.loader import load_controls  # noqa: E402
from acb.model import Control  # noqa: E402

# OWASP AST IDs verified against the published OWASP Agentic Skills Top 10
# (August 2026) so far (PROMPT.md ground rule 4). Any owasp_ast id used by a
# control that is not in this set is flagged in docs/mappings.md as a TODO
# rather than presented as a confirmed mapping.
VERIFIED_AST_IDS = {"AST02"}

FIVE_EYES_TITLE = "Careful Adoption of Agentic AI Services (ASD's ACSC, CISA, NSA, CCCS, NCSC-NZ, NCSC-UK, May 2026)"
FIVE_EYES_URL = "https://www.ncsc.govt.nz/assets/guidance/Documents/Careful-adoption-of-agentic-AI-services_FINAL.pdf"
CSF_TITLE = "NIST Cybersecurity Framework 2.0 (NIST CSWP 29)"
CSF_URL = "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf"

# Subcategory text checked against NIST CSWP 29 for every ID a control uses;
# an ID missing here fails generation rather than shipping unverified.
CSF_SUBCATEGORIES = {
    "GV.RR-02": "Roles, responsibilities, and authorities related to cybersecurity risk management are established, "
    "communicated, understood, and enforced",
    "ID.AM-02": "Inventories of software, services, and systems managed by the organization are maintained",
    "ID.IM-02": "Improvements are identified from security tests and exercises, including those done in coordination "
    "with suppliers and relevant third parties",
    "ID.RA-09": "The authenticity and integrity of hardware and software are assessed prior to acquisition and use",
    "PR.AA-01": "Identities and credentials for authorized users, services, and hardware are managed by the organization",
    "PR.AA-05": "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and "
    "reviewed, and incorporate the principles of least privilege and separation of duties",
    "PR.PS-01": "Configuration management practices are established and applied",
    "PR.PS-05": "Installation and execution of unauthorized software are prevented",
    "PR.PS-06": "Secure software development practices are integrated, and their performance is monitored throughout "
    "the software development life cycle",
}

DOCS_CONTROLS_DIR = REPO_ROOT / "docs" / "controls"
MAPPINGS_PATH = REPO_ROOT / "docs" / "mappings.md"
SITE_DIR = REPO_ROOT / "site"
REPO_URL = "https://github.com/konstruktoid/agent-config-baseline"

CSS = """\
:root { color-scheme: light dark; --bg: #fff; --fg: #1b1f24; --muted: #59636e; --line: #d1d9e0; --code: #f6f8fa; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #3d444d; --code: #151b23; }
}
body { margin: 0 auto; max-width: 56rem; padding: 1.5rem 1rem 4rem; background: var(--bg); color: var(--fg);
  font: 16px/1.6 system-ui, sans-serif; }
a { color: inherit; }
nav { display: flex; gap: 1rem; flex-wrap: wrap; padding-bottom: 1rem; border-bottom: 1px solid var(--line); }
h1 { font-size: 1.6rem; } h2 { margin-top: 2rem; font-size: 1.2rem; } h3 { font-size: 1rem; }
code { background: var(--code); padding: .1em .35em; border-radius: 4px; font-size: .9em; }
table { border-collapse: collapse; display: block; overflow-x: auto; }
th, td { border: 1px solid var(--line); padding: .35rem .6rem; text-align: left; vertical-align: top; }
"""


def client_notes(clients) -> dict[str, list[tuple[str, dict]]]:
    """Implementation-specific audit notes, keyed by control ID, as (client, note) pairs."""
    notes: dict[str, list[tuple[str, dict]]] = {}
    for client, profile in clients.profiles:
        for note in profile.get("audit_notes", []):
            notes.setdefault(note["control"], []).append((client, note))
    return notes


def render_control(control: Control, notes: list[tuple[str, dict]] = ()) -> str:
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

    if notes:
        lines += [
            "## Implementation notes",
            "",
            "Client-specific facts from `clients/`; the control above is the requirement.",
            "",
        ]
        for client, note in notes:
            lines += [f"### {client}: `{note['audit']}`", "", note["note"].strip(), ""]
            lines += [f"- {source}" for source in note["sources"]] + [""]

    refs = control.references
    if refs:
        lines += ["## References", ""]
        if refs.get("owasp_asi"):
            lines.append("- OWASP Top 10 for Agentic Applications 2026: " + ", ".join(refs["owasp_asi"]))
        if refs.get("owasp_ast"):
            lines.append("- OWASP Agentic Skills Top 10: " + ", ".join(refs["owasp_ast"]))
        if refs.get("five_eyes_risk_areas"):
            lines.append("- Careful Adoption of Agentic AI Services risk areas: " + ", ".join(refs["five_eyes_risk_areas"]))
        if refs.get("nist_csf"):
            lines.append("- NIST CSF 2.0: " + ", ".join(refs["nist_csf"]))
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


def framework_maps(controls: list[Control]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    risk_map: dict[str, list[str]] = {}
    csf_map: dict[str, list[str]] = {}
    for control in sorted(controls, key=lambda c: c.id):
        for area in control.references.get("five_eyes_risk_areas", []):
            risk_map.setdefault(area, []).append(control.id)
        for csf in control.references.get("nist_csf", []):
            if csf not in CSF_SUBCATEGORIES:
                raise SystemExit(f"{control.id}: NIST CSF ID {csf} is not in CSF_SUBCATEGORIES; verify it first")
            csf_map.setdefault(csf, []).append(control.id)
    return risk_map, csf_map


def mapping_data(controls: list[Control]) -> tuple[dict[str, list[str]], dict[str, list[str]], list[tuple[str, str]]]:
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
    return asi_map, ast_map, todo_ast


def render_mappings(controls: list[Control]) -> str:
    asi_map, ast_map, todo_ast = mapping_data(controls)
    risk_map, csf_map = framework_maps(controls)

    lines = [
        "# Coverage mappings",
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

    lines += ["", f"## {FIVE_EYES_TITLE}", "", f"Source: {FIVE_EYES_URL}", "", "| Risk area | Controls |", "| --- | --- |"]
    for area in sorted(risk_map):
        lines.append(f"| {area} | {', '.join(risk_map[area])} |")

    lines += [
        "",
        f"## {CSF_TITLE}",
        "",
        f"Source: {CSF_URL}. Each subcategory's text was checked against that publication.",
        "",
        "| Subcategory | Outcome | Controls |",
        "| --- | --- | --- |",
    ]
    for csf in sorted(csf_map):
        lines.append(f"| {csf} | {CSF_SUBCATEGORIES[csf]} | {', '.join(csf_map[csf])} |")
    lines.append("")

    return "\n".join(lines)


def esc(text: str) -> str:
    return html.escape(text, quote=True)


def code(text: str) -> str:
    return f"<code>{esc(text)}</code>"


def table(header: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in header)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def page(title: str, body: str, root: str) -> str:
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>{esc(title)}</title>\n"
        f'<link rel="stylesheet" href="{root}style.css">\n</head>\n<body>\n'
        f'<nav><a href="{root}index.html">agent-config-baseline</a>'
        f'<a href="{root}controls/index.html">Controls</a>'
        f'<a href="{root}mappings.html">Mappings</a>'
        f'<a href="{REPO_URL}">Source</a></nav>\n'
        f"<main>\n{body}</main>\n</body>\n</html>\n"
    )


def render_control_html(control: Control, notes: list[tuple[str, dict]] = ()) -> str:
    rows = [
        ["Status", code(control.status)],
        ["Severity", code(control.severity.value)],
        ["Check type", code(control.check_type)],
        ["Applies to", ", ".join(code(a) for a in control.applies_to)],
        ["Profiles", esc(", ".join(control.profiles))],
        ["Exceptions", code(control.exceptions)],
    ]
    if control.deprecated_by:
        rows.append(["Deprecated by", esc(control.deprecated_by)])
    out = [
        f"<h1>{esc(control.id)}: {esc(control.title)}</h1>",
        table(["Field", "Value"], rows),
        f"<h2>Description</h2><p>{esc(control.description.strip())}</p>",
        f"<h2>Rationale</h2><p>{esc(control.rationale.strip())}</p>",
        "<h2>Audit procedures</h2>",
    ]
    for audit in control.audit:
        out.append(f"<h3>{code(audit.id)} ({esc(audit.method)})</h3><p>{esc(audit.procedure.strip())}</p>")
        if audit.indicators:
            items = "".join(f"<li>{code(i)}</li>" for i in audit.indicators)
            out.append(f"<p>Illustrative failing indicators (non-exhaustive):</p><ul>{items}</ul>")
    out.append(f"<h2>Remediation</h2><p>{esc(control.remediation.strip())}</p>")
    if notes:
        out.append("<h2>Implementation notes</h2><p>Client-specific facts from <code>clients/</code>; the control above is the requirement.</p>")
        for client, note in notes:
            sources = "".join(f'<li><a href="{esc(s)}">{esc(s)}</a></li>' for s in note["sources"])
            out.append(f"<h3>{esc(client)}: {code(note['audit'])}</h3><p>{esc(note['note'].strip())}</p><ul>{sources}</ul>")
    refs = control.references
    if refs:
        items = []
        if refs.get("owasp_asi"):
            items.append("OWASP Top 10 for Agentic Applications 2026: " + esc(", ".join(refs["owasp_asi"])))
        if refs.get("owasp_ast"):
            items.append("OWASP Agentic Skills Top 10: " + esc(", ".join(refs["owasp_ast"])))
        if refs.get("five_eyes_risk_areas"):
            items.append("Careful Adoption of Agentic AI Services risk areas: " + esc(", ".join(refs["five_eyes_risk_areas"])))
        if refs.get("nist_csf"):
            items.append("NIST CSF 2.0: " + esc(", ".join(refs["nist_csf"])))
        items += [f"Specification: {esc(spec)}" for spec in refs.get("specifications", [])]
        items += [esc(other) for other in refs.get("other", [])]
        out.append("<h2>References</h2><ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>")
    return page(f"{control.id}: {control.title}", "\n".join(out) + "\n", "../")


def render_index_html(controls: list[Control]) -> str:
    rows = [
        [
            f'<a href="{esc(c.id)}.html">{esc(c.id)}</a>',
            esc(c.title),
            esc(", ".join(c.applies_to)),
            esc(c.severity.value),
            esc(", ".join(c.references.get("owasp_asi", [])) or "-"),
            esc(", ".join(c.references.get("owasp_ast", [])) or "-"),
        ]
        for c in sorted(controls, key=lambda c: c.id)
    ]
    body = "<h1>Control index</h1>" + table(["ID", "Title", "Applies to", "Severity", "OWASP ASI", "OWASP AST"], rows)
    return page("Control index", body + "\n", "../")


def render_mappings_html(controls: list[Control]) -> str:
    asi_map, ast_map, todo_ast = mapping_data(controls)
    risk_map, csf_map = framework_maps(controls)
    asi_rows = [[esc(i), esc(", ".join(asi_map[i]))] for i in sorted(asi_map)]
    ast_rows = [
        [esc(i), esc(", ".join(ast_map[i])), "yes" if i in VERIFIED_AST_IDS else "<strong>TODO</strong>"]
        for i in sorted(ast_map)
    ]
    if todo_ast:
        todo = "<ul>" + "".join(f"<li>{esc(c)} references {esc(a)}, which is not yet verified.</li>" for a, c in todo_ast) + "</ul>"
    else:
        todo = "<p>None open: every <code>owasp_ast</code> reference currently in controls/ is verified.</p>"
    risk_rows = [[esc(a), esc(", ".join(risk_map[a]))] for a in sorted(risk_map)]
    csf_rows = [[esc(i), esc(CSF_SUBCATEGORIES[i]), esc(", ".join(csf_map[i]))] for i in sorted(csf_map)]
    body = (
        "<h1>Coverage mappings</h1>"
        "<p>Mapping is by ID only; control text does not reproduce OWASP prose.</p>"
        "<h2>OWASP Top 10 for Agentic Applications 2026 (ASI)</h2>" + table(["ASI ID", "Controls"], asi_rows) +
        "<h2>OWASP Agentic Skills Top 10 (AST)</h2>" + table(["AST ID", "Controls", "Verified"], ast_rows) +
        "<h2>Unverified AST mappings</h2>" + todo +
        f'<h2>{esc(FIVE_EYES_TITLE)}</h2><p>Source: <a href="{FIVE_EYES_URL}">{esc(FIVE_EYES_URL)}</a></p>'
        + table(["Risk area", "Controls"], risk_rows) +
        f'<h2>{esc(CSF_TITLE)}</h2><p>Source: <a href="{CSF_URL}">{esc(CSF_URL)}</a>. Each subcategory\'s text was '
        "checked against that publication.</p>" + table(["Subcategory", "Outcome", "Controls"], csf_rows)
    )
    return page("Coverage mappings", body + "\n", "")


def render_landing_html() -> str:
    body = (
        "<h1>agent-config-baseline</h1>"
        "<p>A strict, vendor-neutral security baseline for the files that configure AI agents: Agent Skills "
        "directories, agent instruction files, Model Context Protocol server declarations, agent extension packages "
        "and agent permission settings. Each control has a "
        "rationale, an audit procedure and a remediation, and the <code>acb</code> checker evaluates them.</p>"
        '<ul><li><a href="controls/index.html">Control index</a></li>'
        '<li><a href="mappings.html">Coverage mappings</a></li>'
        f'<li><a href="{REPO_URL}">Source repository</a></li></ul>\n'
    )
    return page("agent-config-baseline", body, "")


def render_all(controls: list[Control], notes: dict[str, list[tuple[str, dict]]]) -> dict[Path, str]:
    docs = {DOCS_CONTROLS_DIR / f"{c.id}.md": render_control(c, notes.get(c.id, [])) for c in controls}
    docs[DOCS_CONTROLS_DIR / "index.md"] = render_index(controls)
    docs[MAPPINGS_PATH] = render_mappings(controls)
    for c in controls:
        docs[SITE_DIR / "controls" / f"{c.id}.html"] = render_control_html(c, notes.get(c.id, []))
    docs[SITE_DIR / "controls" / "index.html"] = render_index_html(controls)
    docs[SITE_DIR / "mappings.html"] = render_mappings_html(controls)
    docs[SITE_DIR / "index.html"] = render_landing_html()
    docs[SITE_DIR / "style.css"] = CSS
    return docs


def generated_files_on_disk() -> set[Path]:
    on_disk = set(DOCS_CONTROLS_DIR.glob("*.md")) | {MAPPINGS_PATH}
    return on_disk | {p for p in SITE_DIR.rglob("*") if p.is_file()}


def main(argv: list[str] | None = None) -> int:
    check = "--check" in (sys.argv[1:] if argv is None else argv)
    controls = load_controls(REPO_ROOT / "controls", REPO_ROOT / "schema" / "control.schema.json")
    notes = client_notes(load_clients(REPO_ROOT / "clients"))
    audits = {(c.id, a) for c in controls for a in c.audit_ids}
    for control_id, entries in notes.items():
        for client, note in entries:
            if (control_id, note["audit"]) not in audits:
                raise SystemExit(f"clients/{client}: audit note names unknown {control_id}/{note['audit']}")
    docs = render_all(controls, notes)

    if check:
        expected = set(docs)
        on_disk = generated_files_on_disk()
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

    for path in generated_files_on_disk() - set(docs):
        path.unlink()
    for path, text in docs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    print(f"wrote {len(docs)} generated file(s) for {len(controls)} control(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
