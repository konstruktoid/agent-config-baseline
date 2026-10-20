"""Every `indicators` string in every control's YAML must appear in at least
one failing fixture (PROMPT.md deliverable 5). This is a repo-wide
invariant, not a per-control test, so it lives on its own rather than in
tests/test_controls/.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from acb.loader import default_controls_dir, default_schema_path, load_controls

FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"

# An indicator shaped "<relative/path> (<description>)" names a file to be
# present somewhere in the fixture tree, not text to be present verbatim,
# e.g. "scripts/helper (ELF executable)" from ACB-SKILL-003.
_PATH_WITH_DESCRIPTION_RE = re.compile(r"^(?P<path>\S+)\s+\([^)]+\)$")

# An indicator shaped as one or more "key": "value" JSON fragments is an
# illustrative snippet, not a literal substring to find verbatim (real
# fixture JSON is pretty-printed differently); check each quoted token
# individually instead.
_QUOTED_TOKEN_RE = re.compile(r'"([^"]*)"')


def _normalize(text: str) -> str:
    return " ".join(text.split())


def _fail_fixture_dir(control_id: str, audit_id: str) -> Path:
    return FIXTURES_ROOT / control_id / audit_id / "fail"


def _fail_fixture_text(fail_dir: Path) -> str:
    if not fail_dir.is_dir():
        return ""
    chunks = []
    for path in fail_dir.rglob("*"):
        if path.is_file():
            try:
                chunks.append(path.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, OSError):
                pass
    return "\n".join(chunks)


def _cases():
    controls = load_controls(default_controls_dir(), default_schema_path())
    for control in controls:
        for audit in control.audit:
            for indicator in audit.indicators:
                yield control.id, audit.id, indicator


@pytest.mark.parametrize("control_id,audit_id,indicator", list(_cases()))
def test_indicator_present_in_a_failing_fixture(control_id: str, audit_id: str, indicator: str):
    fail_dir = _fail_fixture_dir(control_id, audit_id)

    path_match = _PATH_WITH_DESCRIPTION_RE.match(indicator)
    if path_match:
        suffix = path_match.group("path")
        if any(p.is_file() and p.relative_to(fail_dir).as_posix().endswith(suffix) for p in fail_dir.rglob("*")):
            return

    haystack = _normalize(_fail_fixture_text(fail_dir))

    quoted_tokens = _QUOTED_TOKEN_RE.findall(indicator)
    if quoted_tokens:
        missing = [t for t in quoted_tokens if _normalize(t.split("...", 1)[0]) not in haystack]
        assert not missing, (
            f"{control_id}/{audit_id}: indicator {indicator!r} has quoted token(s) {missing} not found "
            f"under tests/fixtures/{control_id}/{audit_id}/fail/"
        )
        return

    # Indicators are illustrative (control.schema.json: "non-exhaustive
    # examples"), so a trailing "..." is an elision, not literal text, and
    # formatting (e.g. multi-line JSON vs. the inline snippet in the YAML)
    # may differ from the fixture's. Match the part before any elision,
    # with whitespace collapsed on both sides.
    prefix = indicator.split("...", 1)[0]
    assert _normalize(prefix) in haystack, (
        f"{control_id}/{audit_id}: indicator {indicator!r} from the control YAML has no match "
        f"(as text or as a file) under tests/fixtures/{control_id}/{audit_id}/fail/"
    )
