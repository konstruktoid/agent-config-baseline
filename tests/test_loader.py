import textwrap
from pathlib import Path

import pytest

from acb.clients import load_clients
from acb.loader import (
    ControlLoadError,
    active_controls,
    default_clients_dir,
    default_controls_dir,
    default_schema_path,
    load_controls,
)

SCHEMA_PATH = default_schema_path()


def test_bundled_controls_load_and_validate() -> None:
    controls = load_controls(default_controls_dir(), SCHEMA_PATH)
    assert len(controls) == 22
    ids = {c.id for c in controls}
    assert "ACB-GEN-001" in ids
    assert "ACB-SKILL-003" in ids
    assert "ACB-EXT-001" in ids
    assert "ACB-CFG-004" in ids


def test_every_control_maps_to_risk_areas_and_csf() -> None:
    for control in load_controls(default_controls_dir(), SCHEMA_PATH):
        assert control.references.get("five_eyes_risk_areas"), f"{control.id} has no five_eyes_risk_areas"
        assert control.references.get("nist_csf"), f"{control.id} has no nist_csf"


def test_controls_name_no_client() -> None:
    names = load_clients(default_clients_dir()).clients
    for control in load_controls(default_controls_dir(), SCHEMA_PATH):
        text = control.source_path.read_text(encoding="utf-8").lower()
        for name in names:
            for word in {name, name.split("-")[0]}:
                assert word not in text, f"{control.id} names client {word!r}; product facts belong in clients/"


def test_active_controls_filters_profile_and_status() -> None:
    controls = load_controls(default_controls_dir(), SCHEMA_PATH)
    active = active_controls(controls)
    assert all(c.status != "deprecated" for c in active)
    assert all("strict-general" in c.profiles for c in active)


def _write(path: Path, text: str) -> None:
    path.write_text(textwrap.dedent(text), encoding="utf-8")


VALID = """\
schema_version: "1.0"
id: ACB-GEN-999
title: A placeholder test control for loader coverage
status: draft
profiles: [strict-general]
applies_to: [skill]
check_type: static
severity: low
description: Placeholder description long enough to satisfy the schema.
rationale: Placeholder rationale long enough to satisfy the schema.
audit:
  - id: some-check
    method: pattern
    procedure: Placeholder audit procedure text, long enough to validate.
remediation: Placeholder remediation text, long enough to validate ok.
exceptions: permitted
references:
  owasp_asi: [ASI01]
"""


def test_filename_mismatch_fails(tmp_path: Path) -> None:
    _write(tmp_path / "ACB-GEN-998.yaml", VALID)
    with pytest.raises(ControlLoadError, match="does not match filename"):
        load_controls(tmp_path, SCHEMA_PATH)


def test_duplicate_audit_id_within_control_fails(tmp_path: Path) -> None:
    bad = VALID.replace(
        "audit:\n  - id: some-check\n    method: pattern\n"
        "    procedure: Placeholder audit procedure text, long enough to validate.\n",
        "audit:\n"
        "  - id: some-check\n    method: pattern\n"
        "    procedure: Placeholder audit procedure text, long enough to validate.\n"
        "  - id: some-check\n    method: pattern\n"
        "    procedure: Another placeholder procedure text for duplicate id test.\n",
    )
    _write(tmp_path / "ACB-GEN-999.yaml", bad)
    with pytest.raises(ControlLoadError, match="duplicate audit procedure id"):
        load_controls(tmp_path, SCHEMA_PATH)


def test_deprecated_without_deprecated_by_fails(tmp_path: Path) -> None:
    bad = VALID.replace("status: draft", "status: deprecated")
    _write(tmp_path / "ACB-GEN-999.yaml", bad)
    with pytest.raises(ControlLoadError, match="deprecated_by"):
        load_controls(tmp_path, SCHEMA_PATH)


def test_schema_violation_fails(tmp_path: Path) -> None:
    bad = VALID.replace("severity: low", "severity: catastrophic")
    _write(tmp_path / "ACB-GEN-999.yaml", bad)
    with pytest.raises(ControlLoadError, match="schema validation failed"):
        load_controls(tmp_path, SCHEMA_PATH)


def test_empty_controls_dir_fails(tmp_path: Path) -> None:
    with pytest.raises(ControlLoadError, match="no control YAML files"):
        load_controls(tmp_path, SCHEMA_PATH)
