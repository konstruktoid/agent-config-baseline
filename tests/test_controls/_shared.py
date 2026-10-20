"""Generic pass/fail-fixture runner, shared by every tests/test_controls/test_acb_*.py."""

from __future__ import annotations

from pathlib import Path

from tests._harness import context_for

FIXTURES_ROOT = Path(__file__).resolve().parent.parent / "fixtures"


def audit_ids_for(control_id: str) -> list[str]:
    directory = FIXTURES_ROOT / control_id
    return sorted(p.name for p in directory.iterdir() if p.is_dir())


def check_pass_and_fail(control_id: str, audits: dict, skip: frozenset[str] = frozenset()) -> None:
    """Run every <CONTROL-ID>/<audit-id>/{pass,fail} fixture through `audits[audit_id]`.

    `skip` names audit ids that need non-default ClientData to exercise
    (e.g. a client-declared bypass flag) and so are checked by a separate,
    explicit test instead; their fixtures still live at the canonical
    tests/fixtures/<CONTROL-ID>/<audit-id>/ path, they are just not run
    with the default empty ClientData() here.
    """
    audit_ids = audit_ids_for(control_id)
    assert audit_ids, f"no fixtures found for {control_id}"
    assert set(audit_ids) <= set(audits), (
        f"{control_id}: fixtures exist for audit id(s) with no AUDITS entry: "
        f"{sorted(set(audit_ids) - set(audits))}"
    )

    for audit_id in audit_ids:
        if audit_id in skip:
            continue
        check = audits[audit_id]
        pass_dir = FIXTURES_ROOT / control_id / audit_id / "pass"
        fail_dir = FIXTURES_ROOT / control_id / audit_id / "fail"

        if pass_dir.is_dir():
            findings = check(context_for(pass_dir))
            assert findings == [], f"{control_id}/{audit_id} pass fixture produced findings: {findings}"

        if fail_dir.is_dir():
            findings = check(context_for(fail_dir))
            assert findings, f"{control_id}/{audit_id} fail fixture produced no findings"
