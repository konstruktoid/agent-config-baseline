from __future__ import annotations

import sys
from dataclasses import replace
from typing import TYPE_CHECKING

from acb.controls.acb_ext_003 import AUDITS
from acb.model import Outcome
from tests._harness import context_for
from tests.test_controls._bundled import BUNDLED
from tests.test_controls._shared import FIXTURES_ROOT, check_pass_and_fail

if TYPE_CHECKING:
    from pathlib import Path

    from acb.clients import ClientData
    from acb.model import Finding

FIXTURES = FIXTURES_ROOT / "ACB-EXT-003"


def test_acb_ext_003_fixtures() -> None:
    check_pass_and_fail("ACB-EXT-003", AUDITS, skip=frozenset({"record-current"}), clients=BUNDLED)


def test_high_risk_capabilities_are_each_reported() -> None:
    findings = AUDITS["high-risk-documented"](context_for(FIXTURES / "high-risk-documented" / "fail", BUNDLED))
    assert {f.message.split()[4].rstrip(",") for f in findings} == {"tool.check", "$.process.spawn"}


def _with_fake_validator(tmp_path: Path, output: str, exit_code: int = 0) -> ClientData:
    script = tmp_path / "fake_validator.py"
    script.write_text(f"import sys\nsys.stdout.write({output!r})\nsys.exit({exit_code})\n")
    profile = dict(BUNDLED.profile("claude-code"))
    extension = dict(profile["extension_packages"])
    extension["validator"] = dict(extension["validator"], command=[sys.executable, str(script)])
    profile["extension_packages"] = extension
    return replace(BUNDLED, profiles=(("claude-code", profile),))


def _record_current(fixture: str, clients: ClientData, *, run_validators: bool = True) -> list[Finding]:
    ctx = replace(context_for(FIXTURES / "record-current" / fixture, clients), run_validators=run_validators)
    return AUDITS["record-current"](ctx)


VALIDATOR_OUTPUT = (
    "Validating hooks: x/hooks/hooks.json\n\n"
    "  \u276f ./register.js hooks: session.start\n  \u276f ./register.js calls: nothing on $\n\n✔ Validation passed\n"
)


def test_record_current_is_not_evaluated_unless_enabled() -> None:
    findings = _record_current("pass", BUNDLED, run_validators=False)
    assert [f.outcome for f in findings] == [Outcome.NOT_EVALUATED]
    assert "--run-validators" in findings[0].message


def test_record_current_is_not_evaluated_when_validator_is_missing() -> None:
    profile = dict(BUNDLED.profile("claude-code"))
    extension = dict(profile["extension_packages"])
    extension["validator"] = dict(extension["validator"], command=["acb-no-such-validator-binary"])
    profile["extension_packages"] = extension
    findings = _record_current("pass", replace(BUNDLED, profiles=(("claude-code", profile),)))
    assert [f.outcome for f in findings] == [Outcome.NOT_EVALUATED]
    assert "not installed" in findings[0].message


def test_record_current_with_validator(tmp_path: Path) -> None:
    clients = _with_fake_validator(tmp_path, VALIDATOR_OUTPUT)
    assert _record_current("pass", clients) == []
    fail = _record_current("fail", clients)
    assert fail
    assert all(f.outcome == Outcome.FAIL for f in fail)
    assert any("$.fs.read" in f.message for f in fail)


def test_validator_failure_is_not_evaluated(tmp_path: Path) -> None:
    clients = _with_fake_validator(tmp_path, "✘ Validation failed\n", exit_code=1)
    assert [f.outcome for f in _record_current("pass", clients)] == [Outcome.NOT_EVALUATED]
