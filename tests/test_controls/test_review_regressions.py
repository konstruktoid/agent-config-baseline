"""Regressions for false passes found in review of the EXT and CFG controls."""

import json
import os
import sys
from dataclasses import replace

from acb.controls import acb_cfg_002, acb_cfg_004, acb_ext_001, acb_ext_003
from acb.model import Outcome
from tests._harness import context_for
from tests.test_controls._bundled import BUNDLED


def _package(root, manifest=None, hooks_json=None, module=None, readme=None):
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(json.dumps(manifest or {"name": "p"}))
    if hooks_json is not None:
        (root / "hooks").mkdir(exist_ok=True)
        (root / "hooks" / "hooks.json").write_text(json.dumps(hooks_json))
    if module is not None:
        (root / "hooks").mkdir(exist_ok=True)
        (root / "hooks" / "register.js").write_text(module)
    if readme is not None:
        (root / "README.md").write_text(readme)


def test_missing_manifest_hook_file_is_not_evaluated(tmp_path):
    _package(tmp_path, manifest={"name": "p", "hooks": "./config/gone.json"})
    findings = acb_ext_001.AUDITS["modules-documented"](context_for(tmp_path, BUNDLED))
    assert [f.outcome for f in findings] == [Outcome.NOT_EVALUATED]


def test_module_through_symlinked_directory_outside_is_not_evaluated(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "m.js").write_text("export function register(on) {}\n")
    pkg = tmp_path / "pkg"
    _package(pkg, hooks_json={"modules": ["./lnk/m.js"]}, readme="nothing")
    os.symlink(outside, pkg / "hooks" / "lnk")
    findings = acb_ext_001.AUDITS["modules-documented"](context_for(pkg, BUNDLED))
    assert Outcome.NOT_EVALUATED in {f.outcome for f in findings}
    assert all("outside" in f.message or "symlinked" in f.message for f in findings if f.outcome == Outcome.NOT_EVALUATED)


def test_readme_naming_a_longer_file_does_not_declare_the_module(tmp_path):
    _package(tmp_path, hooks_json={"modules": ["./register.js"]}, module="export function register(on) {}\n",
             readme="We ship hooks/register.json only.\n")
    findings = acb_ext_001.AUDITS["modules-documented"](context_for(tmp_path, BUNDLED))
    assert [f.outcome for f in findings] == [Outcome.FAIL]


def test_integer_one_is_not_true_in_managed_requirements(tmp_path):
    (tmp_path / "managed-settings.json").write_text(json.dumps({"disableSideloadFlags": 1}))
    findings = acb_cfg_002.AUDITS["managed-sideload-disabled"](context_for(tmp_path, BUNDLED))
    assert [f.outcome for f in findings] == [Outcome.FAIL]


def test_handler_registration_with_space_before_paren_is_seen(tmp_path):
    _package(tmp_path, hooks_json={"modules": ["./register.js"]},
             module="export function register(on) {\n  on ('tool.check', f)\n  $ ?. process . run('x')\n}\n")
    findings = acb_cfg_004.AUDITS["approval-not-delegated"](context_for(tmp_path, BUNDLED))
    assert [f.outcome for f in findings] == [Outcome.FAIL]


def test_committed_local_settings_file_is_discovered(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.local.json").write_text(json.dumps({"permissions": {"allow": ["Bash"]}}))
    ctx = context_for(tmp_path, BUNDLED)
    assert [s.path.name for s in ctx.inventory.agent_settings] == ["settings.local.json"]


def _fake_validator(tmp_path, body):
    script = tmp_path / "fake_validator.py"
    script.write_text(body)
    profile = dict(BUNDLED.profile("claude-code"))
    extension = dict(profile["extension_packages"])
    extension["validator"] = dict(extension["validator"], command=[sys.executable, str(script)])
    profile["extension_packages"] = extension
    return replace(BUNDLED, profiles=(("claude-code", profile),))


def test_validator_output_without_capability_lines_is_not_evaluated(tmp_path):
    pkg = tmp_path / "pkg"
    _package(pkg, hooks_json={"modules": ["./register.js"]}, module="export function register(on) {}\n")
    (pkg / "extension-capabilities.txt").write_text("nothing recorded\n")
    clients = _fake_validator(tmp_path, "print('ok')\n")
    ctx = replace(context_for(pkg, clients), run_validators=True)
    findings = acb_ext_003.AUDITS["record-current"](ctx)
    assert [f.outcome for f in findings] == [Outcome.NOT_EVALUATED]


def test_validator_gets_no_inherited_secrets_and_no_terminal_escapes(tmp_path, monkeypatch):
    monkeypatch.setenv("ACB_TEST_SECRET", "s3cret")
    pkg = tmp_path / "pkg"
    _package(pkg, hooks_json={"modules": ["./register.js"]}, module="export function register(on) {}\n")
    clients = _fake_validator(
        tmp_path, "import os, sys\nprint('\\x1b[31m' + os.environ.get('ACB_TEST_SECRET', 'none'))\nsys.exit(3)\n"
    )
    ctx = replace(context_for(pkg, clients), run_validators=True)
    [finding] = acb_ext_003.AUDITS["record-current"](ctx)
    assert finding.outcome == Outcome.NOT_EVALUATED
    assert "s3cret" not in finding.message and "none" in finding.message and "\x1b" not in finding.message
