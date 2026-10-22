from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from acb.controls.acb_gen_003 import AUDITS
from tests._harness import context_for
from tests.test_controls._shared import check_pass_and_fail

if TYPE_CHECKING:
    from pathlib import Path

    from acb.model import Finding

TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"


def test_acb_gen_003_fixtures() -> None:
    check_pass_and_fail("ACB-GEN-003", AUDITS)


def test_secret_is_redacted_in_messages(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text(f"token: {TOKEN}\n")
    findings = AUDITS["secret-scan"](context_for(tmp_path))
    assert findings
    assert all(TOKEN not in f.message for f in findings)


def _mcp(tmp_path: Path, text: str, name: str = "mcp.yaml") -> list[Finding]:
    (tmp_path / name).write_text(text)
    return AUDITS["mcp-env-indirection"](context_for(tmp_path))


def test_path_like_keys_are_not_credentials(tmp_path: Path) -> None:
    payload = {"mcpServers": {"a": {"command": "x", "env": {"PATH": "/usr/bin", "PATTERN": "x", "BYPASS_CACHE": "1"}}}}
    assert _mcp(tmp_path, json.dumps(payload), "mcp.json") == []


def test_short_credential_word_as_name_segment_still_counts(tmp_path: Path) -> None:
    payload = {"mcpServers": {"a": {"command": "x", "env": {"GITHUB_PAT": "literalvalue123"}}}}
    findings = _mcp(tmp_path, json.dumps(payload), "mcp.json")
    assert findings
    assert "literalvalue123" not in findings[0].message


def test_non_string_keys_do_not_crash(tmp_path: Path) -> None:
    assert _mcp(tmp_path, "mcpServers:\n  a:\n    command: x\n    env:\n      1: foo\n") == []


def test_recursive_alias_does_not_crash(tmp_path: Path) -> None:
    assert _mcp(tmp_path, "mcpServers:\n  a:\n    command: x\n    env: &e\n      nested: *e\n") == []


def test_url_and_path_fragments_are_not_high_entropy_secrets(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text(
        "See https://docs.github.com/en/organizations/managing-organization-settings/managing-rulesets for rules,\n"
        "and repos/OWNER/REPO/actions/permissions/workflow in the API.\n"
    )
    assert AUDITS["secret-scan"](context_for(tmp_path)) == []


@pytest.mark.parametrize(
    "text",
    [
        "curl 'https://api.example.com/v1?token=Zk8pQ2vL9mXr3Tn7Yh5Wc1Bd6Fg4Jk2S'",
        "git clone https://Zk8pQ2vL9mXr3Tn7Yh5Wc1Bd6Fg4Jk2S@github.com/o/r.git",
        "https://hooks.slack.com/services/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",
        "aws_secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "key: Q7XK2M9PLW4RT8VN3ZB6YH1CJ5GD0FSA",
        "SG.Zk8pQ2vL9mXr3Tn7Yh5Wc1.Bd6Fg4Jk2SxxxxxxxxxxQ7XK2M9PLW4RT8",
        "gho_Zk8pQ2vL9mXr3Tn7Yh5Wc1Bd6Fg4Jk2S",
        "glpat-Zk8pQ2vL9mXr3Tn7Yh5W",
        "api_key = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "password=Tr0ub4dor3xyz",
        "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
    ],
)
def test_secret_shapes_the_filter_must_not_lose(tmp_path: Path, text: str) -> None:
    (tmp_path / "AGENTS.md").write_text(text + "\n")
    assert AUDITS["secret-scan"](context_for(tmp_path))


@pytest.mark.parametrize(
    "text",
    [
        "commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b is the base",
        "id 123e4567-e89b-12d3-a456-426614174000",
        "See https://docs.github.com/en/organizations/managing-organization-settings/managing-rulesets",
        "password: ${DB_PASSWORD}",
        "set the password to something strong",
    ],
)
def test_structure_is_not_a_secret(tmp_path: Path, text: str) -> None:
    (tmp_path / "AGENTS.md").write_text(text + "\n")
    assert AUDITS["secret-scan"](context_for(tmp_path)) == []


def test_named_list_entries_keep_their_other_fields(tmp_path: Path) -> None:
    payload = {"mcpServers": {"a": {"command": "x", "headers": [{"name": "primary", "password": "literalvalue123"}]}}}
    findings = _mcp(tmp_path, json.dumps(payload), "mcp.json")
    assert [f.message.split("'")[3] for f in findings] == ["password"]


def test_env_list_value_is_reported_once_under_its_name(tmp_path: Path) -> None:
    payload = {"mcpServers": {"a": {"command": "x", "env": [{"name": "API_KEY", "value": "literalvalue123"}]}}}
    findings = _mcp(tmp_path, json.dumps(payload), "mcp.json")
    assert [f.message.split("'")[3] for f in findings] == ["API_KEY"]


@pytest.mark.parametrize("secret", [1234, "pw12", "abcd1234efgh"])
def test_short_credential_reveals_no_characters(tmp_path: Path, secret: int | str) -> None:
    payload = {"mcpServers": {"a": {"command": "x", "env": {"PASSWORD": secret}}}}
    findings = _mcp(tmp_path, json.dumps(payload), "mcp.json")
    assert findings
    assert str(secret)[:4] not in findings[0].message
