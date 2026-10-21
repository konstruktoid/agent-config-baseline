"""ACB-SKILL-001: SKILL.md frontmatter conforms to the Agent Skills specification."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import yaml

from acb.model import Finding, Outcome
from acb.scan import safe_read_text, split_frontmatter
from acb.yamlsafe import safe_load_strict

if TYPE_CHECKING:
    from pathlib import Path

    from acb.controls import CheckContext

CONTROL_ID = "ACB-SKILL-001"
_NAME_MAX_LENGTH = 64
_DESCRIPTION_MAX_LENGTH = 1024
_COMPATIBILITY_MAX_LENGTH = 500

_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
_KNOWN_OPTIONAL_KEYS = {"license", "compatibility", "metadata", "allowed-tools"}
_KNOWN_KEYS = {"name", "description"} | _KNOWN_OPTIONAL_KEYS


def _parse_frontmatter(skill_md_path: Path) -> dict | None:
    """Return the parsed frontmatter mapping, or None if it does not parse."""
    text = safe_read_text(skill_md_path)
    if text is None:
        return None
    frontmatter_raw, _body = split_frontmatter(text)
    if frontmatter_raw is None:
        return None
    try:
        data = safe_load_strict(frontmatter_raw)
    except (yaml.YAMLError, ValueError, TypeError, RecursionError):
        # TypeError: an unhashable mapping key (e.g. a YAML list used as a
        # key) blows up the strict constructor's `dict` lookup.
        # RecursionError: pathologically deep nesting exhausts the stack.
        # Both mean "does not parse", same as a YAMLError/ValueError.
        return None
    if not isinstance(data, dict):
        return None
    return data


def _check_frontmatter_parses(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for skill in ctx.inventory.skills:
        text = safe_read_text(skill.skill_md)
        if text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="frontmatter-parses",
                    outcome=Outcome.NOT_EVALUATED,
                    message="SKILL.md could not be read (not valid UTF-8 text, or is a symlink)",
                    path=ctx.relative(skill.skill_md),
                )
            )
            continue

        frontmatter_raw, _body = split_frontmatter(text)
        if frontmatter_raw is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="frontmatter-parses",
                    outcome=Outcome.FAIL,
                    message="SKILL.md does not begin with a `---`-delimited frontmatter block",
                    path=ctx.relative(skill.skill_md),
                )
            )
            continue

        try:
            data = safe_load_strict(frontmatter_raw)
        except (yaml.YAMLError, ValueError, TypeError, RecursionError) as exc:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="frontmatter-parses",
                    outcome=Outcome.FAIL,
                    message=f"frontmatter failed to parse: {exc}",
                    path=ctx.relative(skill.skill_md),
                )
            )
            continue

        if not isinstance(data, dict):
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="frontmatter-parses",
                    outcome=Outcome.FAIL,
                    message="frontmatter does not parse to a mapping",
                    path=ctx.relative(skill.skill_md),
                )
            )
    return findings


def _check_required_fields(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for skill in ctx.inventory.skills:
        data = _parse_frontmatter(skill.skill_md)
        if data is None:
            continue  # covered by frontmatter-parses

        rel = ctx.relative(skill.skill_md)

        name = data.get("name")
        if not isinstance(name, str) or not (1 <= len(name) <= _NAME_MAX_LENGTH) or not _NAME_RE.match(name):
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="required-fields",
                    outcome=Outcome.FAIL,
                    message=f"`name` {name!r} must be 1-64 chars matching ^[a-z0-9]+(-[a-z0-9]+)*$",
                    path=rel,
                )
            )
        elif name != skill.directory.name:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="required-fields",
                    outcome=Outcome.FAIL,
                    message=f"`name` {name!r} does not match directory name {skill.directory.name!r}",
                    path=rel,
                )
            )

        description = data.get("description")
        if not isinstance(description, str) or not description or len(description) > _DESCRIPTION_MAX_LENGTH:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="required-fields",
                    outcome=Outcome.FAIL,
                    message="`description` must be a non-empty string of at most 1024 characters",
                    path=rel,
                )
            )
    return findings


def _check_optional_fields(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    for skill in ctx.inventory.skills:
        data = _parse_frontmatter(skill.skill_md)
        if data is None:
            continue  # covered by frontmatter-parses

        rel = ctx.relative(skill.skill_md)

        findings.extend(
            Finding(
                control_id=CONTROL_ID,
                audit_id="optional-fields",
                outcome=Outcome.FAIL,
                message=f"unknown top-level frontmatter key {key!r}",
                path=rel,
            )
            for key in data
            if key not in _KNOWN_KEYS
        )

        if "license" in data and not isinstance(data["license"], str):
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="optional-fields",
                    outcome=Outcome.FAIL,
                    message="`license` must be a string",
                    path=rel,
                )
            )

        if "compatibility" in data:
            compatibility = data["compatibility"]
            if not isinstance(compatibility, str) or not (1 <= len(compatibility) <= _COMPATIBILITY_MAX_LENGTH):
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="optional-fields",
                        outcome=Outcome.FAIL,
                        message="`compatibility` must be a string of 1-500 characters",
                        path=rel,
                    )
                )

        if "metadata" in data:
            metadata = data["metadata"]
            if not isinstance(metadata, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in metadata.items()
            ):
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="optional-fields",
                        outcome=Outcome.FAIL,
                        message="`metadata` must be a mapping of string keys to string values",
                        path=rel,
                    )
                )

        if "allowed-tools" in data and not isinstance(data["allowed-tools"], str):
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="optional-fields",
                    outcome=Outcome.FAIL,
                    message="`allowed-tools` must be a string",
                    path=rel,
                )
            )
    return findings


AUDITS = {
    "frontmatter-parses": _check_frontmatter_parses,
    "required-fields": _check_required_fields,
    "optional-fields": _check_optional_fields,
}
