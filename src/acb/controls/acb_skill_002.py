"""ACB-SKILL-002: Skills do not pre-approve tools."""

from __future__ import annotations

import yaml

from acb.model import Finding, Outcome
from acb.scan import safe_read_text, split_frontmatter
from acb.yamlsafe import safe_load_strict

CONTROL_ID = "ACB-SKILL-002"

# The control blocks the *intent* of self-granted tool approval, not one
# specific spelling of the key. ACB-SKILL-001's optional-fields audit
# separately flags any of these as an unknown top-level key, but that is a
# distinct concern (frontmatter hygiene) from this control's (authorization).
_ALLOWED_TOOLS_KEYS = {"allowed-tools", "allowed_tools", "allowedTools"}


def _allowed_tools_keys(data: dict) -> set:
    return _ALLOWED_TOOLS_KEYS & data.keys()


def _check_no_allowed_tools(ctx) -> list[Finding]:
    findings: list[Finding] = []
    for skill in ctx.inventory.skills:
        text = safe_read_text(skill.skill_md)
        if text is None:
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="no-allowed-tools",
                    outcome=Outcome.NOT_EVALUATED,
                    message="SKILL.md could not be read (not valid UTF-8 text, or is a symlink); cannot verify",
                    path=ctx.relative(skill.skill_md),
                )
            )
            continue

        frontmatter_raw, _body = split_frontmatter(text)
        if frontmatter_raw is None:
            continue

        try:
            data = safe_load_strict(frontmatter_raw)
        except (yaml.YAMLError, ValueError, TypeError, RecursionError):
            # TypeError: unhashable mapping key. RecursionError: pathologically
            # deep nesting. Both mean "does not parse"; frontmatter-parses
            # (ACB-SKILL-001) is the control that reports the parse failure.
            continue

        if not isinstance(data, dict):
            continue

        rel = ctx.relative(skill.skill_md)

        for key in sorted(_allowed_tools_keys(data)):
            findings.append(
                Finding(
                    control_id=CONTROL_ID,
                    audit_id="no-allowed-tools",
                    outcome=Outcome.FAIL,
                    message=f"top-level `{key}` key is present in frontmatter",
                    path=rel,
                )
            )

        metadata = data.get("metadata")
        if isinstance(metadata, dict):
            for key in sorted(_allowed_tools_keys(metadata)):
                findings.append(
                    Finding(
                        control_id=CONTROL_ID,
                        audit_id="no-allowed-tools",
                        outcome=Outcome.FAIL,
                        message=f"`{key}` key is present nested under `metadata`",
                        path=rel,
                    )
                )
    return findings


AUDITS = {
    "no-allowed-tools": _check_no_allowed_tools,
}
