---
name: escape-skill
description: A fail fixture proving a symlink inside the skill directory is flagged, and that a reference through it genuinely resolves outside the skill directory rather than being caught by a dot-dot segment check.
---

This skill contains a symlink named escape and references
escape/secret.txt in its body, a token with no dot-dot segment at all.
