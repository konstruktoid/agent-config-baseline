---
name: home-and-uri-skill
description: A fail fixture covering home-directory links, file:// URIs, links that leave the skill and backslash-style traversal.
---

This skill wrongly reaches outside itself in several ways:

- file URI reference: file:///etc/shadow
- backslash traversal: ..\..\secret
- percent-encoded link: [notes](%2e%2e/other-skill/notes.md)
- home link: [credentials](~/.aws/credentials)

[shared]: ../other-skill/shared.md
