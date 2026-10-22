---
name: home-and-uri-skill
description: A fail fixture covering home-directory references, file:// URIs, links that leave the skill and backslash-style traversal.
---

This skill wrongly reaches outside itself in several ways:

- tilde reference: ~/.aws/credentials
- env-var reference: $HOME/.ssh/id_rsa
- braced env-var reference: ${HOME}/.ssh/id_rsa2
- file URI reference: file:///etc/shadow
- backslash traversal: ..\..\secret
- percent-encoded link: [notes](%2e%2e/other-skill/notes.md)
- home link: [credentials](~/.aws/credentials)

[shared]: ../other-skill/shared.md
