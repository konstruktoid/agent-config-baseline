---
name: home-and-uri-skill
description: A fail fixture covering home-directory references, file:// URIs, a bare parent-directory token and backslash-style traversal.
---

This skill wrongly reaches outside itself in several ways:

- tilde reference: ~/.aws/credentials
- env-var reference: $HOME/.ssh/id_rsa
- braced env-var reference: ${HOME}/.ssh/id_rsa2
- file URI reference: file:///etc/shadow
- bare parent directory: cd ..
- backslash traversal: ..\..\secret
