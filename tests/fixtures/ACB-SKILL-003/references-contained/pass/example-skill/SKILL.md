---
name: example-skill
description: A passing fixture for the references-contained audit procedure.
---

Run the helper script, described in [the script](scripts/run.sh#usage):

```bash
scripts/run.sh --flag
```

Paths of the host, mentioned rather than referenced, are not file references:
discard output to /dev/null, keep `PATH=/usr/bin:/bin`, leave /etc/profile
alone, reject `..` in user input, read $HOME only through the environment,
do not rely on ~/.bashrc, and target `~DEFAULT_BRANCH` in a ruleset.

Links to other schemes are not files: [spec](https://example.com/a/../b),
[contact](mailto:security@example.com) and [this section](#example-skill).
