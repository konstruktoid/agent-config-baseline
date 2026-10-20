---
name: boundary-skill
description: A fail fixture proving executables-referenced matches whole path tokens (not substrings) and ignores references hidden inside HTML comments.
---

Run the helper script:

```bash
scripts/run.sh --flag
```

This skill also bundles an unrelated, unreferenced decoy script whose name
is a short text substring of the path above, and another script that is
mentioned only inside a hidden comment, not in reviewable text:

<!-- scripts/evil.sh -->
