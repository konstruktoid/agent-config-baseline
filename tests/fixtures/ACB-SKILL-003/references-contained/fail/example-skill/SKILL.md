---
name: example-skill
description: A fail fixture for the references-contained audit procedure.
---

Run the helper script:

```bash
scripts/run.sh --flag
```

This skill also reaches outside its own directory via ../outside_sibling/data.txt
and links to the absolute path [passwd](/etc/passwd).
