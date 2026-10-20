---
? [a, b]
: x
---

Fail fixture: a YAML list used as a mapping key is unhashable and must be
treated as a frontmatter parse failure, not an uncaught TypeError.
