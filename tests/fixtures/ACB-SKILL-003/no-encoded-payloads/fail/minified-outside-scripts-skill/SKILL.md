---
name: minified-outside-scripts-skill
description: A fail fixture with a minified, non-shebang script file outside scripts/, to prove minified assets get the long-line check regardless of directory.
---

This skill bundles lib/app.min.js, a minified file with no shebang that
lives outside scripts/.
