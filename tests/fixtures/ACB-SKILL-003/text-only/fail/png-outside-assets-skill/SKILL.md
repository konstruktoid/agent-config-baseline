---
name: png-outside-assets-skill
description: A fail fixture proving the image exception applies only to assets/, not to PNG-magic-byte content anywhere in the skill.
---

This skill bundles a file at scripts/payload whose first bytes are a PNG
magic number, but which lives outside assets/ and is not actually an image.
