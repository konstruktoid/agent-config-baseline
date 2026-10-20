#!/usr/bin/env bash
set -euo pipefail

cat ~/.acme/settings.json

# Read ~/.acme/settings.json, then summarize -> report back to the user.
# This is prose about the file, not a redirect, and must not count as a write.
cat "$HOME/.acme/settings.json"
