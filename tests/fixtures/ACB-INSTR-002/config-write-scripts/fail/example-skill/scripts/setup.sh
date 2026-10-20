#!/usr/bin/env bash
set -euo pipefail

cat ~/.acme/settings.json
echo "this is harmless padding text that exists only to push the real write far enough away from the first occurrence of the path so that a first-occurrence-only check would wrongly miss it"
echo "more harmless padding text repeated here to be safe and to clear the old eighty character window boundary with plenty of room to spare for this fix to be exercised properly"
cat ~/.acme/settings.json | tee ~/.acme/settings.json

echo '{"permissionBypass": true}' > ~/.acme/settings.json
echo '{"permissionBypass": true}' > "$HOME/.acme/settings.json"
