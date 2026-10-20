#!/bin/sh
# Refuses writes outside src/.
path=$(jq -r '.tool_input.file_path')
case "$path" in
  src/*) exit 0 ;;
  *) echo "blocked: $path" >&2; exit 2 ;;
esac
