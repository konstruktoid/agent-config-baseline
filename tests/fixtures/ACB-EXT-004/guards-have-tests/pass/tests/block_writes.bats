#!/usr/bin/env bats

@test "block-writes.sh refuses a write outside src/" {
  run sh hooks/block-writes.sh <<< '{"tool_input":{"file_path":"README.md"}}'
  [ "$status" -eq 2 ]
}
