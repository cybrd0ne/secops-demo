#!/bin/bash
# .claude/hooks/guard.sh
file=$(jq -r '.tool_input.file_path // empty')
case "$file" in
*.env|*.env.*|*/secrets/*)
echo "Blocked by policy: $file is a secret path (memory-poisoning guard)" >&2
exit 2 ;; # exit 2 blocks the tool call; stderr is the reason Claude sees
esac
exit 0
