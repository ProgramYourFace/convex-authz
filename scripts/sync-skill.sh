#!/bin/bash
# Syncs SKILL.md content from README.md, preserving the YAML frontmatter.
# Called automatically by the npm "version" lifecycle hook.
set -euo pipefail

SKILL_FILE="SKILL.md"
README_FILE="README.md"

if [ ! -f "$README_FILE" ]; then
  echo "README.md not found, skipping SKILL.md sync"
  exit 0
fi

# Extract frontmatter from existing SKILL.md (everything between first --- and second ---)
FRONTMATTER=$(awk '/^---$/{n++} n<=2' "$SKILL_FILE")

# Rebuild SKILL.md: frontmatter + README content
{
  echo "$FRONTMATTER"
  echo ""
  cat "$README_FILE"
} > "$SKILL_FILE"

echo "SKILL.md synced from README.md"
git add "$SKILL_FILE"
