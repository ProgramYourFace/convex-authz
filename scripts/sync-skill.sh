#!/bin/bash
# Syncs SKILL.md content from README.md, preserving the YAML frontmatter.
# Strips sections between <!-- SKILL-EXCLUDE-START --> and <!-- SKILL-EXCLUDE-END -->.
# Called automatically by the npm "version" lifecycle hook.
set -euo pipefail

SKILL_FILE="skills/convex-authz/SKILL.md"
README_FILE="README.md"

if [ ! -f "$README_FILE" ]; then
  echo "README.md not found, skipping SKILL.md sync"
  exit 0
fi

# Extract frontmatter from existing SKILL.md (everything between first --- and second ---)
FRONTMATTER=$(awk '/^---$/{n++; print; if(n==2) exit; next} n>=1{print}' "$SKILL_FILE")

# Rebuild SKILL.md: frontmatter + README content (excluding marked sections)
{
  echo "$FRONTMATTER"
  echo ""
  awk '/<!-- SKILL-EXCLUDE-START -->/{skip=1; next} /<!-- SKILL-EXCLUDE-END -->/{skip=0; next} !skip' "$README_FILE"
} > "$SKILL_FILE"

echo "SKILL.md synced from README.md"
git add "$SKILL_FILE"
