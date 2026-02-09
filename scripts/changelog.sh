#!/bin/bash
# Auto-generate changelog entry from git commits since the last release tag.
# Called by the npm "version" lifecycle hook — $npm_package_version is the NEW version.

set -euo pipefail

VERSION="${npm_package_version:?npm_package_version is not set}"

# Find the most recent release tag (e.g. v0.1.4)
PREV_TAG=$(git describe --tags --abbrev=0 2>/dev/null || true)

# Collect commit subjects since that tag (skip merge commits)
if [ -n "$PREV_TAG" ]; then
  LOG=$(git log "$PREV_TAG"..HEAD --pretty=format:'- %s' --no-merges --reverse)
else
  LOG=$(git log --pretty=format:'- %s' --no-merges --reverse)
fi

# Strip the existing "# Changelog" header so we can rebuild it
EXISTING=$(sed '1{/^# Changelog$/d;}' CHANGELOG.md | sed '1{/^$/d;}')

# Write the updated changelog
{
  echo "# Changelog"
  echo ""
  echo "## ${VERSION}"
  echo ""
  echo "$LOG"
  echo ""
  echo "$EXISTING"
} > CHANGELOG.md
