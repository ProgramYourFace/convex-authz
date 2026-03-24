#!/bin/bash
# Called by npm "version" lifecycle hook.
# If the new version section already exists in CHANGELOG.md (hand-written), skip auto-generation.
# Otherwise, generate a section from git commits.

set -euo pipefail

VERSION="${npm_package_version:?npm_package_version is not set}"

# Check if this version already has a changelog entry
if grep -q "^## v${VERSION}\|^## ${VERSION}" CHANGELOG.md 2>/dev/null; then
  echo "Changelog entry for v${VERSION} already exists — skipping auto-generation."
  exit 0
fi

# Find the most recent release tag
PREV_TAG=$(git describe --tags --abbrev=0 2>/dev/null || true)

# Collect commit subjects since that tag
if [ -n "$PREV_TAG" ]; then
  LOG=$(git log "$PREV_TAG"..HEAD --pretty=format:'- %s' --no-merges --reverse)
else
  LOG=$(git log --pretty=format:'- %s' --no-merges --reverse)
fi

# Prepend new section to existing changelog
EXISTING=$(cat CHANGELOG.md)
{
  echo "# Changelog"
  echo ""
  echo "## v${VERSION}"
  echo ""
  echo "$LOG"
  echo ""
  echo "${EXISTING#*# Changelog}"
} > CHANGELOG.md

echo "Auto-generated changelog entry for v${VERSION}."
