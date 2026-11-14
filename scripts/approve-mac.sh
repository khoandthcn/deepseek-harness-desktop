#!/usr/bin/env bash
# Let macOS open DeepSeek Harness after installing it from a .dmg.
#
#   ./scripts/approve-mac.sh [path/to/DeepSeek Harness.app]
#
# The build is not notarized, so Gatekeeper blocks it ("cannot be opened" or
# "is damaged") while the download's quarantine flag is on it. This clears the
# flag, checks that the ad-hoc signature is intact, and opens the app. Default path: /Applications/DeepSeek Harness.app.
set -euo pipefail

APP="${1:-/Applications/DeepSeek Harness.app}"
if [ ! -d "$APP" ]; then
  echo "not found: $APP" >&2
  echo "drag DeepSeek Harness from the .dmg into Applications first, or pass the app's path" >&2
  exit 1
fi

# /Applications usually belongs to the user; otherwise the change needs sudo.
run() { if [ -w "$APP" ]; then "$@"; else sudo "$@"; fi; }

echo "clearing quarantine: $APP"
run xattr -dr com.apple.quarantine "$APP"

# Re-signing would drop the entitlements the build was signed with, so a
# broken signature means a broken copy: install it again from the .dmg.
if ! codesign --verify --deep "$APP" 2>/dev/null; then
  echo "the app's signature does not verify; reinstall it from the .dmg" >&2
  exit 1
fi

version="$(defaults read "$APP/Contents/Info" CFBundleShortVersionString 2>/dev/null || echo '?')"
echo "approved: DeepSeek Harness $version"
open "$APP"
