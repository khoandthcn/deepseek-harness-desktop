#!/usr/bin/env bash
# Install the newest locally built DeepSeek Harness Desktop on this Mac.
#
#   ./scripts/install-local-mac.sh [path/to/build.dmg]
#
# With no argument it takes the newest .dmg that build-local-mac.sh produced.
# Settings, sessions and credentials under ~/.dsh are left as they are.
set -euo pipefail
cd "$(dirname "$0")/.."

APP="DeepSeek Harness.app"
WORK="${DSH_SOC_WORK:-.work/upstream}"
case "$(uname -m)" in
  arm64) TARGET=mac-arm64 ;;
  x86_64) TARGET=mac-x64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

DMG="${1:-$(ls -t "$WORK/apps/desktop/.desktop-build/targets/$TARGET/artifacts"/*.dmg 2>/dev/null | head -1)}"
if [ -z "$DMG" ] || [ ! -f "$DMG" ]; then
  echo "no .dmg found; run ./scripts/build-local-mac.sh first, or pass a path" >&2
  exit 1
fi
echo "installing: $DMG"

# A running copy keeps its files open and would be half replaced.
if pgrep -f "/Applications/$APP/" >/dev/null; then
  osascript -e 'tell application "DeepSeek Harness" to quit' 2>/dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pgrep -f "/Applications/$APP/" >/dev/null || break
    sleep 1
  done
  if pgrep -f "/Applications/$APP/" >/dev/null; then
    echo "DeepSeek Harness is still running; quit it and run this again" >&2
    exit 1
  fi
fi

MOUNT="$(mktemp -d /tmp/dsh-install.XXXXXX)"
trap 'hdiutil detach "$MOUNT" -quiet 2>/dev/null || true; rmdir "$MOUNT" 2>/dev/null || true' EXIT
hdiutil attach "$DMG" -nobrowse -readonly -mountpoint "$MOUNT" -quiet
if [ ! -d "$MOUNT/$APP" ]; then
  echo "the disk image holds no $APP" >&2
  exit 1
fi
rm -rf "/Applications/$APP"
cp -R "$MOUNT/$APP" /Applications/
# The build is unsigned: without this, macOS reports it as damaged.
xattr -cr "/Applications/$APP"

# Skills installed by hand before they shipped with the application take
# precedence over the shipped ones, so an old copy would hide the new skill.
# Moved aside, not deleted.
HOME_DIR="${DSH_HOME:-$HOME/.dsh}"
for skill in monthly-mss-report; do
  if [ -d "$HOME_DIR/skills/$skill" ]; then
    backup="$HOME_DIR/skill-backups/$skill-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$HOME_DIR/skill-backups"
    mv "$HOME_DIR/skills/$skill" "$backup"
    echo "moved the hand-installed skill aside: $backup"
  fi
done

echo "installed: /Applications/$APP"
echo "open it with: open -a \"DeepSeek Harness\""
