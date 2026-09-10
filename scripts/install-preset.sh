#!/usr/bin/env bash
# Install the `standard-brave` agent preset into the DeepSeek Harness home and make it
# the default for new sessions. Works for both dsh CLI and DeepSeek Harness Desktop.
#
#   ./scripts/install-preset.sh            # install + set default
#   ./scripts/install-preset.sh --no-default
set -euo pipefail

PRESET=standard-brave
SRC="$(cd "$(dirname "$0")/.." && pwd)/presets/$PRESET"
DSH_HOME_DIR="${DSH_HOME:-$HOME/.dsh}"
DEST="$DSH_HOME_DIR/.agent-presets/$PRESET"
SETTINGS="$DSH_HOME_DIR/settings.yaml"

[ -f "$SRC/agent.cordis.yml" ] || { echo "missing $SRC/agent.cordis.yml" >&2; exit 1; }
mkdir -p "$DEST"
cp "$SRC/agent.cordis.yml" "$SRC/preset.yml" "$DEST/"
echo "Installed preset: $DEST"

if [ "${1:-}" = "--no-default" ]; then exit 0; fi

if [ ! -s "$SETTINGS" ] || [ "$(tr -d '[:space:]' < "$SETTINGS")" = "{}" ]; then
  printf 'agent-presets:\n  default: %s\n' "$PRESET" > "$SETTINGS"
  echo "Default preset set in $SETTINGS"
elif grep -qE '^agent-presets:' "$SETTINGS"; then
  if grep -qE "^[[:space:]]+default:[[:space:]]*$PRESET[[:space:]]*$" "$SETTINGS"; then
    echo "Default preset already $PRESET"
  else
    echo "$SETTINGS already has an agent-presets section; set its default to $PRESET by hand:"
    printf '  agent-presets:\n    default: %s\n' "$PRESET"
  fi
else
  printf '\nagent-presets:\n  default: %s\n' "$PRESET" >> "$SETTINGS"
  echo "Default preset set in $SETTINGS"
fi
echo "New sessions now use '$PRESET'; running sessions keep their preset."
