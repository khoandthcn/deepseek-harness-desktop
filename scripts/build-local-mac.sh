#!/usr/bin/env bash
# Build an unsigned DeepSeek Harness Desktop .dmg for this Mac's architecture.
#
#   ./scripts/build-local-mac.sh [upstream-ref]
#
# Reuses .work/upstream when it already exists; delete it to switch refs.
set -euo pipefail
cd "$(dirname "$0")/.."

REF="${1:-dsh-v0.1.5-rc.1}"
WORK=.work/upstream

if [ ! -d "$WORK/.git" ]; then
  git clone --depth 1 --branch "$REF" https://github.com/deepseek-ai/deepseek-harness.git "$WORK"
fi
node scripts/patch-upstream.mjs "$WORK"

case "$(uname -m)" in
  arm64) TARGET=mac-arm64 SCRIPT=mac:arm64 ;;
  x86_64) TARGET=mac-x64 SCRIPT=mac:x64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
export DSH_TELEMETRY_DISABLED=1
export DSH_DESKTOP_UNSIGNED=1
export DSH_DESKTOP_APP_ID="${DSH_DESKTOP_APP_ID:-io.github.khoandthcn.deepseekharness}"
export DSH_DESKTOP_GITHUB_REPOSITORY="${DSH_DESKTOP_GITHUB_REPOSITORY:-khoandthcn/deepseek-harness-desktop}"
export DSH_DESKTOP_AUTO_UPDATE_ENV=test
export DOWNLOAD_TEST_ORIGIN=https://github.com

cd "$WORK"
corepack pnpm install --frozen-lockfile
corepack pnpm run "package:desktop:$SCRIPT"
ls -la "apps/desktop/.desktop-build/targets/$TARGET/artifacts"
