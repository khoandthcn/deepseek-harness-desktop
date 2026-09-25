#!/usr/bin/env bash
# Build an unsigned DeepSeek Harness Desktop .dmg for this Mac's architecture.
#
#   ./scripts/build-local-mac.sh [upstream-ref]
#
# Reuses .work/upstream when it already exists; delete it to switch refs.
set -euo pipefail
cd "$(dirname "$0")/.."

REF="${1:-dsh-v0.1.5-rc.1}"
# The bundler labels CSS regions with the absolute path of their source, so the
# checkout's location travels inside every client package. A build meant for
# other people should therefore live somewhere that names nobody:
#   DSH_SOC_WORK=/tmp/dsh-build/upstream ./scripts/build-local-mac.sh
WORK="${DSH_SOC_WORK:-.work/upstream}"

mkdir -p "$(dirname "$WORK")"
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
# Not frozen: the patch declares the SOC workspace packages, which the upstream
# lockfile cannot know about (workspace links only).
corepack pnpm install
corepack pnpm run "package:desktop:$SCRIPT"
ls -la "apps/desktop/.desktop-build/targets/$TARGET/artifacts"
