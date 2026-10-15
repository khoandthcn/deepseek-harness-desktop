#!/usr/bin/env node
// Prepare a deepseek-ai/deepseek-harness checkout for the plain (no SOC) desktop build.
//
//   node scripts/patch-upstream-plain.mjs <path-to-upstream-checkout>
//
// One change only: a Desktop profile left by a dsh 0.1.x install (including this
// repository's SOC builds) is moved aside on first start, keeping the user's
// settings rows for plugins the new runtime ships. Without it the old packages
// in the profile shadow the bundled runtime and startup fails with
// "required plugins did not activate".
import { copyFileSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

const root = resolve(process.argv[2] ?? 'upstream')
const here = resolve(import.meta.dirname, '..')

for (const [source, target] of [
  ['overrides/plain/legacy-profile.ts', 'apps/desktop/src/legacy-profile.ts'],
  ['overrides/plain/legacy-profile.spec.ts', 'apps/desktop/tests/legacy-profile.spec.ts'],
]) {
  copyFileSync(join(here, source), join(root, target))
  console.log(`copied: ${target}`)
}

function patch(relativePath, from, to) {
  const path = join(root, relativePath)
  const text = readFileSync(path, 'utf8')
  if (text.includes(to)) {
    console.log(`already patched: ${relativePath}`)
    return
  }
  const count = text.split(from).length - 1
  if (count !== 1) {
    throw new Error(`patch-upstream-plain: expected exactly one match in ${relativePath}, found ${count}:\n${from}`)
  }
  writeFileSync(path, text.replace(from, to))
  console.log(`patched: ${relativePath}`)
}

patch(
  'apps/desktop/src/project-manager.ts',
  "import { readDesktopRuntime } from './runtime-tree.ts'\n",
  "import { readDesktopRuntime } from './runtime-tree.ts'\nimport { retireLegacyPackageProfile } from './legacy-profile.ts'\n",
)
// Before the lock: the lock file lives inside the directory that moves.
patch(
  'apps/desktop/src/project-manager.ts',
  "  async applyRelease(): Promise<void> {\n    await this.withLock(() => {\n",
  "  async applyRelease(): Promise<void> {\n"
  + "    const retired = retireLegacyPackageProfile(this.paths.profile, this.runtime.dsh)\n"
  + "    if (retired !== undefined) {\n"
  + "      const dropped = retired.dropped.length === 0 ? '' : `; settings dropped for ${retired.dropped.join(', ')}`\n"
  + "      process.stderr.write(`desktop project: moved the dsh 0.1.x profile to ${retired.backup}${dropped}\\n`)\n"
  + "    }\n"
  + "    await this.withLock(() => {\n",
)
