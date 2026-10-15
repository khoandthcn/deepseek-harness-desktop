#!/usr/bin/env node
// Prepare a deepseek-ai/deepseek-harness checkout for the plain (no SOC) desktop build.
//
//   node scripts/patch-upstream-plain.mjs <path-to-upstream-checkout>
//
// Two changes, both for users upgrading from this repository's SOC builds:
// 1. A Desktop profile left by a dsh 0.1.x install is moved aside on first
//    start, keeping the user's settings rows for plugins the new runtime ships.
//    Without it the old packages in the profile shadow the bundled runtime and
//    startup fails with "required plugins did not activate".
// 2. A saved Session whose recorded agent preset is no longer registered
//    (`soc-cloud`, `standard-brave`) resumes under the default preset instead
//    of failing with "Unknown agent preset". Upstream already does this for
//    blank Sessions (ui-workspace navigation.ts, restoreBlank).
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

// Resume under the default preset once the recorded one is gone.
patch(
  'packages/api/session-controller/src/agent.ts',
  "    const composition = await this.composeAgent(this.presetForObservation(observation))\n",
  "    const composition = await this.composeResumed(this.presetForObservation(observation))\n",
)
patch(
  'packages/api/session-controller/src/agent.ts',
  "  private liveAgent(sessionId: SessionId): ApiSessionAgentResult | undefined {\n",
  "  /**\n"
  + "   * Compose a resumed Agent under its recorded preset, or under the default once that preset is no longer\n"
  + "   * registered — an application update can remove a preset that saved Sessions still name.\n"
  + "   * @param recorded - preset the Session log recorded, if any.\n"
  + "   * @returns the composition for the recorded preset, or for the default when the recorded one is unknown.\n"
  + "   */\n"
  + "  private async composeResumed(recorded: string | undefined): Promise<ApiSessionComposition> {\n"
  + "    try {\n"
  + "      return await this.composeAgent(recorded)\n"
  + "    } catch (error: unknown) {\n"
  + "      if (recorded === undefined || remoteErrorOf(error)?.code !== 'agent-preset/not-found') throw error\n"
  + "      return await this.composeAgent(undefined)\n"
  + "    }\n"
  + "  }\n"
  + "\n"
  + "  private liveAgent(sessionId: SessionId): ApiSessionAgentResult | undefined {\n",
)
