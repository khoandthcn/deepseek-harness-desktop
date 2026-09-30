/**
 * The skills that ship with the SOC preset.
 *
 * A skill here is a directory under `skills/` beside this package's `lib/` —
 * instructions plus the scripts they run. They travel inside the package, so a
 * build that mounts this plugin offers them with nothing to install.
 *
 * It mounts a second filesystem skill provider rather than adding a root to the
 * preset's own: that one scans the user's and the project's directories, and
 * its configuration is the deployment's to change. This provider sees only the
 * shipped directory and answers under its own name, so the two never discover
 * the same skill twice.
 *
 * A skill of the same name in the user's or the project's skill directory
 * outranks the shipped one, which is how a team overrides or pins a version.
 *
 * @module @deepseek-ai/dsh-soc-skills
 */

import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Context } from '@deepseek-ai/cordis'
import * as skillFilesystem from '@deepseek-ai/dsh-skill-filesystem'

export const name = 'soc-skills'

/** The skill registry this provider registers on. */
export const inject = ['skills']

/** Provider name, distinct from the preset's own `filesystem` provider. */
export const PROVIDER_NAME = 'soc-skills'

/**
 * Where the shipped skills live: `skills/` beside the built `lib/` (or beside
 * `src/` when run from source).
 * @param moduleUrl - this module's URL.
 * @returns the absolute directory.
 */
export function shippedSkillsDir(moduleUrl: string = import.meta.url): string {
  return join(dirname(fileURLToPath(moduleUrl)), '..', 'skills')
}

/**
 * Offer the shipped skills to agents on this preset.
 * @param ctx - the mounting context.
 */
export function apply(ctx: Context): void {
  ctx.plugin(skillFilesystem, {
    providerName: PROVIDER_NAME,
    includeDefaultRoots: false,
    bundledSkillDir: shippedSkillsDir(),
  })
}
