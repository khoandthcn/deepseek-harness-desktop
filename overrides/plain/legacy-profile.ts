/** Retirement of Desktop profiles that dsh 0.1.x populated with their own installed packages. */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/** File a dsh 0.1.x Desktop profile kept beside the packages it installed. */
const LEGACY_PACKAGE_SET_FILE = 'desktop-packages.json'
const PROFILE_PATCH_FILE = 'cordis.patch.yml'

/** Outcome of {@link retireLegacyPackageProfile}, for the startup log. */
export interface LegacyProfileRetirement {
  /** Directory the old profile was moved to. */
  readonly backup: string
  /** Plugin names whose settings rows were dropped because this runtime does not ship them. */
  readonly dropped: readonly string[]
}

/**
 * Move a dsh 0.1.x profile aside before the current release prepares its own.
 *
 * Those releases installed every plugin into the profile's `node_modules`, and the Host resolves plugins
 * from the profile first, so the old copies shadow the bundled runtime and required services never start.
 * The whole directory moves to `<profile>.legacy-<time>`; the user's settings patch is carried over with
 * only the rows whose plugin the bundled runtime contains, since a row naming an absent plugin fails startup.
 * The caller must run this before taking the profile lock, which lives inside the moved directory.
 * @param profileDir - Desktop profile directory.
 * @param runtimeDsh - Bundled dsh runtime directory whose `node_modules` holds the shipped plugins.
 * @param now - Clock for the backup name.
 * @returns What was moved and dropped, or undefined when the profile is not a 0.1.x package profile.
 */
export function retireLegacyPackageProfile(
  profileDir: string,
  runtimeDsh: string,
  now: () => number = Date.now,
): LegacyProfileRetirement | undefined {
  if (!existsSync(join(profileDir, LEGACY_PACKAGE_SET_FILE))) return undefined
  const backup = `${profileDir}.legacy-${String(now())}`
  renameSync(profileDir, backup)
  mkdirSync(profileDir, { recursive: true, mode: 0o700 })
  const patchPath = join(backup, PROFILE_PATCH_FILE)
  if (!existsSync(patchPath)) return { backup, dropped: [] }
  const shipped = (name: string): boolean => existsSync(join(runtimeDsh, 'node_modules', name, 'package.json'))
  const { text, dropped } = keepShippedRows(readFileSync(patchPath, 'utf8'), shipped)
  writeFileSync(join(profileDir, PROFILE_PATCH_FILE), text, { mode: 0o600 })
  return { backup, dropped }
}

/**
 * Filter a profile patch to the rows whose plugin is shipped.
 *
 * The patch the settings UI writes is a top-level YAML sequence: comment lines, then one `- id:` item per
 * plugin with an indented `name:` line. An item without a `name:` line (an insert or override block) is
 * dropped with the label `(unnamed)`; a patch that is not a sequence (`[]`) is returned unchanged.
 * @param text - Patch file contents.
 * @param shipped - Whether the bundled runtime contains a plugin package.
 * @returns The filtered patch and the names of the dropped rows.
 */
export function keepShippedRows(text: string, shipped: (name: string) => boolean): { text: string, dropped: string[] } {
  const lines = text.replaceAll('\r\n', '\n').split('\n')
  const head: string[] = []
  const items: string[][] = []
  for (const line of lines) {
    if (line.startsWith('- ')) items.push([line])
    else if (items.length === 0) head.push(line)
    else items[items.length - 1]!.push(line)
  }
  if (items.length === 0) return { text, dropped: [] }
  const kept: string[][] = []
  const dropped: string[] = []
  for (const item of items) {
    const name = itemName(item)
    if (name !== undefined && shipped(name)) kept.push(item)
    else dropped.push(name ?? '(unnamed)')
  }
  const body = kept.length === 0 ? ['[]', ''] : kept.flat()
  return { text: [...head, ...body].join('\n'), dropped }
}

function itemName(item: readonly string[]): string | undefined {
  for (const line of item) {
    const match = /^(?:- | {2})name:\s*(.+?)\s*$/u.exec(line)
    if (match === null) continue
    const raw = match[1]!
    return raw.startsWith('"') || raw.startsWith("'") ? raw.slice(1, -1) : raw
  }
  return undefined
}
