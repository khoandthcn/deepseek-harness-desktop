#!/usr/bin/env node
// Prepare a deepseek-ai/deepseek-harness checkout for unsigned desktop packaging.
//
//   node scripts/apply-unsigned.mjs <path-to-upstream-checkout>
//
// Every edit matches an exact upstream snippet and fails loudly when the snippet
// is gone, so a changed upstream is caught here instead of producing a broken app.
import { copyFileSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

const root = resolve(process.argv[2] ?? 'upstream')
const here = resolve(import.meta.dirname, '..')
const desktop = join(root, 'apps', 'desktop')

function patch(relativePath, from, to) {
  const path = join(root, relativePath)
  const text = readFileSync(path, 'utf8')
  if (text.includes(to)) {
    console.log(`already patched: ${relativePath}`)
    return
  }
  const count = text.split(from).length - 1
  if (count !== 1) {
    throw new Error(`apply-unsigned: expected exactly one match in ${relativePath}, found ${count}:\n${from}`)
  }
  writeFileSync(path, text.replace(from, to))
  console.log(`patched: ${relativePath}`)
}

// 1. electron-builder: ad-hoc macOS signature, unsigned Windows, GitHub publish.
copyFileSync(
  join(here, 'overrides', 'electron-builder.config.mjs'),
  join(desktop, 'electron-builder.config.mjs'),
)
console.log('replaced: apps/desktop/electron-builder.config.mjs')

// 2. Seed preparation: skip Developer ID re-signing of the pnpm store's Mach-O
//    files. Prebuilt native modules keep their own signatures, and the bundled
//    upstream Node.js loads them as it does for any npm install.
patch(
  'apps/desktop/scripts/prepare-seed.ts',
  "    if (targetPlatform === 'darwin') {\n      macOSSigning = resolveMacOSSigningEnvironment(process.env)",
  "    if (targetPlatform === 'darwin' && process.env.DSH_DESKTOP_UNSIGNED !== '1') {\n      macOSSigning = resolveMacOSSigningEnvironment(process.env)",
)
