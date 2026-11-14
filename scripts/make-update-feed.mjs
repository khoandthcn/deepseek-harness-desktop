#!/usr/bin/env node
// Write the electron-updater feed that unsigned builds read from GitHub Releases.
//
//   node scripts/make-update-feed.mjs <installers-dir> <owner/repo> <version> <out-dir>
//
// The feed lives in one fixed release (tag `desktop-updates`), so every build
// polls the same URL; each file names its installer by absolute URL in the
// versioned release `v<version>`. Both channels get the same files, so a user
// who switches channel in Settings still finds a feed. Windows reads
// <channel>.yml and installs the .exe; macOS reads <channel>-mac.yml only to
// learn that a newer version exists (the app then opens the release page).
import { createHash } from 'node:crypto'
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const [dir, repository, version, out] = process.argv.slice(2)
if (!dir || !/^[\w.-]+\/[\w.-]+$/u.test(repository ?? '') || !version || !out) {
  throw new Error('usage: make-update-feed.mjs <installers-dir> <owner/repo> <version> <out-dir>')
}
const base = `https://github.com/${repository}/releases/download/v${encodeURIComponent(version)}`

function entries(extension) {
  return readdirSync(dir).filter(name => name.endsWith(extension)).sort().map((name) => {
    const path = join(dir, name)
    return {
      url: `${base}/${encodeURIComponent(name)}`,
      sha512: createHash('sha512').update(readFileSync(path)).digest('base64'),
      size: statSync(path).size,
    }
  })
}

function feed(files) {
  if (files.length === 0) return undefined
  const lines = [`version: ${JSON.stringify(version)}`, 'files:']
  for (const file of files) {
    lines.push(`  - url: ${JSON.stringify(file.url)}`, `    sha512: ${JSON.stringify(file.sha512)}`, `    size: ${file.size}`)
  }
  lines.push(`path: ${JSON.stringify(files[0].url)}`, `sha512: ${JSON.stringify(files[0].sha512)}`,
    `releaseDate: ${JSON.stringify(new Date().toISOString())}`)
  return `${lines.join('\n')}\n`
}

mkdirSync(out, { recursive: true })
for (const [suffix, extension] of [['', '.exe'], ['-mac', '.dmg']]) {
  const text = feed(entries(extension))
  if (text === undefined) throw new Error(`make-update-feed: no ${extension} installer in ${dir}`)
  for (const channel of ['nightly', 'stable']) {
    writeFileSync(join(out, `${channel}${suffix}.yml`), text)
    console.log(`wrote: ${channel}${suffix}.yml`)
  }
}
