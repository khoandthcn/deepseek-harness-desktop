import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { keepShippedRows, retireLegacyPackageProfile } from '../src/legacy-profile.ts'

const roots: string[] = []
function temporaryRoot(): string {
  const root = mkdtempSync(join(tmpdir(), 'dsh-legacy-profile-test-'))
  roots.push(root)
  return root
}
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true })
})

const PATCH = [
  '# Profile patch',
  '- id: llm-pi-ai',
  '  name: "@deepseek-ai/dsh-llm-pi-ai"',
  '  config:',
  '    providers:',
  '      internal:',
  '        baseURL: https://models.example/routing',
  '- id: soc-auth',
  "  name: '@deepseek-ai/dsh-soc-auth'",
  '  config:',
  '    clientId: PORTAL',
  '- id: agent-default-model',
  '  name: "@deepseek-ai/dsh-agent-default-model"',
  '  config:',
  '    model: deepseek-v4-flash',
  '',
].join('\n')

function shippedRuntime(root: string, names: readonly string[]): string {
  const runtime = join(root, 'dsh')
  for (const name of names) {
    mkdirSync(join(runtime, 'node_modules', name), { recursive: true })
    writeFileSync(join(runtime, 'node_modules', name, 'package.json'), JSON.stringify({ name }))
  }
  return runtime
}

describe('keepShippedRows', () => {
  it('keeps the rows of shipped plugins and names the others', () => {
    const result = keepShippedRows(PATCH, name => name !== '@deepseek-ai/dsh-soc-auth')
    expect(result.dropped).toEqual(['@deepseek-ai/dsh-soc-auth'])
    expect(result.text).toContain('baseURL: https://models.example/routing')
    expect(result.text).toContain('model: deepseek-v4-flash')
    expect(result.text).not.toContain('soc-auth')
    expect(result.text.startsWith('# Profile patch\n- id: llm-pi-ai\n')).toBe(true)
  })

  it('drops an item without a name line', () => {
    const result = keepShippedRows('- insert:\n    - id: x\n      name: y\n', () => true)
    expect(result).toEqual({ text: '[]\n', dropped: ['(unnamed)'] })
  })

  it('leaves an empty patch as it is', () => {
    expect(keepShippedRows('# header\n[]\n', () => false)).toEqual({ text: '# header\n[]\n', dropped: [] })
  })

  it('writes an empty sequence when nothing is shipped', () => {
    expect(keepShippedRows(PATCH, () => false).text).toBe('# Profile patch\n[]\n')
  })

  it('reads Windows line endings', () => {
    const result = keepShippedRows(PATCH.replaceAll('\n', '\r\n'), () => true)
    expect(result.dropped).toEqual([])
    expect(result.text).toBe(PATCH)
  })
})

describe('retireLegacyPackageProfile', () => {
  it('ignores a profile without the 0.1.x package set', () => {
    const root = temporaryRoot()
    const profile = join(root, 'desktop')
    mkdirSync(join(profile, 'node_modules'), { recursive: true })
    expect(retireLegacyPackageProfile(profile, shippedRuntime(root, []))).toBeUndefined()
    expect(existsSync(join(profile, 'node_modules'))).toBe(true)
  })

  it('moves a 0.1.x profile aside and carries over the shipped settings', () => {
    const root = temporaryRoot()
    const profile = join(root, 'desktop')
    mkdirSync(join(profile, 'node_modules', '@deepseek-ai', 'dsh-webserver'), { recursive: true })
    writeFileSync(join(profile, 'desktop-packages.json'), '{}')
    writeFileSync(join(profile, 'cordis.patch.yml'), PATCH)
    const runtime = shippedRuntime(root, ['@deepseek-ai/dsh-llm-pi-ai', '@deepseek-ai/dsh-agent-default-model'])

    const result = retireLegacyPackageProfile(profile, runtime, () => 1234)

    expect(result).toEqual({ backup: `${profile}.legacy-1234`, dropped: ['@deepseek-ai/dsh-soc-auth'] })
    expect(existsSync(join(profile, 'node_modules'))).toBe(false)
    expect(existsSync(join(profile, 'desktop-packages.json'))).toBe(false)
    expect(existsSync(join(`${profile}.legacy-1234`, 'node_modules', '@deepseek-ai', 'dsh-webserver'))).toBe(true)
    const carried = readFileSync(join(profile, 'cordis.patch.yml'), 'utf8')
    expect(carried).toContain('deepseek-v4-flash')
    expect(carried).not.toContain('soc-auth')
  })

  it('moves a 0.1.x profile without a patch', () => {
    const root = temporaryRoot()
    const profile = join(root, 'desktop')
    mkdirSync(profile, { recursive: true })
    writeFileSync(join(profile, 'desktop-packages.json'), '{}')
    expect(retireLegacyPackageProfile(profile, shippedRuntime(root, []), () => 5)?.dropped).toEqual([])
    expect(existsSync(join(profile, 'cordis.patch.yml'))).toBe(false)
    expect(existsSync(profile)).toBe(true)
  })
})
