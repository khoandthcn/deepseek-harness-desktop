import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import SkillRegistry from '@deepseek-ai/dsh-skill'
import * as socSkills from '../src/index.ts'
import { apply, PROVIDER_NAME, shippedSkillsDir } from '../src/index.ts'

describe('soc-skills', () => {
  it('mounts a provider of its own that sees only the shipped skills', () => {
    const plugin = vi.fn()
    apply({ plugin } as never)
    const [, config] = plugin.mock.calls[0] as [unknown, Record<string, unknown>]
    // Its own name and no default roots: the preset's filesystem provider
    // already scans the user's and the project's directories, and two
    // providers finding the same skill would list it twice.
    expect(config).toEqual({
      providerName: PROVIDER_NAME,
      includeDefaultRoots: false,
      bundledSkillDir: shippedSkillsDir(),
    })
    expect(PROVIDER_NAME).not.toBe('filesystem')
  })

  it('looks for the skills beside the package, wherever it is installed', () => {
    expect(shippedSkillsDir('file:///opt/app/node_modules/pkg/lib/index.js')).toBe('/opt/app/node_modules/pkg/skills')
  })

  it('ships each skill as a directory with a SKILL.md that names itself', () => {
    // A directory without one is not a skill to the provider and would ship
    // as dead weight; a name that differs from the directory is a skill nobody
    // can find by the name they were told.
    const root = shippedSkillsDir()
    if (!existsSync(root)) return
    const skills = readdirSync(root, { withFileTypes: true }).filter(entry => entry.isDirectory())
    expect(skills.length).toBeGreaterThan(0)
    for (const skill of skills) {
      const manifest = join(root, skill.name, 'SKILL.md')
      expect(existsSync(manifest), manifest).toBe(true)
      const text = readFileSync(manifest, 'utf8')
      expect(text.startsWith('---\n'), `${skill.name} frontmatter`).toBe(true)
      expect(text).toMatch(new RegExp(`^name: ${skill.name}$`, 'm'))
      expect(text).toMatch(/^description: .+/m)
    }
  })
})

describe('soc-skills through the real registry', () => {
  it('puts the shipped report skill in the catalog an agent sees', async () => {
    // The point of the package: with nothing installed by hand, the skill is
    // there, named as its directory, with a description to choose it by.
    if (!existsSync(shippedSkillsDir())) return
    const ctx = new Context()
    await ctx.plugin(SkillRegistry)
    await ctx.plugin(socSkills)
    try {
      const skills = await ctx.skills.list({ cwd: process.cwd() })
      const report = skills.find(skill => skill.name === 'monthly-mss-report')
      expect(report, skills.map(skill => skill.name).join(', ')).toBeDefined()
      expect(report!.description).toMatch(/monthly Managed Security Service report/)
    } finally {
      await ctx.fiber.dispose()
    }
  })
})
