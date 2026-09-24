/**
 * Mounts the plugin itself, with a settings service double, because the SOC
 * Cloud card in Settings only appears when this plugin installs its section:
 * the card's slot entry is keyed by the namespace, and the host lists an entry
 * only for a namespace it serves. A mount that stopped installing it would take
 * the card away silently, which is exactly what this asserts against.
 */
import { describe, expect, it, vi } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import * as socAuth from '../src/index.ts'

/** A settings service double recording what a plugin installs. */
function settingsDouble() {
  const installed: { ns: string, entry: Record<string, unknown> }[] = []
  let source: (() => Record<string, unknown>) | undefined
  const settings = {
    installSection: vi.fn((
      _owner: unknown,
      ns: string,
      _schema: unknown,
      entry: Record<string, unknown>,
      hooks: { setSource: (current: () => Record<string, unknown>) => void, onChange: () => void },
    ) => {
      installed.push({ ns, entry })
      hooks.setSource(() => entry)
    }),
  }
  return { settings, installed, source }
}

async function mount(config: Record<string, unknown> | undefined = {}) {
  const ctx = new Context()
  const double = settingsDouble()
  ctx.provide('settings')
  ctx.settings = double.settings as never
  await ctx.plugin(socAuth, config as never)
  return { ctx, ...double }
}

describe('soc-auth mounting', () => {
  it('installs the section each card is keyed to: one per platform', async () => {
    const { installed } = await mount()
    expect(installed.map(entry => entry.ns)).toEqual([socAuth.SOC_CREDENTIALS_NS, socAuth.SOC_TI_NS])
  })

  it('offers the SOC settings in that section, so the card can render them', async () => {
    const { installed } = await mount()
    const entry = installed[0]!.entry
    for (const field of socAuth.SOC_ENDPOINT_FIELDS) {
      expect(Object.keys(entry), field).toContain(field)
    }
    // the portal client id is not a card field: it is fixed per platform
    expect(Object.keys(entry)).not.toContain('clientId')
  })

  it('mounts with no config block at all, as the preset row has none', async () => {
    const { ctx } = await mount(undefined)
    expect(ctx.socAuth).toBeDefined()
    expect(ctx.socAuth.isAuthenticated()).toBe(false)
  })

  it('can serve the settings sections alone, for a Host that mounts no session', async () => {
    const { ctx, installed } = await mount({ settingsOnly: true })
    expect(installed.map(entry => entry.ns)).toEqual([socAuth.SOC_CREDENTIALS_NS, socAuth.SOC_TI_NS])
    // no service: this row exists so the card has a namespace before any
    // session mounts the preset
    expect(ctx.get('socAuth')).toBeUndefined()
  })

  it('names the credential reference each endpoint is stored under', () => {
    expect(socAuth.endpointRef('iamUrl')).toBe('SOC_IAM_URL')
    expect(socAuth.endpointRef('soarBaseUrl')).toBe('SOC_SOAR_BASE_URL')
    expect(socAuth.endpointRef('nsmBaseUrl')).toBe('SOC_NSM_BASE_URL')
  })
})
