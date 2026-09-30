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
function settingsDouble(values: Record<string, Record<string, unknown>> = {}) {
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
      // What the section carries: the entry's defaults unless this test put
      // something in it, which is what a user typing into the card produces.
      hooks.setSource(() => ({ ...entry, ...values[ns] }))
    }),
  }
  return { settings, installed, source }
}

async function mount(
  config: Record<string, unknown> | undefined = {},
  values: Record<string, Record<string, unknown>> = {},
) {
  const ctx = new Context()
  const double = settingsDouble(values)
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
    // Named as the card names them: the section is where the non-secret
    // controls keep what the user typed, so they read it back on the next visit.
    expect(Object.keys(entry).sort()).toEqual(['socClientId', 'socDomain', 'socUsername'])
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

describe('what the cards keep in their sections', () => {
  it('hands the Threat Intelligence tools their own card\'s platform and account', async () => {
    const { ctx } = await mount({}, {
      [socAuth.SOC_TI_NS]: { tiDomain: 'ti.example.com', tiUsername: 'someone@example.com' },
    })
    expect(ctx.socAuth.threatIntelSettings()).toEqual({
      tiDomain: 'ti.example.com',
      tiUsername: 'someone@example.com',
    })
  })

  it('reads the SOC section under the names soc-auth knows', () => {
    // The card names it after the platform; sign-in knows it as the client id.
    expect(socAuth.socEndpointSettings({
      soc: () => ({ socDomain: ' soc.example.com ', socClientId: 'CID', socUsername: 'u' }),
    })).toEqual({ socDomain: 'soc.example.com', clientId: 'CID' })
  })

  it('lets a blank control fall through to whatever else supplies the field', () => {
    // An untouched control must not mask the machine's file or environment.
    expect(socAuth.socEndpointSettings({
      soc: () => ({ socDomain: '', socClientId: '   ', socUsername: '' }),
    })).toEqual({})
    expect(socAuth.socEndpointSettings({})).toEqual({})
  })
})
