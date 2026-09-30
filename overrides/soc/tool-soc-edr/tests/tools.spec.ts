import { describe, expect, it, vi } from 'vitest'
import { createEdrToolDefs } from '../src/tools.ts'

/** vitest types `mock.calls` from the stub's own signature; these tests read
 * positional args the stubs do not declare, so narrow once here. */
const callsOf = (m: { mock: { calls: unknown[] } }): any[][] =>
  m.mock.calls as unknown as any[][]

/** The adapter methods the tools call, all as spies. */
function fakeAdapter() {
  return {
    searchEvents: vi.fn(async () => ({ total: 1, items: [{ _id: 'e1' }] })),
    searchAlerts: vi.fn(async () => ({ total: 1, items: [{ alert_id: 'a1' }] })),
    searchAgents: vi.fn(async () => ({ total: 1, items: [{ agent_id: 'ag1' }] })),
    getAgents: vi.fn(async () => ({ total: 1, items: [{ agentId: 'ag1', policy: 'alpha' }] })),
    getAlertEvents: vi.fn(async () => ({ a1: [{ EventID: 3 }] })),
    threatHuntingHistory: vi.fn(async () => ({ total: 1, items: [{ _id: 'h1' }] })),
    listEventFields: vi.fn(async () => ({ fields: { process_name: {} } })),
    listAlertFields: vi.fn(async () => ({ fields: { severity: {} } })),
  }
}

/** Structural stand-in for soc-auth's `SocAuthService` (only the session check). */
function fakeAuth(authenticated: boolean) {
  return { isAuthenticated: vi.fn(() => authenticated) }
}

function defs(authenticated: boolean) {
  const adapter = fakeAdapter()
  const auth = fakeAuth(authenticated)
  const list = createEdrToolDefs({ adapter, auth })
  const byName = (name: string) => {
    const def = list.find(d => d.name === name)
    if (!def) throw new Error(`no tool named ${name}`)
    return def
  }
  return { adapter, auth, list, byName }
}

const EXPECTED = [
  'edr_search_events',
  'edr_search_alerts',
  'edr_search_agents',
  'edr_get_agents',
  'edr_get_alert_events',
  'edr_threat_hunting_history',
  'edr_list_event_fields',
  'edr_list_alert_fields',
]

describe('createEdrToolDefs', () => {
  it('defines exactly the expected edr_* tools', () => {
    const { list } = defs(true)
    expect(list.map(d => d.name).sort()).toEqual([...EXPECTED].sort())
  })

  it('does NOT define soc_login (that stays in tool-soc-soar)', () => {
    const { list } = defs(true)
    expect(list.map(d => d.name)).not.toContain('soc_login')
  })

  it('gives every tool a description and a parameters object', () => {
    const { list } = defs(true)
    for (const def of list) {
      expect(typeof def.description).toBe('string')
      expect(def.description.length).toBeGreaterThan(0)
      expect(typeof def.parameters).toBe('object')
    }
  })
})

describe('fail-closed when not logged in', () => {
  for (const name of EXPECTED) {
    it(`${name} returns the not_authenticated value and never calls the adapter`, async () => {
      const { adapter, byName } = defs(false)
      const out = await byName(name).execute({})
      expect(out).toMatchObject({ error: 'not_authenticated' })
      expect((out as { message: string }).message).toMatch(/soc_login/)
      for (const spy of Object.values(adapter)) {
        expect(spy).not.toHaveBeenCalled()
      }
    })
  }

  it('does not throw — the model gets a structured value it can act on', async () => {
    const { byName } = defs(false)
    await expect(byName('edr_search_events').execute({})).resolves.toBeDefined()
  })
})

describe('authenticated happy paths', () => {
  it('edr_search_events forwards its arguments and returns the adapter result', async () => {
    const { adapter, byName } = defs(true)
    const args = {
      query: 'process_name = "cmd.exe"',
      key_quick_search: 'cmd',
      last_seconds: 3600,
      from_timestamp: 100,
      to_timestamp: 200,
      limit: 25,
      sort: '-timestamp',
    }
    const out = await byName('edr_search_events').execute(args)
    expect(callsOf(adapter.searchEvents)[0]![0]).toEqual({
      searchQuery: 'process_name = "cmd.exe"',
      keyQuickSearch: 'cmd',
      lastSeconds: 3600,
      fromTimestamp: 100,
      toTimestamp: 200,
      limit: 25,
      // the model writes a string; the API wants { field, direction }
      sort: { field: 'timestamp', direction: 'desc' },
    })
    expect(out).toEqual({ total: 1, items: [{ _id: 'e1' }] })
  })

  it('reads an ascending sort and leaves an absent one to the adapter default', async () => {
    const { adapter, byName } = defs(true)
    await byName('edr_search_alerts').execute({ sort: 'timestamp_create' })
    expect(callsOf(adapter.searchAlerts)[0]![0].sort).toEqual({ field: 'timestamp_create', direction: 'asc' })
    await byName('edr_search_alerts').execute({})
    expect(callsOf(adapter.searchAlerts)[1]![0].sort).toBeUndefined()
  })

  it('passes an agent filter object through unchanged', async () => {
    const { adapter, byName } = defs(true)
    await byName('edr_search_agents').execute({ query: { hostname: 'web-01' } })
    expect(callsOf(adapter.searchAgents)[0]![0].query).toEqual({ hostname: 'web-01' })
  })

  it('edr_search_alerts forwards query and time window', async () => {
    const { adapter, byName } = defs(true)
    await byName('edr_search_alerts').execute({ query: 'severity = "high"', last_seconds: 60, limit: 10 })
    expect(adapter.searchAlerts).toHaveBeenCalledWith({
      searchQuery: 'severity = "high"',
      lastSeconds: 60,
      fromTimestamp: undefined,
      toTimestamp: undefined,
      limit: 10,
      since: undefined,
      sort: undefined,
    })
  })

  it('pages a search with since, the offset of the first record', async () => {
    const { adapter, byName } = defs(true)
    await byName('edr_search_alerts').execute({ since: 500, limit: 100 })
    expect(callsOf(adapter.searchAlerts)[0]![0]).toMatchObject({ since: 500, limit: 100 })
  })

  it('edr_get_agents looks agents up by id, and takes one bare id for a list of one', async () => {
    const { adapter, byName } = defs(true)
    await byName('edr_get_agents').execute({ agent_ids: ['A1', 'A2'], infos: ['policy', 'ip'] })
    expect(adapter.getAgents).toHaveBeenCalledWith(['A1', 'A2'], ['policy', 'ip'])
    await byName('edr_get_agents').execute({ agent_ids: 'A3' })
    expect(adapter.getAgents).toHaveBeenLastCalledWith(['A3'], undefined)
  })

  it('edr_get_agents refuses an empty id list rather than asking for every agent', async () => {
    const { adapter, byName } = defs(true)
    await expect(byName('edr_get_agents').execute({ agent_ids: [] })).rejects.toThrow(/agent_ids must be a non-empty array/)
    expect(adapter.getAgents).not.toHaveBeenCalled()
  })

  it('edr_get_alert_events expands alerts into their events, newest first unless asked', async () => {
    const { adapter, byName } = defs(true)
    const out = await byName('edr_get_alert_events').execute({ alert_ids: ['a1'] })
    expect(adapter.getAlertEvents).toHaveBeenCalledWith(['a1'], 'desc')
    expect(out).toEqual({ a1: [{ EventID: 3 }] })
    await byName('edr_get_alert_events').execute({ alert_ids: ['a1'], direction: 'asc' })
    expect(adapter.getAlertEvents).toHaveBeenLastCalledWith(['a1'], 'asc')
  })

  it('edr_search_agents forwards query/since/limit', async () => {
    const { adapter, byName } = defs(true)
    await byName('edr_search_agents').execute({ query: 'srv1', since: 5, limit: 20 })
    expect(adapter.searchAgents).toHaveBeenCalledWith({ query: 'srv1', since: 5, limit: 20 })
  })

  it('edr_threat_hunting_history forwards from/size', async () => {
    const { adapter, byName } = defs(true)
    await byName('edr_threat_hunting_history').execute({ from: 10, size: 5 })
    expect(adapter.threatHuntingHistory).toHaveBeenCalledWith({ from: 10, size: 5 })
  })

  it('the field-list tools take no arguments', async () => {
    const { adapter, byName } = defs(true)
    const events = await byName('edr_list_event_fields').execute({})
    const alerts = await byName('edr_list_alert_fields').execute({})
    expect(adapter.listEventFields).toHaveBeenCalledTimes(1)
    expect(adapter.listAlertFields).toHaveBeenCalledTimes(1)
    expect(events).toEqual({ fields: { process_name: {} } })
    expect(alerts).toEqual({ fields: { severity: {} } })
  })
})
