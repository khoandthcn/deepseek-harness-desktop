import { describe, expect, it, vi } from 'vitest'
import {
  createSiemToolDefs,
  SIEM_DEFAULT_SIZE,
  SIEM_MAX_SIZE,
  SIEM_PATHS,
  SIEM_TOKEN_FOR,
  type SiemHttpLike,
} from '../src/tools.ts'

/** A fixed clock and query id, so request bodies are exact in assertions. */
const NOW = 1_790_076_489_000
const QUERY_ID = 'qid-1'

/** vitest types `mock.calls` from the stub's own signature; these tests read
 * positional args the stubs do not declare, so narrow once here. */
const callsOf = (m: { mock: { calls: unknown[] } }): any[][] =>
  m.mock.calls as unknown as any[][]

/** A structural `SocHttp` double: SIEM carries its credential itself, so no scope. */
function stubHttp(responses: Record<string, unknown>) {
  const postJson = vi.fn(async (path: string) => {
    if (!(path in responses)) throw new Error(`unexpected POST ${path}`)
    return responses[path]
  })
  return { postJson }
}

/** Structural stand-in for soc-auth's `SocAuthService`. */
function fakeAuth(authenticated: boolean, siemMgmtClientId = 'cym_api') {
  return { isAuthenticated: vi.fn(() => authenticated), siemMgmtClientId }
}

function defs(authenticated: boolean, responses: Record<string, unknown> = {}) {
  const http = stubHttp(responses)
  const auth = fakeAuth(authenticated)
  const list = createSiemToolDefs({
    http: http as unknown as SiemHttpLike,
    auth,
    now: () => NOW,
    newQueryId: () => QUERY_ID,
  })
  const byName = (name: string) => {
    const def = list.find(d => d.name === name)
    if (!def) throw new Error(`no tool named ${name}`)
    return def
  }
  return { http, auth, list, byName }
}

describe('createSiemToolDefs', () => {
  it('defines the read-only SIEM suite', () => {
    const { list } = defs(true)
    expect(list.map(d => d.name)).toEqual([
      'siem_check_access',
      'siem_list_tenants',
      'siem_list_event_fields',
      'siem_search_events',
      'siem_count_events',
      'siem_search_agents',
    ])
  })

  it('never defines a tool that writes', () => {
    const { list } = defs(true)
    expect(list.map(d => d.name).filter(n => /create|update|delete|edit|acknowledge|assign/.test(n))).toEqual([])
  })

  it('does NOT define soc_login (that stays in tool-soc-soar)', () => {
    const { list } = defs(true)
    expect(list.map(d => d.name)).not.toContain('soc_login')
  })

  it('gives the tool a description and a parameters object', () => {
    const { byName } = defs(true)
    const def = byName('siem_check_access')
    expect(typeof def.description).toBe('string')
    expect(def.description.length).toBeGreaterThan(0)
    expect(def.parameters).toEqual({})
  })
})

describe('fail-closed when not logged in', () => {
  it('fails closed for every tool, not just the probe', async () => {
    const { http, list } = defs(false)
    for (const def of list) {
      await expect(def.execute({})).resolves.toMatchObject({ error: 'not_authenticated' })
    }
    expect(http.postJson).not.toHaveBeenCalled()
  })

  it('returns the not_authenticated value and never touches the http client', async () => {
    const { http, byName } = defs(false)
    const out = await byName('siem_check_access').execute({})
    expect(out).toMatchObject({ error: 'not_authenticated' })
    expect((out as { message: string }).message).toMatch(/soc_login/)
    expect(http.postJson).not.toHaveBeenCalled()
  })

  it('does not throw — the model gets a structured value it can act on', async () => {
    const { byName } = defs(false)
    await expect(byName('siem_check_access').execute({})).resolves.toBeDefined()
  })
})

describe('authenticated happy path', () => {
  it('posts the mgmt client_id and parses {count, data}', async () => {
    const { http, byName } = defs(true, {
      [SIEM_PATHS.userRolePerm]: { count: 2, data: ['view_dashboard', 'view_alert'] },
    })
    const out = await byName('siem_check_access').execute({})
    expect(out).toEqual({ count: 2, data: ['view_dashboard', 'view_alert'] })

    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(path).toBe('/oauth/management/get_user_role_perm')
    expect(body).toEqual({ client_id: 'cym_api' })
  })

  it('tolerates a missing count by falling back to the data length', async () => {
    const { byName } = defs(true, { [SIEM_PATHS.userRolePerm]: { data: ['a', 'b', 'c'] } })
    const out = await byName('siem_check_access').execute({})
    expect(out).toEqual({ count: 3, data: ['a', 'b', 'c'] })
  })

  it('rejects a non-object payload with a clear contract error', async () => {
    const { byName } = defs(true, { [SIEM_PATHS.userRolePerm]: 'nope' })
    await expect(byName('siem_check_access').execute({})).rejects.toThrow(/SIEM access/i)
  })
})

describe('siem_list_tenants', () => {
  it('parses {tenantId, fullName} out of the tenant search', async () => {
    const { http, byName } = defs(true, {
      [SIEM_PATHS.tenantSearch]: {
        status: 'success',
        data: { items: [{ tenantId: 'acme', fullName: 'Acme Corp' }, { tenantId: 'beta', fullName: 'Beta' }], count: '2' },
      },
    })
    const out = await byName('siem_list_tenants').execute({})
    expect(out).toEqual({
      count: 2,
      tenants: [{ tenantId: 'acme', fullName: 'Acme Corp' }, { tenantId: 'beta', fullName: 'Beta' }],
    })
    expect(callsOf(http.postJson)[0]![0]).toBe('/cymtenantapi/api/v1/tenant/socp_search')
  })

  it('rejects a payload without items', async () => {
    const { byName } = defs(true, { [SIEM_PATHS.tenantSearch]: { data: {} } })
    await expect(byName('siem_list_tenants').execute({})).rejects.toThrow(/data\.items/)
  })
})

describe('siem_list_event_fields', () => {
  it('asks for the field map over a 30-day window and returns {field: type}', async () => {
    const { http, byName } = defs(true, {
      [SIEM_PATHS.eventStatistic]: { code: 0, fields: { agentId: 'keyword', dpt: 'integer' }, data: [] },
    })
    const out = await byName('siem_list_event_fields').execute({})
    expect(out).toEqual({ count: 2, fields: { agentId: 'keyword', dpt: 'integer' } })

    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body).toEqual({
      time_from: NOW - 30 * 24 * 3600 * 1000,
      time_to: NOW,
      type: 'event',
      query: '',
      aggs: '',
      getting_fields: true,
    })
  })

  it('honours a caller-supplied window', async () => {
    const { http, byName } = defs(true, { [SIEM_PATHS.eventStatistic]: { fields: {} } })
    await byName('siem_list_event_fields').execute({ last_seconds: 60 })
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, number>]
    expect(body.time_from).toBe(NOW - 60_000)
  })
})

describe('siem_search_events', () => {
  const hit = {
    '@timestamp': '2026-09-22T11:28:07.326Z',
    agentId: 'A1',
    hostname: 'host-1',
    _raw_event: 'x'.repeat(500),
  }

  it('sends the search body the SIEM app sends, defaulting to the last hour', async () => {
    const { http, byName } = defs(true, { [SIEM_PATHS.eventSearch]: { code: 0, count: 0, data: [hit] } })
    const out = await byName('siem_search_events').execute({ query: 'log_parser ~ "win"', tenants: 'acme' })

    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(path).toBe('/adaptereventapi/v1/search')
    expect(body).toEqual({
      query: 'log_parser ~ "win"',
      time_from: NOW - 3600 * 1000,
      time_to: NOW,
      tenants: 'acme',
      _sort: '-timestamp',
      _size: SIEM_DEFAULT_SIZE,
      _from: 0,
      _counting: false,
      query_id: QUERY_ID,
    })
    // the raw log line is dropped; the parsed fields stay
    expect(out).toMatchObject({ returned: 1, window: { time_from: NOW - 3600 * 1000, time_to: NOW } })
    const [event] = (out as { events: Record<string, unknown>[] }).events
    expect(event).toEqual({ '@timestamp': '2026-09-22T11:28:07.326Z', agentId: 'A1', hostname: 'host-1' })
  })

  it('takes explicit epoch bounds over last_seconds and clamps the page size', async () => {
    const { http, byName } = defs(true, { [SIEM_PATHS.eventSearch]: { data: [] } })
    await byName('siem_search_events').execute({ time_from: 1000, time_to: 2000, last_seconds: 99, size: 5000, from: 40 })
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body).toMatchObject({ time_from: 1000, time_to: 2000, _size: SIEM_MAX_SIZE, _from: 40 })
  })

  it('rejects a payload whose data is not an array', async () => {
    const { byName } = defs(true, { [SIEM_PATHS.eventSearch]: { data: {} } })
    await expect(byName('siem_search_events').execute({})).rejects.toThrow(/`data` must be an array/)
  })
})

describe('siem_count_events', () => {
  it('asks for a count only and returns it with the window', async () => {
    const { http, byName } = defs(true, { [SIEM_PATHS.eventSearch]: { code: 0, count: 540, data: [] } })
    const out = await byName('siem_count_events').execute({ query: 'log_parser ~ "win"', tenants: 'acme' })
    expect(out).toEqual({ count: 540, window: { time_from: NOW - 3600 * 1000, time_to: NOW } })

    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body).toMatchObject({ _counting: true, _size: 0, query: 'log_parser ~ "win"' })
  })
})

describe('siem_search_agents', () => {
  it('reduces each agent to its identity and platform', async () => {
    const { http, byName } = defs(true, {
      [SIEM_PATHS.agentSearch]: {
        success: true,
        total: 3909,
        agent_infos: [{
          agentId: 'B91C',
          hostInfo: {
            computerName: 'host-1',
            os: 'linux',
            platform: 'ubuntu',
            platformVersion: '24.04',
            architecture: 'amd64',
            fileInfo: new Array(40).fill({ name: 'bulk' }),
          },
        }],
      },
    })
    const out = await byName('siem_search_agents').execute({ active: '1' })
    expect(out).toEqual({
      total: 3909,
      returned: 1,
      agents: [{
        agentId: 'B91C',
        computerName: 'host-1',
        os: 'linux',
        platform: 'ubuntu',
        platformVersion: '24.04',
        architecture: 'amd64',
      }],
    })

    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(path).toBe('/cymagentapi/CyMAgentManagement/Search')
    expect(body).toEqual({
      limit: SIEM_DEFAULT_SIZE,
      since: 0,
      query: { active: '1' },
      sort: [{ field: 'hostInfo.computerName', direction: 'asc' }],
    })
  })

  it('omits the state filter when the caller gives none', async () => {
    const { http, byName } = defs(true, { [SIEM_PATHS.agentSearch]: { total: 0, agent_infos: [] } })
    await byName('siem_search_agents').execute({})
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body.query).toEqual({})
  })
})

describe('SIEM_TOKEN_FOR', () => {
  it('routes every SIEM path to the audience/scope its SPA uses', () => {
    for (const path of Object.values(SIEM_PATHS)) {
      expect(SIEM_TOKEN_FOR[path], path).toBeDefined()
    }
    expect(SIEM_TOKEN_FOR[SIEM_PATHS.userRolePerm]).toEqual({ audience: 'gatekeeper', scope: 'login' })
    expect(SIEM_TOKEN_FOR[SIEM_PATHS.eventSearch]).toEqual({ audience: 'cym_event_alert_api', scope: 'read:eventapi' })
    expect(SIEM_TOKEN_FOR[SIEM_PATHS.eventStatistic]).toEqual({ audience: 'cym_dashboard_api', scope: 'read:db_statistic' })
    expect(SIEM_TOKEN_FOR[SIEM_PATHS.tenantSearch]).toEqual({ audience: 'cym_tenant_api', scope: 'read:te_tenant' })
    expect(SIEM_TOKEN_FOR[SIEM_PATHS.agentSearch]).toEqual({ audience: 'cym_agent_api', scope: 'read:agent' })
  })
})
