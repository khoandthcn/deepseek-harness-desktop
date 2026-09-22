import { describe, expect, it, vi } from 'vitest'
import {
  createNsmToolDefs,
  NSM_DEFAULT_SIZE,
  NSM_MAX_SIZE,
  NSM_PATHS,
  type NsmHttpLike,
} from '../src/tools.ts'

/** vitest types `mock.calls` from the stub's own signature; these tests read
 * positional args the stubs do not declare, so narrow once here. */
const callsOf = (m: { mock: { calls: unknown[] } }): any[][] =>
  m.mock.calls as unknown as any[][]

/** A fixed clock, so request bodies are exact in assertions. */
const NOW = 1_789_132_662_000

/** The envelope every NSM response carries. */
function envelope(data: unknown, count = 0, extra: Record<string, unknown> = {}) {
  return { ama_url: '', code: 200, count, data, message: 'OK', status: true, ...extra }
}

/** A structural `SocHttp` double. */
function stubHttp(responses: Record<string, unknown>) {
  const getJson = vi.fn(async (path: string) => {
    if (!(path in responses)) throw new Error(`unexpected GET ${path}`)
    return responses[path]
  })
  const postJson = vi.fn(async (path: string) => {
    if (!(path in responses)) throw new Error(`unexpected POST ${path}`)
    return responses[path]
  })
  return { getJson, postJson }
}

/** Structural stand-in for soc-auth's `SocAuthService`. */
function fakeAuth(authenticated: boolean) {
  return { isAuthenticated: vi.fn(() => authenticated) }
}

function defs(authenticated: boolean, responses: Record<string, unknown> = {}) {
  const http = stubHttp(responses)
  const auth = fakeAuth(authenticated)
  const list = createNsmToolDefs({ http: http as unknown as NsmHttpLike, auth, now: () => NOW })
  const byName = (name: string) => {
    const def = list.find(d => d.name === name)
    if (!def) throw new Error(`no tool named ${name}`)
    return def
  }
  return { http, auth, list, byName }
}

describe('createNsmToolDefs', () => {
  it('defines the read-only NSM suite', () => {
    const { list } = defs(true)
    expect(list.map(d => d.name)).toEqual([
      'nsm_check_access',
      'nsm_list_tenants',
      'nsm_list_sensors',
      'nsm_list_alert_fields',
      'nsm_search_alerts',
      'nsm_group_alerts',
    ])
  })

  it('never defines a tool that writes, nor a second login', () => {
    const { list } = defs(true)
    const names = list.map(d => d.name)
    expect(names.filter(n => /create|update|delete|edit|acknowledge|assign/.test(n))).toEqual([])
    expect(names).not.toContain('soc_login')
  })

  it('fails closed for every tool when no SOC session exists', async () => {
    const { http, list } = defs(false)
    for (const def of list) {
      await expect(def.execute({ group_by_field: 'alert_attacker' })).resolves.toMatchObject({
        error: 'not_authenticated',
      })
    }
    expect(http.getJson).not.toHaveBeenCalled()
    expect(http.postJson).not.toHaveBeenCalled()
  })
})

describe('nsm_check_access', () => {
  it('reports the identity and permission list', async () => {
    const { byName } = defs(true, {
      [NSM_PATHS.perm]: envelope({
        current_user: {
          fullname: 'analyst@master',
          _level: 'manager',
          server_type: 'manager',
          perms: ['write_event_management', 'read_alert'],
        },
      }),
    })
    expect(await byName('nsm_check_access').execute({})).toEqual({
      fullname: 'analyst@master',
      level: 'manager',
      serverType: 'manager',
      permissions: ['write_event_management', 'read_alert'],
    })
  })

  it('reports an NSM refusal with its upstream message', async () => {
    const { byName } = defs(true, { [NSM_PATHS.perm]: { code: 403, message: 'permission denied' } })
    await expect(byName('nsm_check_access').execute({})).rejects.toThrow(/code 403.*permission denied/)
  })
})

describe('nsm_list_tenants and nsm_list_sensors', () => {
  it('reduces the tenant list to its ids', async () => {
    const { byName } = defs(true, {
      [NSM_PATHS.tenants]: envelope([{ tenant_id: 'acme', _id: 'acme' }, { tenant_id: 'beta' }], 2),
    })
    expect(await byName('nsm_list_tenants').execute({})).toEqual({ count: 2, tenants: ['acme', 'beta'] })
  })

  it('keeps sensor identity and health only', async () => {
    const { byName } = defs(true, {
      [NSM_PATHS.sensors]: envelope([{
        sensor_id: 'bng',
        _tenant: 'bng',
        sensor_ip: '10.0.0.1',
        sensor_active: true,
        sensor_last_ping: '2026-09-11T20:17:19+07:00',
        sensor_eps: '57.2667',
        _index: 'naptm-static-bng-',
        _version: 92312,
      }], 1),
    })
    expect(await byName('nsm_list_sensors').execute({})).toEqual({
      count: 1,
      sensors: [{
        sensorId: 'bng',
        tenant: 'bng',
        ip: '10.0.0.1',
        active: true,
        lastPing: '2026-09-11T20:17:19+07:00',
        eventsPerSecond: '57.2667',
      }],
    })
  })
})

describe('nsm_list_alert_fields', () => {
  it('lists the alert model properties, sorted', async () => {
    const { byName } = defs(true, {
      [NSM_PATHS.modelMap]: {
        data: {
          alert: { model: 'alert', properties: { alert_dst: {}, alert_attacker: {}, _create_time: {} } },
          event: { properties: {} },
        },
      },
    })
    expect(await byName('nsm_list_alert_fields').execute({})).toEqual({
      docType: 'alert',
      count: 3,
      fields: ['_create_time', 'alert_attacker', 'alert_dst'],
    })
  })

  it('names the known document types when the alert model is absent', async () => {
    const { byName } = defs(true, { [NSM_PATHS.modelMap]: { data: { event: { properties: {} } } } })
    await expect(byName('nsm_list_alert_fields').execute({})).rejects.toThrow(/known types: event/)
  })
})

describe('nsm_search_alerts', () => {
  const hit = {
    _id: 'a3286a20',
    alert_attacker: '1.1.9.9',
    alert_category: 'Anomaly Detection',
    alert_events: new Array(30).fill({ bulk: 'x'.repeat(200) }),
  }

  it('sends the search body the NSM app sends, defaulting to the last hour', async () => {
    const { http, byName } = defs(true, {
      [NSM_PATHS.searchEvent]: envelope({ data: [hit], aggr: {} }, 433),
    })
    const out = await byName('nsm_search_alerts').execute({ query: 'src="22"' })

    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, any>]
    expect(path).toBe('/api/v1/custom_search_event')
    expect(body).toEqual({
      search_type: 'advance_search',
      data: { time: { from: NOW - 3600 * 1000, to: NOW }, query: 'src="22"', groupby: { field: '' } },
      doc_type: 'alert',
      request_cache: true,
      size: NSM_DEFAULT_SIZE,
      from: 0,
      sort_field: '_create_time',
      sort_type: 'desc',
    })

    // the nested event copies are dropped; the alert fields stay
    expect(out).toMatchObject({ count: 433, returned: 1, window: { from: NOW - 3600 * 1000, to: NOW } })
    const [alert] = (out as { alerts: Record<string, unknown>[] }).alerts
    expect(alert).toEqual({ _id: 'a3286a20', alert_attacker: '1.1.9.9', alert_category: 'Anomaly Detection' })
  })

  it('takes explicit epoch bounds over last_seconds, clamps the size and passes the sort', async () => {
    const { http, byName } = defs(true, { [NSM_PATHS.searchEvent]: envelope({ data: [] }) })
    await byName('nsm_search_alerts').execute({
      time_from: 1000,
      time_to: 2000,
      last_seconds: 99,
      size: 5000,
      from: 50,
      sort_field: 'alert_severity',
      sort_type: 'asc',
    })
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, any>]
    expect(body.data.time).toEqual({ from: 1000, to: 2000 })
    expect(body).toMatchObject({ size: NSM_MAX_SIZE, from: 50, sort_field: 'alert_severity', sort_type: 'asc' })
  })

  it('rejects a payload whose rows are not an array', async () => {
    const { byName } = defs(true, { [NSM_PATHS.searchEvent]: envelope({ data: {} }) })
    await expect(byName('nsm_search_alerts').execute({})).rejects.toThrow(/`data\.data` must be an array/)
  })
})

describe('nsm_group_alerts', () => {
  it('asks for a count per value and returns the buckets', async () => {
    const { http, byName } = defs(true, {
      [NSM_PATHS.groupBy]: envelope({
        aggr: { group_by_data: { buckets: [{ key: '1.1.9.9', doc_count: 120 }, { key: '2.2.2.2', doc_count: 4 }] } },
        data: [],
      }, 13095),
    })
    const out = await byName('nsm_group_alerts').execute({ group_by_field: 'alert_attacker', query: 'src="22"' })
    expect(out).toEqual({
      field: 'alert_attacker',
      count: 13095,
      buckets: [{ key: '1.1.9.9', count: 120 }, { key: '2.2.2.2', count: 4 }],
    })

    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, any>]
    expect(path).toBe('/api/v1/group_by')
    expect(body).toMatchObject({ group_by_field: 'alert_attacker', size: 0, from: 0, doc_type: 'alert' })
    expect(body.data.query).toBe('src="22"')
  })

  it('rejects a payload without buckets', async () => {
    const { byName } = defs(true, { [NSM_PATHS.groupBy]: envelope({ aggr: {} }) })
    await expect(byName('nsm_group_alerts').execute({ group_by_field: 'alert_attacker' }))
      .rejects.toThrow(/buckets` must be an array/)
  })
})
