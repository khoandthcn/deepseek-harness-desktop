import { describe, expect, it, vi } from 'vitest'
import { createSoarToolDefs } from '../src/tools.ts'

/** vitest types `mock.calls` from the stub's own signature; these tests read
 * positional args the stubs do not declare, so narrow once here. */
const callsOf = (m: { mock: { calls: unknown[] } }): any[][] =>
  m.mock.calls as unknown as any[][]

/** The adapter methods the tools call, all as spies. */
function fakeAdapter() {
  return {
    searchAlerts: vi.fn(async () => ({ count: 1, data: [{ _id: 1, severity: 'high' }] })),
    groupAlerts: vi.fn(async () => ({
      field: 'rule_id', total: 3, scanned: 3, truncated: false, distinct: 2, missing: 0,
      groups: [{ value: 'R1', count: 2 }, { value: 'R2', count: 1 }],
    })),
    getAlertEvents: vi.fn(async () => ({ count: 3, data: [{ n: 1 }, { n: 2 }, { n: 3 }] })),
    listAlertTypes: vi.fn(async () => ({ count: 1, data: [{ _id: 2, name: 'phishing' }] })),
    listAlertFields: vi.fn(async () => ({ count: 1, data: [{ _id: 3, name: 'severity' }] })),
    searchCases: vi.fn(async () => ({ count: 1, data: [{ _id: 5, case_id: '240801_0001' }] })),
    searchTickets: vi.fn(async () => ({ count: 1, data: [{ _id: 4, status: 'OPEN' }] })),
    listNotifications: vi.fn(async () => ({
      notifications: [{ notification_id: 'n1' }],
      counting_all: 1,
      counting_unread: 1,
    })),
  }
}

/** Structural stand-in for soc-auth's `SocAuthService`. */
function fakeAuth(authenticated: boolean) {
  return {
    isAuthenticated: vi.fn(() => authenticated),
    login: vi.fn(async (_otp: string) => {}),
    soarBearer: vi.fn(async () => 'bearer-token'),
    authHeadersForSoar: vi.fn(() => ({ Authorization: 'Bearer bearer-token' })),
    invalidate: vi.fn(() => {}),
  }
}

function defs(authenticated: boolean) {
  const adapter = fakeAdapter()
  const auth = fakeAuth(authenticated)
  const list = createSoarToolDefs({ adapter, auth })
  const byName = (name: string) => {
    const def = list.find(d => d.name === name)
    if (!def) throw new Error(`no tool named ${name}`)
    return def
  }
  return { adapter, auth, list, byName }
}

const EXPECTED = [
  'soc_login',
  'soc_check_network',
  'soar_search_alerts',
  'soar_group_alerts',
  'soar_get_alert_events',
  'soar_list_alert_types',
  'soar_list_alert_fields',
  'soar_search_cases',
  'soar_search_tickets',
  'soar_list_notifications',
]

/** The tools that read the platform; signing in and checking the network need no session. */
const READ_TOOLS = EXPECTED.filter(n => n !== 'soc_login' && n !== 'soc_check_network')

describe('createSoarToolDefs', () => {
  it('defines exactly the expected tools', () => {
    const { list } = defs(true)
    expect(list.map(d => d.name).sort()).toEqual([...EXPECTED].sort())
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
  for (const name of READ_TOOLS) {
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
    await expect(byName('soar_search_alerts').execute({})).resolves.toBeDefined()
  })
})

describe('soc_login', () => {
  it('passes the OTP to auth.login', async () => {
    const { auth, byName } = defs(false)
    await byName('soc_login').execute({ otp: '123456' })
    expect(auth.login).toHaveBeenCalledWith('123456')
  })

  it('never echoes the OTP back to the model', async () => {
    const { byName } = defs(false)
    const out = await byName('soc_login').execute({ otp: '987654' })
    expect(JSON.stringify(out)).not.toContain('987654')
    expect(out).toMatchObject({ status: 'logged_in' })
  })

  it('is callable while unauthenticated (it is what makes you authenticated)', async () => {
    const { auth, byName } = defs(false)
    await byName('soc_login').execute({ otp: '111111' })
    expect(auth.isAuthenticated).not.toHaveBeenCalled()
  })

  it('tells the model to ask the user for a fresh OTP', () => {
    const { byName } = defs(false)
    expect(byName('soc_login').description).toMatch(/OTP/i)
    expect(byName('soc_login').description).toMatch(/ask the user/i)
  })
})

describe('authenticated happy paths', () => {
  it('soar_search_alerts forwards its arguments and returns the adapter result', async () => {
    const { adapter, byName } = defs(true)
    const args = {
      severity: 'high',
      status: 'NEW',
      created_from: 1780718815823,
      created_to: 1781323615824,
      query: 'hostname = "srv1"',
      page: 2,
      size: 10,
      sort: '-created',
    }
    const out = await byName('soar_search_alerts').execute(args)

    expect(adapter.searchAlerts).toHaveBeenCalledTimes(1)
    expect(callsOf(adapter.searchAlerts)[0]![0]).toEqual({
      severity: 'high',
      status: 'NEW',
      createdFrom: 1780718815823,
      createdTo: 1781323615824,
      rawQuery: 'hostname = "srv1"',
      page: 2,
      size: 10,
      sort: '-created',
    })
    expect(out).toEqual({ count: 1, data: [{ _id: 1, severity: 'high' }] })
  })

  it('soar_list_notifications forwards size/only_unread and returns the list', async () => {
    const { adapter, byName } = defs(true)
    const out = await byName('soar_list_notifications').execute({ size: 5, only_unread: true })

    expect(adapter.listNotifications).toHaveBeenCalledWith({ size: 5, onlyUnread: true })
    expect(out).toEqual({
      notifications: [{ notification_id: 'n1' }],
      counting_all: 1,
      counting_unread: 1,
    })
  })

  it('keeps a search to one tenant when asked, on alerts, cases and tickets alike', async () => {
    const { adapter, byName } = defs(true)
    await byName('soar_search_alerts').execute({ tenant: 'acme', size: 1 })
    await byName('soar_search_cases').execute({ tenant: 'acme', size: 1 })
    await byName('soar_search_tickets').execute({ tenant: 'acme', created_from: 10, created_to: 20, size: 1 })
    expect(callsOf(adapter.searchAlerts)[0]![0].tenant).toBe('acme')
    expect(callsOf(adapter.searchCases)[0]![0].tenant).toBe('acme')
    expect(callsOf(adapter.searchTickets)[0]![0]).toMatchObject({ tenant: 'acme', createdFrom: 10, createdTo: 20 })
  })

  it('soar_group_alerts groups the whole period for one tenant by the field asked for', async () => {
    const { adapter, byName } = defs(true)
    const out = await byName('soar_group_alerts').execute({
      field: 'rule_id', top: 5, tenant: 'acme', created_from: 10, created_to: 20,
    })
    expect(adapter.groupAlerts).toHaveBeenCalledWith({
      field: 'rule_id', top: 5, severity: undefined, status: undefined,
      createdFrom: 10, createdTo: 20, tenant: 'acme', rawQuery: undefined,
    })
    expect(out).toMatchObject({ total: 3, truncated: false, groups: [{ value: 'R1', count: 2 }, { value: 'R2', count: 1 }] })
  })

  it('soar_group_alerts refuses an open-ended period, which would read every alert ever kept', async () => {
    const { adapter, byName } = defs(true)
    await expect(byName('soar_group_alerts').execute({ field: 'severity', top: 5 })).rejects.toThrow(/needs a period/)
    await expect(byName('soar_group_alerts').execute({ field: 'severity', created_from: 10 })).rejects.toThrow(/needs a period/)
    expect(adapter.groupAlerts).not.toHaveBeenCalled()
  })

  it('soar_group_alerts takes one field name, not an expression', async () => {
    const { adapter, byName } = defs(true)
    await expect(byName('soar_group_alerts').execute({ field: 'rule_id, hostname' })).rejects.toThrow(/name of one alert field/)
    await expect(byName('soar_group_alerts').execute({})).rejects.toThrow(/name of one alert field/)
    expect(adapter.groupAlerts).not.toHaveBeenCalled()
  })

  it('soar_get_alert_events takes the internal id and reports the full count beside a bounded page', async () => {
    const { adapter, byName } = defs(true)
    const out = await byName('soar_get_alert_events').execute({ alert_internal_id: 206899862, limit: 2 })
    expect(adapter.getAlertEvents).toHaveBeenCalledWith(206899862)
    expect(out).toEqual({ count: 3, returned: 2, data: [{ n: 1 }, { n: 2 }] })
  })

  it('soar_get_alert_events refuses the business alert id, which the endpoint does not accept', async () => {
    const { adapter, byName } = defs(true)
    await expect(byName('soar_get_alert_events').execute({ alert_internal_id: 'c0654630-32e2-4219-a071' }))
      .rejects.toThrow(/numeric `_id`/)
    expect(adapter.getAlertEvents).not.toHaveBeenCalled()
  })

  it('soar_search_cases forwards the period, the raw query and paging to the case search', async () => {
    const { adapter, byName } = defs(true)
    const out = await byName('soar_search_cases').execute({
      created_from: 10, created_to: 20, query: 'tenant = "acme"', size: 1,
    })
    expect(adapter.searchCases).toHaveBeenCalledWith({
      severity: undefined,
      status: undefined,
      createdFrom: 10,
      createdTo: 20,
      tenant: undefined,
      rawQuery: 'tenant = "acme"',
      page: undefined,
      size: 1,
      sort: '-created',
    })
    // cases never go to the ticket search: they are different things
    expect(adapter.searchTickets).not.toHaveBeenCalled()
    expect(out).toEqual({ count: 1, data: [{ _id: 5, case_id: '240801_0001' }] })
  })

  it('soar_search_tickets forwards its raw query and paging', async () => {
    const { adapter, byName } = defs(true)
    const out = await byName('soar_search_tickets').execute({ query: 'status = "OPEN"', page: 1, size: 20 })

    expect(adapter.searchTickets).toHaveBeenCalledWith({
      rawQuery: 'status = "OPEN"',
      page: 1,
      size: 20,
      sort: '-created',
    })
    expect(out).toEqual({ count: 1, data: [{ _id: 4, status: 'OPEN' }] })
  })

  it('the metadata tools take plain paging', async () => {
    const { adapter, byName } = defs(true)
    await byName('soar_list_alert_types').execute({ page: 1, size: 50 })
    await byName('soar_list_alert_fields').execute({})
    expect(adapter.listAlertTypes).toHaveBeenCalledWith({ page: 1, size: 50 })
    expect(adapter.listAlertFields).toHaveBeenCalledWith({})
  })
})

describe('soc_check_network', () => {
  /** What `fetch` throws: the reason sits in a nested cause. */
  const failure = (code: string) => Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error(code), { code }) })

  function check(probeFetch: typeof fetch, env: Record<string, string | undefined> = {}) {
    const list = createSoarToolDefs({
      adapter: fakeAdapter(),
      auth: fakeAuth(false),
      endpoints: () => ({ 'sign-in': 'https://iam.soc.example', soar: 'https://soar.soc.example/api', edr: '' }),
      probeFetch,
      env,
    })
    return list.find(d => d.name === 'soc_check_network')!
  }

  it('needs no session, probes each configured system once without credentials, and reports per system', async () => {
    const probe = vi.fn(async (input: unknown) => {
      if (String(input).startsWith('https://iam.')) throw failure('ENOTFOUND')
      return new Response(null, { status: 302 })
    })
    const out = await check(probe as unknown as typeof fetch).execute({}) as any
    expect(callsOf(probe).map(call => call[0])).toEqual(['https://iam.soc.example/', 'https://soar.soc.example/'])
    for (const [, init] of callsOf(probe)) expect(init.headers).toBeUndefined()
    expect(out).toMatchObject({ proxy: 'none', no_proxy: 'none', reachable: 1, unreachable: 1 })
    expect(out.results[0]).toMatchObject({ system: 'sign-in', host: 'iam.soc.example', reachable: false, kind: 'dns', code: 'ENOTFOUND' })
    expect(out.results[0].detail).toMatch(/set HTTPS_PROXY/)
    expect(out.results[1]).toEqual({ system: 'soar', host: 'soar.soc.example', route: 'direct', reachable: true, status: 302 })
  })

  it('shows the proxy in effect without its credentials, and checks extra URLs the same way', async () => {
    const probe = vi.fn(async () => { throw failure('SELF_SIGNED_CERT_IN_CHAIN') })
    const out = await check(probe as unknown as typeof fetch, {
      HTTPS_PROXY: 'http://alice:s3cret@proxy.corp:3128', NO_PROXY: '.corp',
    }).execute({ extra_urls: ['https://api.ti.example/v1', 'ftp://ignored'] }) as any
    expect(out.proxy).toBe('http://proxy.corp:3128')
    expect(JSON.stringify(out)).not.toContain('s3cret')
    expect(out.no_proxy).toBe('.corp')
    expect(out.results.map((r: any) => r.host)).toEqual(['iam.soc.example', 'soar.soc.example', 'api.ti.example'])
    expect(out.results[2]).toMatchObject({ system: 'extra', kind: 'certificate' })
    expect(out.results[2].detail).toMatch(/~\/\.dsh\/certs/)
    expect(out.results[2].route).toBe('proxy')
  })

  it('shows which hosts the bypass list sends direct, and why that fails', async () => {
    const probe = vi.fn(async (input: unknown) => {
      if (String(input).includes('iam.')) throw failure('ENOTFOUND')
      return new Response(null, { status: 200 })
    })
    const out = await check(probe as unknown as typeof fetch, {
      HTTPS_PROXY: 'http://proxy.corp:3128', NO_PROXY: 'soc.example,localhost',
    }).execute({ extra_urls: ['https://api.ti.example'] }) as any
    expect(out.results[0]).toMatchObject({ system: 'sign-in', route: 'direct', bypassed_by: 'NO_PROXY entry "soc.example"', kind: 'dns' })
    expect(out.results[0].detail).toMatch(/remove "soc.example" from NO_PROXY/)
    expect(out.results[2]).toMatchObject({ system: 'extra', route: 'proxy', reachable: true })
  })

  it('says where to configure the platform when nothing is configured', async () => {
    const list = createSoarToolDefs({ adapter: fakeAdapter(), auth: fakeAuth(false) })
    const out = await list.find(d => d.name === 'soc_check_network')!.execute({}) as any
    expect(out.results).toEqual([])
    expect(out.note).toMatch(/Settings → Plugins → SOC Cloud/)
  })
})
