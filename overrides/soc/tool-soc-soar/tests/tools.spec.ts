import { describe, expect, it, vi } from 'vitest'
import { createSoarToolDefs } from '../src/tools.ts'

/** vitest types `mock.calls` from the stub's own signature; these tests read
 * positional args the stubs do not declare, so narrow once here. */
const callsOf = (m: { mock: { calls: unknown[] } }): any[][] =>
  m.mock.calls as unknown as any[][]

/** The five adapter methods the tools call, all as spies. */
function fakeAdapter() {
  return {
    searchAlerts: vi.fn(async () => ({ count: 1, data: [{ _id: 1, severity: 'high' }] })),
    listAlertTypes: vi.fn(async () => ({ count: 1, data: [{ _id: 2, name: 'phishing' }] })),
    listAlertFields: vi.fn(async () => ({ count: 1, data: [{ _id: 3, name: 'severity' }] })),
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
  'soar_search_alerts',
  'soar_list_alert_types',
  'soar_list_alert_fields',
  'soar_search_tickets',
  'soar_list_notifications',
]

const READ_TOOLS = EXPECTED.filter(n => n !== 'soc_login')

describe('createSoarToolDefs', () => {
  it('defines exactly the six expected tools', () => {
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
