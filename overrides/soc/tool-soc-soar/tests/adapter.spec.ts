import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it, vi } from 'vitest'
import { SoarAdapter, type SoarHttp } from '../src/adapter.ts'

/** vitest types `mock.calls` from the stub's own signature; these tests read
 * positional args the stubs do not declare, so narrow once here. */
const callsOf = (m: { mock: { calls: unknown[] } }): any[][] =>
  m.mock.calls as unknown as any[][]

const FIX = join(dirname(fileURLToPath(import.meta.url)), 'fixtures')

function fixture(name: string): unknown {
  return JSON.parse(readFileSync(join(FIX, name), 'utf8'))
}

/** Stand-in for socp-mcp's respx routes: a structural `SocHttp` double. */
function stubHttp(responses: Record<string, unknown>) {
  const postJson = vi.fn(async (path: string) => {
    if (!(path in responses)) throw new Error(`unexpected POST ${path}`)
    return responses[path]
  })
  const getJson = vi.fn(async (path: string) => {
    const bare = path.split('?')[0]!
    const key = path in responses ? path : bare
    if (!(key in responses)) throw new Error(`unexpected GET ${path}`)
    return responses[key]
  })
  return { postJson, getJson }
}

function adapter(responses: Record<string, unknown>, tenant = 'MASTER') {
  const http = stubHttp(responses)
  return { http, soar: new SoarAdapter(http as unknown as SoarHttp, tenant) }
}

describe('SoarAdapter', () => {
  it('search_alerts builds the body and parses the envelope', async () => {
    const { http, soar } = adapter({
      '/soarapi/v1/MASTER/alert/_search': fixture('alert_search.json'),
    })
    const env = await soar.searchAlerts({ severity: 'high', page: 1, size: 20, sort: '-created' })
    expect(env.data[0]!.severity).toBe('high')

    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(path).toBe('/soarapi/v1/MASTER/alert/_search')
    expect(body._from).toBe(20)
    expect(body._size).toBe(20)
    expect(body._sort).toBe('-created')
    expect(body.query).toBe('severity = "high"')
    expect(body._counting).toBe(true)
    expect(body._fields).toBe('')
  })

  it('search_alerts defaults to page 0 / size 50 / -created', async () => {
    const { http, soar } = adapter({
      '/soarapi/v1/MASTER/alert/_search': fixture('alert_search.json'),
    })
    await soar.searchAlerts({})
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body).toMatchObject({ _from: 0, _size: 50, _sort: '-created', _counting: true, query: '' })
  })

  it('list_alert_types parses', async () => {
    const { http, soar } = adapter({
      '/soarapi/v1/MASTER/alert_type/_search': fixture('alert_type_search.json'),
    })
    const env = await soar.listAlertTypes()
    expect(Array.isArray(env.data[0]!.alert_fields)).toBe(true)
    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(path).toBe('/soarapi/v1/MASTER/alert_type/_search')
    expect(body).toEqual({ _from: 0, _size: 100, _counting: true })
  })

  it('list_alert_fields sorts by name and sends an empty query', async () => {
    const { http, soar } = adapter({
      '/soarapi/v1/MASTER/alert_field/_search': fixture('alert_field_search.json'),
    })
    const env = await soar.listAlertFields()
    expect(env.count).toBe(0)
    expect(Array.isArray(env.data)).toBe(true)
    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(path).toBe('/soarapi/v1/MASTER/alert_field/_search')
    expect(body).toEqual({ _from: 0, _size: 500, _sort: 'name', _counting: true, query: '' })
  })

  it('search_tickets passes rawQuery through verbatim', async () => {
    const { http, soar } = adapter({
      '/ticketapi/v1/MASTER/ticket/restricted_search': { count: 1, data: [{ _id: 7, status: 'OPEN' }] },
    })
    const env = await soar.searchTickets({ rawQuery: 'status = "OPEN"', page: 2, size: 10 })
    expect(env.data[0]!.status).toBe('OPEN')
    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(path).toBe('/ticketapi/v1/MASTER/ticket/restricted_search')
    expect(body).toEqual({
      _from: 20,
      _size: 10,
      _sort: '-created',
      _counting: true,
      _fields: '',
      query: 'status = "OPEN"',
    })
  })

  it('search_tickets sends an empty query when rawQuery is absent', async () => {
    const { http, soar } = adapter({
      '/ticketapi/v1/MASTER/ticket/restricted_search': { count: 0, data: [] },
    })
    await soar.searchTickets({})
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body.query).toBe('')
  })

  it('list_notifications parses', async () => {
    const { http, soar } = adapter({
      '/notification/v1/notification': fixture('notification.json'),
    })
    const nl = await soar.listNotifications()
    expect(nl.notifications[0]!.object).toBe('ticket')
    expect(nl.counting_all).toBe(0)
    expect(nl.counting_unread).toBe(0)
    const [path] = callsOf(http.getJson)[0] as [string]
    expect(path).toContain('/notification/v1/notification')
    expect(path).toContain('_from=0')
    expect(path).toContain('_size=50')
    expect(path).toContain('_counting=true')
    expect(path).toContain('_only_unread=false')
  })

  it('list_notifications honours size and onlyUnread', async () => {
    const { http, soar } = adapter({
      '/notification/v1/notification': fixture('notification.json'),
    })
    await soar.listNotifications({ size: 5, onlyUnread: true })
    const [path] = callsOf(http.getJson)[0] as [string]
    expect(path).toContain('_size=5')
    expect(path).toContain('_only_unread=true')
  })

  it('uses the configured tenant in the path and MASTER by default', async () => {
    const { http, soar } = adapter(
      { '/soarapi/v1/ACME/alert/_search': { count: 0, data: [] } },
      'ACME',
    )
    await soar.searchAlerts({})
    expect(callsOf(http.postJson)[0]![0]).toBe('/soarapi/v1/ACME/alert/_search')

    const bare = new SoarAdapter(
      stubHttp({ '/soarapi/v1/MASTER/alert/_search': { count: 0, data: [] } }) as unknown as SoarHttp,
    )
    const env = await bare.searchAlerts({})
    expect(env.data).toEqual([])
  })

  it('tolerates a missing envelope count/data', async () => {
    const { soar } = adapter({ '/soarapi/v1/MASTER/alert/_search': {} })
    const env = await soar.searchAlerts({})
    expect(env.count).toBe(0)
    expect(env.data).toEqual([])
  })

  it('rejects a non-object envelope', async () => {
    const { soar } = adapter({ '/soarapi/v1/MASTER/alert/_search': 'nope' })
    await expect(soar.searchAlerts({})).rejects.toThrow(/envelope/i)
  })
})
