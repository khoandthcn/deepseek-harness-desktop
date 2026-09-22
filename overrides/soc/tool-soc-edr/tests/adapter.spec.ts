import { describe, expect, it, vi } from 'vitest'
import { EdrAdapter, EDR_PATHS, type EdrHttp } from '../src/adapter.ts'

/** vitest types `mock.calls` from the stub's own signature; these tests read
 * positional args the stubs do not declare, so narrow once here. */
const callsOf = (m: { mock: { calls: unknown[] } }): any[][] =>
  m.mock.calls as unknown as any[][]

/** A structural `SocHttp` double: EDR carries its credential itself, so no scope. */
function stubHttp(responses: Record<string, unknown>) {
  const postJson = vi.fn(async (path: string) => {
    if (!(path in responses)) throw new Error(`unexpected POST ${path}`)
    return responses[path]
  })
  const getJson = vi.fn(async (path: string) => {
    if (!(path in responses)) throw new Error(`unexpected GET ${path}`)
    return responses[path]
  })
  return { postJson, getJson }
}

function adapter(responses: Record<string, unknown>) {
  const http = stubHttp(responses)
  return { http, edr: new EdrAdapter(http as unknown as EdrHttp) }
}

describe('EdrAdapter', () => {
  it('search_events builds the body and parses data/total', async () => {
    const { http, edr } = adapter({
      [EDR_PATHS.eventSearch]: { total: 2, data: [{ _id: 'e1', event_type: 'process' }, { _id: 'e2' }] },
    })
    const env = await edr.searchEvents({ searchQuery: 'process_name = "cmd.exe"', lastSeconds: 3600, limit: 20 })
    expect(env.total).toBe(2)
    expect(env.items[0]!.event_type).toBe('process')

    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(path).toBe('/eventHandler/Search')
    expect(body.search_query_str).toBe('process_name = "cmd.exe"')
    expect(body.last_seconds).toBe(3600)
    expect(body.is_use_last_seconds).toBe(true)
    expect(body.limit).toBe(20)
    expect(body.from_timestamp).toBe(0)
    expect(body.to_timestamp).toBe(0)
    expect(body.keyQuickSearch).toBe('')
  })

  it('search_events defaults to a 24h window with a timestamp-desc sort', async () => {
    const { http, edr } = adapter({ [EDR_PATHS.eventSearch]: { total: 0, data: [] } })
    await edr.searchEvents({})
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body.limit).toBe(50)
    expect(body.is_use_last_seconds).toBe(true)
    expect(body.last_seconds).toBe(86400)
    expect(body.sort).toEqual({ field: 'TimeStamp', direction: 'desc' })
    expect(body.search_query_str).toBe('')
  })

  it('search_alerts builds the body and parses data/total', async () => {
    const { http, edr } = adapter({
      [EDR_PATHS.alertSearch]: { total: 1, data: [{ alert_id: 'a1', severity: 'high' }] },
    })
    const env = await edr.searchAlerts({ searchQuery: 'severity = "high"', fromTimestamp: 100, toTimestamp: 200 })
    expect(env.items[0]!.severity).toBe('high')
    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(path).toBe('/msalert/Search')
    expect(body.search_query_str).toBe('severity = "high"')
    expect(body.from_timestamp).toBe(100)
    expect(body.to_timestamp).toBe(200)
    // an absolute window only takes effect with the relative flag cleared
    expect(body.is_use_last_seconds).toBe(false)
    expect(body.sort).toEqual({ field: 'timestamp_create', direction: 'desc' })
  })

  it('keeps the relative flag set when only last_seconds is given', async () => {
    const { http, edr } = adapter({ [EDR_PATHS.eventSearch]: { total: 0, data: [] } })
    await edr.searchEvents({ lastSeconds: 600 })
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body.is_use_last_seconds).toBe(true)
    expect(body.last_seconds).toBe(600)
  })

  it('clears the relative flag for an absolute event window', async () => {
    const { http, edr } = adapter({ [EDR_PATHS.eventSearch]: { total: 0, data: [] } })
    await edr.searchEvents({ fromTimestamp: 1000, toTimestamp: 2000 })
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body.is_use_last_seconds).toBe(false)
    expect(body.from_timestamp).toBe(1000)
    expect(body.to_timestamp).toBe(2000)
  })

  it('search_agents parses agent_infos/total', async () => {
    const { http, edr } = adapter({
      [EDR_PATHS.agentSearch]: { total: 1, agent_infos: [{ agent_id: 'ag1', hostname: 'srv1' }] },
    })
    const env = await edr.searchAgents({ query: { compare: { field: 'online', operator: '=', value: 'true' } }, limit: 10 })
    expect(env.total).toBe(1)
    expect(env.items[0]!.hostname).toBe('srv1')
    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(path).toBe('/agentManagement/Search')
    expect(body).toEqual({ query: { compare: { field: 'online', operator: '=', value: 'true' } }, limit: 10, since: 0 })
  })

  it('threat_hunting_history parses list/total and forwards from/size', async () => {
    const { http, edr } = adapter({
      [EDR_PATHS.huntingHistory]: { total: 3, list: [{ _id: 'h1' }] },
    })
    const env = await edr.threatHuntingHistory({ from: 10, size: 5 })
    expect(env.total).toBe(3)
    expect(env.items[0]!._id).toBe('h1')
    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(path).toBe('/threatHunting/HistorySearch')
    expect(body).toEqual({ from: 10, size: 5 })
  })

  it('threat_hunting_history defaults from=0/size=50', async () => {
    const { http, edr } = adapter({ [EDR_PATHS.huntingHistory]: { total: 0, list: [] } })
    await edr.threatHuntingHistory({})
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body).toEqual({ from: 0, size: 50 })
  })

  it('list_event_fields posts an empty body and returns the dict', async () => {
    const { http, edr } = adapter({
      [EDR_PATHS.eventFields]: { data: { process_name: { type: 'string' }, pid: { type: 'number' } } },
    })
    const out = await edr.listEventFields()
    expect(Object.keys(out.fields)).toEqual(['process_name', 'pid'])
    const [path, body] = callsOf(http.postJson)[0] as [string, unknown]
    expect(path).toBe('/eventHandler/GetEventFieldList')
    expect(body).toEqual({})
  })

  it('list_alert_fields uses GET and returns the dict', async () => {
    const { http, edr } = adapter({
      [EDR_PATHS.alertFields]: { data: { severity: { type: 'string' } } },
    })
    const out = await edr.listAlertFields()
    expect(Object.keys(out.fields)).toEqual(['severity'])
    const [path] = callsOf(http.getJson)[0] as [string]
    expect(path).toBe('/msalert/GetAlertFieldList')
  })

  it('tolerates a missing total/list and defaults to 0/[]', async () => {
    const { edr } = adapter({ [EDR_PATHS.eventSearch]: {} })
    const env = await edr.searchEvents({})
    expect(env.total).toBe(0)
    expect(env.items).toEqual([])
  })

  it('rejects a non-object envelope', async () => {
    const { edr } = adapter({ [EDR_PATHS.eventSearch]: 'nope' })
    await expect(edr.searchEvents({})).rejects.toThrow(/envelope/i)
  })

  it('rejects a field list whose data is not a dict', async () => {
    const { edr } = adapter({ [EDR_PATHS.eventFields]: { data: [1, 2, 3] } })
    await expect(edr.listEventFields()).rejects.toThrow(/field list/i)
  })
})
