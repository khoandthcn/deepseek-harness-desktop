import { describe, expect, it, vi } from 'vitest'
import {
  createTiToolDefs,
  TI_DEFAULT_SIZE,
  TI_MAX_SIZE,
  TI_PATHS,
  type TiHttpLike,
} from '../src/tools.ts'

/** vitest types `mock.calls` from the stub's own signature; these tests read
 * positional args the stubs do not declare, so narrow once here. */
const callsOf = (m: { mock: { calls: unknown[] } }): any[][] =>
  m.mock.calls as unknown as any[][]

/** A fixed clock, so request bodies are exact in assertions. */
const NOW = 1_752_807_504_000
const THIRTY_DAYS = 30 * 24 * 3600 * 1000

/** The envelope the platform answers searches with. */
function envelope(rows: unknown[], total = rows.length) {
  return { message: 'success', data: rows, total }
}

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

function defs(configured: boolean, responses: Record<string, unknown> = {}) {
  const http = stubHttp(responses)
  const auth = { ensureConfigured: vi.fn(async () => configured) }
  const list = createTiToolDefs({ http: http as unknown as TiHttpLike, auth, now: () => NOW })
  const byName = (name: string) => {
    const def = list.find(d => d.name === name)
    if (!def) throw new Error(`no tool named ${name}`)
    return def
  }
  return { http, auth, list, byName }
}

describe('createTiToolDefs', () => {
  it('defines the read-only Threat Intelligence suite', () => {
    const { list } = defs(true)
    expect(list.map(d => d.name)).toEqual([
      'ti_search_compromised_systems',
      'ti_search_port_anomalies',
      'ti_search_data_leaks',
      'ti_search_impersonations',
      'ti_search_phishing',
      'ti_search_credit_card_leaks',
      'ti_search_cves',
      'ti_search_threat_reports',
      'ti_get_threat_report',
      'ti_search_document_breaches',
      'ti_get_document_breach',
      'ti_get_credit_card_leak',
      'ti_search_easm_assets',
      'ti_search_easm_issues',
      'ti_lookup_indicator',
    ])
  })

  it('defines no tool that writes, marks or exports', () => {
    const { list } = defs(true)
    // Match the verb after the prefix, not a substring: "credit" contains "edit".
    const verbs = list.map(d => d.name.replace(/^ti_/, '').split('_')[0])
    expect([...new Set(verbs)]).toEqual(['search', 'get', 'lookup'])
  })

  it('fails closed for every tool when no account is configured, touching no endpoint', async () => {
    const { http, list } = defs(false)
    for (const def of list) {
      await expect(def.execute({ value: 'x', entity_type: 'domain' })).resolves.toMatchObject({
        error: 'not_configured',
      })
    }
    expect(http.postJson).not.toHaveBeenCalled()
    expect(http.getJson).not.toHaveBeenCalled()
  })
})

describe('the shared alert search', () => {
  it('sends the documented body and reports the platform total', async () => {
    const row = { id: 'a1', ioc: '10.20.30.40', malware: 'Ransomware', severity: 3 }
    const { http, byName } = defs(true, { [TI_PATHS.compromisedSystem]: envelope([row], 50) })
    const out = await byName('ti_search_compromised_systems').execute({ keyword: '10.20.30.40', severity: [3, 4] })

    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(path).toBe('/discovery-service/api/v1/compromised_system')
    expect(body).toEqual({
      from: 0,
      size: TI_DEFAULT_SIZE,
      time_from: NOW - THIRTY_DAYS,
      time_to: NOW,
      keyword: '10.20.30.40',
      severity: [3, 4],
    })
    expect(out).toEqual({ total: 50, returned: 1, rows: [row] })
  })

  it('omits an empty keyword and an out-of-range severity rather than sending them', async () => {
    const { http, byName } = defs(true, { [TI_PATHS.phishing]: envelope([]) })
    await byName('ti_search_phishing').execute({ keyword: '', severity: [9, 'x'] })
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body).not.toHaveProperty('keyword')
    expect(body).not.toHaveProperty('severity')
  })

  it('takes explicit epoch bounds over last_seconds and clamps the page size', async () => {
    const { http, byName } = defs(true, { [TI_PATHS.dataLeak]: envelope([]) })
    await byName('ti_search_data_leaks').execute({ time_from: 1000, time_to: 2000, last_seconds: 99, size: 5000, from: 40 })
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body).toMatchObject({ time_from: 1000, time_to: 2000, size: TI_MAX_SIZE, from: 40 })
  })

  it('reports a payload that carries no rows, naming the keys it got', async () => {
    const { byName } = defs(true, { [TI_PATHS.impersonate]: { message: 'quota exceeded' } })
    await expect(byName('ti_search_impersonations').execute({})).rejects.toThrow(/no `data` array.*message/)
  })
})

describe('the endpoints that spell their fields differently', () => {
  it('sends cvss_level with a CVE search', async () => {
    const { http, byName } = defs(true, { [TI_PATHS.cve]: envelope([{ name: 'CVE-2025-49619' }]) })
    await byName('ti_search_cves').execute({ keyword: 'redhat', cvss_level: ['high', 'critical'] })
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body).toMatchObject({ keyword: 'redhat', cvss_level: ['high', 'critical'] })
  })

  it('sends tlp with a threat-report search', async () => {
    const { http, byName } = defs(true, { [TI_PATHS.threatReport]: envelope([]) })
    await byName('ti_search_threat_reports').execute({ tlp: [2, 3] })
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body).toMatchObject({ tlp: [2, 3] })
  })

  it('names the document-breach window and paging as that endpoint does', async () => {
    const { http, byName } = defs(true, { [TI_PATHS.dataBreach]: { alerts: [{ id: 'b1' }], total: 3 } })
    const out = await byName('ti_search_document_breaches').execute({ from: 20, size: 50, status: [0, 1] })
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body).toEqual({
      offset: 20,
      limit: 50,
      time_from: NOW - THIRTY_DAYS,
      time_to: NOW,
      status: [0, 1],
    })
    // that endpoint returns its rows under `alerts`
    expect(out).toEqual({ total: 3, returned: 1, rows: [{ id: 'b1' }] })
  })

  it('names the attack-surface window from_time/to_time', async () => {
    const { http, byName } = defs(true, { [TI_PATHS.easmAsset]: envelope([]) })
    await byName('ti_search_easm_assets').execute({ type: 'domain', status_code: [403] })
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body).toEqual({
      from: 0,
      size: TI_DEFAULT_SIZE,
      from_time: NOW - THIRTY_DAYS,
      to_time: NOW,
      type: 'domain',
      status_code: [403],
    })
    expect(body).not.toHaveProperty('time_from')
  })

  it('passes the issue handling states and the timestamp the window applies to', async () => {
    const { http, byName } = defs(true, { [TI_PATHS.easmIssue]: envelope([]) })
    await byName('ti_search_easm_issues').execute({ customer_status: [0, 3], data_type: 'alert_time' })
    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body).toMatchObject({ customer_status: [0, 3], data_type: 'alert_time' })
  })
})

describe('ti_lookup_indicator', () => {
  it('asks for enrichment by default and returns the detail', async () => {
    const detail = { metadata: { entity_type: 'domain' }, evaluate: { security_result: { severity: 3 } } }
    const { http, byName } = defs(true, { [TI_PATHS.threatLookup]: { success: true, message: 'OK', detail } })
    const out = await byName('ti_lookup_indicator').execute({ value: 'example.com', entity_type: 'domain' })

    const [, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(body).toEqual({ value: 'example.com', entity_type: 'domain', sections: ['enrichment'] })
    expect(out).toEqual({ value: detail })
  })

  it('reports a lookup that carried no detail', async () => {
    const { byName } = defs(true, { [TI_PATHS.threatLookup]: { success: false, message: 'not found' } })
    await expect(byName('ti_lookup_indicator').execute({ value: 'x', entity_type: 'ip' }))
      .rejects.toThrow(/no `detail`/)
  })
})

describe('the detail reads', () => {
  it('reads one threat report by its code, escaped into the path', async () => {
    const report = { code_report: 'TI_2025_0123', title: 'x' }
    const { byName } = defs(true, { '/discovery-service/api/v1/threat_report/TI_2025_0123': report })
    expect(await byName('ti_get_threat_report').execute({ code_report: 'TI_2025_0123' })).toEqual(report)
  })

  it('reads one card-leak alert by its id', async () => {
    const { byName } = defs(true, { '/discovery-service/api/v1/ccleak/69e0c73e': { id: '69e0c73e' } })
    expect(await byName('ti_get_credit_card_leak').execute({ ccleak_id: '69e0c73e' })).toEqual({ id: '69e0c73e' })
  })
})
