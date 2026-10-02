import { describe, expect, it, vi } from 'vitest'
import { JSON_OUTPUT, NOT_AUTHENTICATED } from '../src/tools.ts'
import { createSoarWriteToolDefs, describeWrite, SoarWriter, WRITE_TOOL_NAMES, type SoarWriteHttp } from '../src/writes.ts'

/** vitest types `mock.calls` from the stub's own signature; narrow once here. */
const callsOf = (m: { mock: { calls: unknown[] } }): any[][] => m.mock.calls as unknown as any[][]

/** An HTTP stub answering by "METHOD path". */
function stubHttp(answers: Record<string, unknown> = {}) {
  const answer = (key: string) => {
    if (!(key in answers)) return { data: { ok: true } }
    return answers[key]
  }
  return {
    postJson: vi.fn(async (path: string, _body: unknown, _scope: string) => answer(`POST ${path}`)),
    putJson: vi.fn(async (path: string, _body: unknown, _scope: string) => answer(`PUT ${path}`)),
    getJson: vi.fn(async (path: string, _scope: string) => answer(`GET ${path}`)),
  }
}

function tools(http: ReturnType<typeof stubHttp>, authenticated = true) {
  const writer = new SoarWriter({ http: http as unknown as SoarWriteHttp, defaultTenant: 'MASTER' })
  const list = createSoarWriteToolDefs({ writer, isAuthenticated: () => authenticated, notAuthenticated: NOT_AUTHENTICATED, output: JSON_OUTPUT })
  return (name: string) => list.find(def => def.name === name)!
}

describe('the write tool set', () => {
  it('names exactly the tools that change the platform as needing approval', () => {
    const http = stubHttp()
    const names = ['soar_get_case_activity', 'soar_list_ticket_options', 'soar_add_case_comment', 'soar_add_ticket_comment', 'soar_close_case', 'soar_create_ticket']
    for (const name of names) expect(tools(http)(name)).toBeDefined()
    expect([...WRITE_TOOL_NAMES].sort()).toEqual(['soar_add_case_comment', 'soar_add_ticket_comment', 'soar_close_case', 'soar_create_ticket'])
  })

  it('touches nothing without a session', async () => {
    const http = stubHttp()
    const get = tools(http, false)
    await expect(get('soar_close_case').execute({ case_id: 5, resolution: 'false_positive', comment: 'x' })).resolves.toBe(NOT_AUTHENTICATED)
    expect(http.putJson).not.toHaveBeenCalled()
  })
})

describe('soar_close_case', () => {
  it('sends the false-positive payload of the API reference to the case\'s own tenant', async () => {
    const http = stubHttp()
    await tools(http)('soar_close_case').execute({ case_id: 1121239, resolution: 'false_positive', comment: 'CDN address', tenant: 'acme' })
    expect(callsOf(http.putJson)[0]).toEqual(['/soarapi/v1/acme/case/1121239', {
      resolution_detail: 'FALSEPOSITIVE', comment_close: 'CDN address', resolution: 'False positive', status: 'close',
    }, 'edit:case'])
  })

  it('takes the true-positive detail, and refuses one the platform does not have', async () => {
    const http = stubHttp()
    const close = tools(http)('soar_close_case')
    await close.execute({ case_id: 7, resolution: 'true_positive', resolution_detail: 'Action of admin', comment: 'confirmed' })
    expect(callsOf(http.putJson)[0]![1]).toMatchObject({ resolution: 'True positive', resolution_detail: 'Action of admin' })
    await expect(close.execute({ case_id: 7, resolution: 'true_positive', resolution_detail: 'Whatever', comment: 'x' })).rejects.toThrow(/must be one of/)
  })

  it('closes a duplicate with the original case id, and requires it', async () => {
    const http = stubHttp()
    const close = tools(http)('soar_close_case')
    await close.execute({ case_id: 7, resolution: 'duplicate', duplicate_of: '260930_0179', comment: 'same alert' })
    expect(callsOf(http.putJson)[0]![1]).toEqual({
      resolution_detail: null, comment_close: 'same alert', duplicate_case_id: '260930_0179', resolution: 'Duplicate', status: 'close',
    })
    await expect(close.execute({ case_id: 7, resolution: 'duplicate', comment: 'x' })).rejects.toThrow(/duplicate_of/)
  })

  it('refuses a human-readable case id where the internal one is needed', async () => {
    await expect(tools(stubHttp())('soar_close_case').execute({ case_id: '260930_0179', resolution: 'false_positive', comment: 'x' }))
      .rejects.toThrow(/internal `_id`/)
  })
})

describe('the comments', () => {
  it('posts a case comment and a ticket comment to their own routes and scopes', async () => {
    const http = stubHttp()
    const get = tools(http)
    await get('soar_add_case_comment').execute({ case_id: 12, comment: 'Host isolated by the customer', tenant: 'acme' })
    await get('soar_add_ticket_comment').execute({ ticket_id: 34, comment: 'Waiting for logs' })
    expect(callsOf(http.postJson).map(call => [call[0], call[1], call[2]])).toEqual([
      ['/soarapi/v1/acme/case/12/comment', { comment: 'Host isolated by the customer' }, 'create:case_comment'],
      ['/ticketapi/v1/MASTER/ticket/34/comment', { comment: 'Waiting for logs' }, 'create:ticket_comment'],
    ])
  })

  it('refuses an empty comment before sending anything', async () => {
    const http = stubHttp()
    await expect(tools(http)('soar_add_case_comment').execute({ case_id: 12, comment: '  ' })).rejects.toThrow(/`comment` is required/)
    expect(http.postJson).not.toHaveBeenCalled()
  })
})

describe('soar_create_ticket', () => {
  const answers = {
    'POST /ticketapi/v1/acme/ticket_type/_search': { data: [{ _id: 3, name: 'Incident' }, { _id: 4, name: 'Request' }] },
    'GET /ticketapi/v1/acme/ticket_severity_type/3': { data: [{ _id: 31, name: 'High' }, { _id: 32, name: 'Low' }] },
    'POST /ticketapi/v1/acme/ticket_status/_search': { data: [{ _id: 9, name: 'closed' }, { _id: 8, name: 'open' }] },
    'GET /ticketapi/v1/acme/resolution/3/8': { data: { name: 'Open' } },
    'POST /ticketapi/v1/acme/ticket': { data: { _id: 501, ticket_id: '261002_0001' } },
  }

  it('resolves the type, severity, open status and resolution by name, then opens the ticket', async () => {
    const http = stubHttp(answers)
    const out = await tools(http)('soar_create_ticket').execute({
      title: 'Web shell on the public web tier', description: 'Please isolate the host.', ticket_type: 'incident',
      severity: 'High', linked_case: '261001_0273', tenant: 'acme',
    })
    const create = callsOf(http.postJson).find(call => call[0] === '/ticketapi/v1/acme/ticket')!
    expect(create[1]).toEqual({
      title: 'Web shell on the public web tier', description: 'Please isolate the host.', tags: [],
      ticket_type_id: 3, ticket_severity_id: 31, ticket_status_id: 8, resolution: 'Open', linked_case: '261001_0273',
    })
    expect(create[2]).toBe('create:ticket')
    expect(out).toEqual({ _id: 501, ticket_id: '261002_0001' })
  })

  it('names the choices when a type or severity does not exist, and opens nothing', async () => {
    const http = stubHttp(answers)
    const create = tools(http)('soar_create_ticket')
    await expect(create.execute({ title: 't', description: 'd', ticket_type: 'Outage', severity: 'High', tenant: 'acme' }))
      .rejects.toThrow(/no ticket type "Outage"; the platform has: Incident \(3\), Request \(4\)/)
    await expect(create.execute({ title: 't', description: 'd', ticket_type: 'Incident', severity: 'Critical', tenant: 'acme' }))
      .rejects.toThrow(/no severity for ticket type "Incident" "Critical"/)
    expect(callsOf(http.postJson).some(call => call[0] === '/ticketapi/v1/acme/ticket')).toBe(false)
  })
})

describe('describeWrite', () => {
  it('states the exact action, from the arguments that will be sent', () => {
    expect(describeWrite('soar_close_case', { case_id: 7, resolution: 'false_positive', comment: 'CDN', tenant: 'acme' }))
      .toBe('Close SOAR case _id 7 (tenant acme) as false_positive, with the comment "CDN".')
    expect(describeWrite('soar_add_case_comment', { case_id: 12, comment: 'line one\nline two' }))
      .toBe('Add a comment to SOAR case _id 12: "line one line two".')
    expect(describeWrite('soar_create_ticket', { ticket_type: 'Incident', severity: 'High', title: 'X', linked_case: '261001_0273' }))
      .toBe('Open a SOAR ticket of type "Incident", severity "High", linked to case 261001_0273, titled "X".')
  })

  it('shortens a long comment in the approval text', () => {
    expect(describeWrite('soar_add_ticket_comment', { ticket_id: 1, comment: 'a'.repeat(500) }).length).toBeLessThan(260)
  })
})
