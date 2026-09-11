import { describe, it, expect, vi } from 'vitest'
import { SocHttp } from '../src/index.ts'
import { SocAuthError, SocMalformedError, SocNotFoundError } from '../src/errors.ts'

/** vitest types `mock.calls` from the stub's own signature; these tests read
 * positional args the stubs do not declare, so narrow once here. */
const callsOf = (m: { mock: { calls: unknown[] } }): any[][] =>
  m.mock.calls as unknown as any[][]

function stubFetch(status: number, body: string, ct = 'application/json') {
  return vi.fn(async () => new Response(body, { status, headers: { 'content-type': ct } }))
}

describe('SocHttp', () => {
  it('posts json and returns parsed body', async () => {
    const f = stubFetch(200, JSON.stringify({ ok: true }))
    const http = new SocHttp('https://soar.example', { fetchImpl: f })
    const out = await http.postJson('/x', { a: 1 })
    expect(out).toEqual({ ok: true })
    const call = callsOf(f)[0]!
    expect(call[1].headers['content-type']).toMatch(/application\/json/)
    expect(JSON.parse(call[1].body)).toEqual({ a: 1 })
  })
  it('maps 401 to SocAuthError', async () => {
    const http = new SocHttp('https://x', { fetchImpl: stubFetch(401, '{}') })
    await expect(http.postJson('/x', {})).rejects.toBeInstanceOf(SocAuthError)
  })
  it('maps non-json to SocMalformedError', async () => {
    const http = new SocHttp('https://x', { fetchImpl: stubFetch(200, '<html>waf</html>', 'text/html') })
    await expect(http.postJson('/x', {})).rejects.toBeInstanceOf(SocMalformedError)
  })
  it('maps 404 to SocNotFoundError', async () => {
    const http = new SocHttp('https://x', { fetchImpl: stubFetch(404, '{}') })
    await expect(http.getJson('/x')).rejects.toBeInstanceOf(SocNotFoundError)
  })
})
