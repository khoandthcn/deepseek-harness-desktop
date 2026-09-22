import { describe, it, expect, vi } from 'vitest'
import { SocHttp, parseD1nBootstrap } from '../src/index.ts'
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

const WAF_BOOTSTRAP_PAGE = '<html><body><script>document.cookie="D1N=df48dc607bd140bd08329c75679ce2e6"+"; expires=Fri, 31 Dec 2099 23:59:59 GMT; path=/";window.location.reload(true);</script></body></html>'

describe('parseD1nBootstrap', () => {
  it('reads the cookie value out of the WAF bootstrap page', () => {
    expect(parseD1nBootstrap(WAF_BOOTSTRAP_PAGE)).toBe('df48dc607bd140bd08329c75679ce2e6')
  })
  it('ignores ordinary bodies', () => {
    expect(parseD1nBootstrap('{"ok":true}')).toBeUndefined()
    expect(parseD1nBootstrap('<html>D1N=abc</html>')).toBeUndefined()
  })
})

describe('SocHttp against the WAF bootstrap', () => {
  it('adopts the cookie and reissues the request once', async () => {
    const pages = [
      new Response(WAF_BOOTSTRAP_PAGE, { status: 200, headers: { 'content-type': 'text/html' } }),
      new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }),
    ]
    const f = vi.fn(async () => pages.shift()!)
    const http = new SocHttp('https://soar.example', { fetchImpl: f })
    expect(await http.postJson('/x', {})).toEqual({ ok: true })
    expect(f).toHaveBeenCalledTimes(2)
    const [first, second] = callsOf(f)
    expect(first![0]).toBe(second![0])
    expect(first![1].headers['cookie']).toBeUndefined()
    expect(second![1].headers['cookie']).toBe('D1N=df48dc607bd140bd08329c75679ce2e6')
  })

  it('merges the WAF cookie into the caller\'s own Cookie header', async () => {
    // The auth header producers send `Cookie` (capital C); a second `cookie`
    // key would reach fetch as a comma-joined pair and lose the session.
    const pages = [
      new Response(WAF_BOOTSTRAP_PAGE, { status: 200, headers: { 'content-type': 'text/html' } }),
      new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }),
    ]
    const f = vi.fn(async () => pages.shift()!)
    const http = new SocHttp('https://soar.example', {
      fetchImpl: f,
      authHeaders: () => ({ Cookie: 'token=abc', Authorization: 'Bearer t' }),
    })
    expect(await http.postJson('/x', {})).toEqual({ ok: true })

    const headers = callsOf(f)[1]![1].headers as Record<string, string>
    const cookieKeys = Object.keys(headers).filter(key => key.toLowerCase() === 'cookie')
    expect(cookieKeys).toHaveLength(1)
    const cookie = headers[cookieKeys[0]!]!
    expect(cookie).toContain('token=abc')
    expect(cookie).toContain('D1N=df48dc607bd140bd08329c75679ce2e6')
    expect(cookie).not.toContain(',')
    // a real fetch would see exactly one Cookie header, with both pairs
    expect(new Headers(headers).get('cookie')).toBe(cookie)
    expect(headers.Authorization).toBe('Bearer t')
  })

  it('does not add the WAF cookie twice when the caller already carries it', async () => {
    const pages = [
      new Response(WAF_BOOTSTRAP_PAGE, { status: 200, headers: { 'content-type': 'text/html' } }),
      new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } }),
    ]
    const f = vi.fn(async () => pages.shift()!)
    const http = new SocHttp('https://soar.example', {
      fetchImpl: f,
      authHeaders: () => ({ Cookie: 'D1N=df48dc607bd140bd08329c75679ce2e6' }),
    })
    await http.getJson('/x')
    const headers = callsOf(f)[1]![1].headers as Record<string, string>
    const cookie = new Headers(headers).get('cookie') ?? ''
    expect(cookie.match(/D1N=/g)).toHaveLength(1)
  })

  it('does not loop when the bootstrap page comes back a second time', async () => {
    const f = vi.fn(async () => new Response(WAF_BOOTSTRAP_PAGE, { status: 200, headers: { 'content-type': 'text/html' } }))
    const http = new SocHttp('https://soar.example', { fetchImpl: f })
    await expect(http.getJson('/x')).rejects.toThrow(/non-JSON/)
    expect(f).toHaveBeenCalledTimes(2)
  })
})
