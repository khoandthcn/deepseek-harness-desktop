import { describe, it, expect, vi } from 'vitest'
import { establishAppSession, establishSiemSession, parseSessionDataKey, runWso2Login } from '../src/wso2.ts'

/** vitest types `mock.calls` from the stub's own signature; these tests read
 * positional args the stubs do not declare, so narrow once here. */
const callsOf = (m: { mock: { calls: unknown[] } }): any[][] =>
  m.mock.calls as unknown as any[][]

const IAM = 'https://iam.example'
const REDIRECT_URI = 'https://app.example/callback'

function redirect(location: string, setCookie?: string) {
  const headers = new Headers({ location })
  if (setCookie) headers.append('set-cookie', setCookie)
  return new Response(null, { status: 302, headers })
}

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

/** A fetch stub that replays a fixed sequence of responses and records calls. */
function sequenceFetch(responses: Response[]) {
  let i = 0
  return vi.fn(async () => {
    const res = responses[i++]
    if (!res) throw new Error('unexpected extra fetch call')
    return res
  })
}

const WAF_BOOTSTRAP_PAGE = '<html><body><script>document.cookie="D1N=df48dc607bd140bd08329c75679ce2e6"+"; expires=Fri, 31 Dec 2099 23:59:59 GMT; path=/";window.location.reload(true);</script></body></html>'

function html(body: string) {
  return new Response(body, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8,gbk' } })
}

function happyPathResponses() {
  return [
    redirect(
      `${IAM}/authenticationendpoint/login.do?client_id=cid&sessionDataKey=K1`,
      'commonAuthId=abc123; Path=/; HttpOnly',
    ),
    redirect(
      `${IAM}/authenticationendpoint/totp.do?client_id=cid&sessionDataKey=K2`,
    ),
    redirect(`${IAM}/oauth2/authorize?sessionDataKey=K3`),
    redirect(`${REDIRECT_URI}?code=CODE-123&session_state=xyz`),
    // the portal's own exchange, not /oauth2/token
    json(200, { accessToken: 'TOKEN-XYZ', idToken: 'ID', item: { username: 'alice' }, scopes: [] }),
  ]
}

const baseOpts = {
  iamUrl: IAM,
  clientId: 'cid',
  redirectUri: REDIRECT_URI,
  username: 'alice',
  password: 'sup3rs3cret',
  otp: '123456',
}

function bodyOf(call: any): URLSearchParams {
  return new URLSearchParams(String(call[1].body))
}

describe('parseSessionDataKey', () => {
  it('extracts the key from an absolute url', () => {
    expect(
      parseSessionDataKey(`${IAM}/authenticationendpoint/login.do?a=1&sessionDataKey=K-42`),
    ).toBe('K-42')
  })

  it('extracts the key from a relative location', () => {
    expect(parseSessionDataKey('/authenticationendpoint/totp.do?sessionDataKey=K-9')).toBe('K-9')
  })

  it('throws when the key is absent', () => {
    expect(() => parseSessionDataKey(`${IAM}/oauth2/authorize?foo=bar`)).toThrow(/sessionDataKey/)
  })
})

describe('runWso2Login', () => {
  it('drives the full flow and returns the access token', async () => {
    const f = sequenceFetch(happyPathResponses())
    const out = await runWso2Login({ ...baseOpts, fetchImpl: f as any })

    expect(out.accessToken).toBe('TOKEN-XYZ')
    expect(out.cookies['commonAuthId']).toBe('abc123')
    expect(f).toHaveBeenCalledTimes(5)

    // Step 1: authorize
    const authorize = new URL(String(callsOf(f)[0]![0]))
    expect(authorize.pathname).toBe('/oauth2/authorize')
    expect(authorize.searchParams.get('response_type')).toBe('code')
    expect(authorize.searchParams.get('client_id')).toBe('cid')
    expect(authorize.searchParams.get('redirect_uri')).toBe(REDIRECT_URI)
    expect(authorize.searchParams.get('scope')).toBe('openid')
    expect((callsOf(f)[0]![1] as any).redirect).toBe('manual')

    // Step 2: password POST
    const pwCall = callsOf(f)[1] as any
    expect(String(pwCall[0])).toBe(`${IAM}/commonauth`)
    expect(pwCall[1].method).toBe('POST')
    expect(String(pwCall[1].headers['content-type'])).toMatch(
      /application\/x-www-form-urlencoded/,
    )
    const pwBody = bodyOf(pwCall)
    expect(pwBody.get('username')).toBe('alice')
    expect(pwBody.get('usernameUserInput')).toBe('alice')
    expect(pwBody.get('password')).toBe('sup3rs3cret')
    expect(pwBody.get('sessionDataKey')).toBe('K1')
    // cookies from step 1 are carried forward
    expect(String(pwCall[1].headers['cookie'])).toContain('commonAuthId=abc123')

    // Step 3: OTP POST
    const otpCall = callsOf(f)[2] as any
    expect(String(otpCall[0])).toBe(`${IAM}/commonauth`)
    const otpBody = bodyOf(otpCall)
    expect(otpBody.get('token')).toBe('123456')
    expect(otpBody.get('sessionDataKey')).toBe('K2')
    expect(otpBody.get('password')).toBeNull()

    // Step 4: follow the authorize redirect
    expect(String(callsOf(f)[3]![0])).toBe(`${IAM}/oauth2/authorize?sessionDataKey=K3`)

    // Step 5: the SOC portal exchanges the code; the browser never touches /oauth2/token
    const exchangeCall = callsOf(f)[4] as any
    expect(String(exchangeCall[0])).toBe(`${REDIRECT_URI}/authen-api/auth`)
    expect(exchangeCall[1].method).toBe('POST')
    expect(String(exchangeCall[1].headers['content-type'])).toMatch(/application\/json/)
    expect(JSON.parse(exchangeCall[1].body)).toEqual({ clientId: 'cid', code: 'CODE-123' })
    // the session cookies collected so far ride along to the portal
    expect(String(exchangeCall[1].headers['cookie'])).toContain('commonAuthId=abc123')
  })

  it('names the keys it got when the portal exchange carries no accessToken', async () => {
    const responses = happyPathResponses()
    responses[4] = json(200, { item: {}, scopes: [] })
    const f = sequenceFetch(responses)
    await expect(runWso2Login({ ...baseOpts, fetchImpl: f as any })).rejects.toThrow(/no accessToken \(keys: item, scopes\)/)
  })

  it('rejects when the password step does not reach the OTP step', async () => {
    const rs = happyPathResponses()
    rs[1] = redirect(`${IAM}/authenticationendpoint/login.do?sessionDataKey=K1&authFailure=true`)
    const p = runWso2Login({ ...baseOpts, fetchImpl: sequenceFetch(rs) as any })
    await expect(p).rejects.toThrow(/password/i)
    // the secret must never appear in the error
    await expect(p).rejects.not.toThrow(/sup3rs3cret/)
  })

  it('rejects when the OTP is rejected (non-302)', async () => {
    const rs = happyPathResponses()
    rs[2] = json(200, { status: 'FAILED' })
    const p = runWso2Login({ ...baseOpts, fetchImpl: sequenceFetch(rs) as any })
    await expect(p).rejects.toThrow(/OTP rejected/i)
    await expect(p).rejects.not.toThrow(/123456/)
  })

  it('rejects when the redirect back carries no authorization code', async () => {
    const rs = happyPathResponses()
    rs[3] = redirect(`${REDIRECT_URI}?error=access_denied`)
    await expect(
      runWso2Login({ ...baseOpts, fetchImpl: sequenceFetch(rs) as any }),
    ).rejects.toThrow(/authorization code/i)
  })

  it('rejects when the portal exchange has no accessToken', async () => {
    const rs = happyPathResponses()
    rs[4] = json(200, { error: 'invalid_grant' })
    await expect(
      runWso2Login({ ...baseOpts, fetchImpl: sequenceFetch(rs) as any }),
    ).rejects.toThrow(/no accessToken/)
  })
})

describe('runWso2Login behind the WAF', () => {
  it('adopts the D1N cookie from the bootstrap page and repeats the authorize step', async () => {
    // What the real IAM returns to a client that has no D1N cookie yet: not the
    // login redirect, but a page that sets the cookie via script and reloads.
    const f = sequenceFetch([html(WAF_BOOTSTRAP_PAGE), ...happyPathResponses()])
    const out = await runWso2Login({ ...baseOpts, fetchImpl: f as any })

    expect(out.accessToken).toBe('TOKEN-XYZ')
    expect(f).toHaveBeenCalledTimes(6)
    const calls = callsOf(f)
    expect(String(calls[1]![0])).toBe(String(calls[0]![0]))
    expect(calls[0]![1].headers['cookie']).toBeUndefined()
    expect(String(calls[1]![1].headers['cookie'])).toContain('D1N=df48dc607bd140bd08329c75679ce2e6')
    // and the cookie rides every later step, which is what the WAF gates on
    expect(String(calls[2]![1].headers['cookie'])).toContain('D1N=')
  })

  it('hands the D1N cookie to the caller with the rest of the jar', async () => {
    const f = sequenceFetch([html(WAF_BOOTSTRAP_PAGE), ...happyPathResponses()])
    let jar: Record<string, string> = {}
    await runWso2Login({ ...baseOpts, fetchImpl: f as any, onCookies: c => { jar = c } })
    expect(jar['D1N']).toBe('df48dc607bd140bd08329c75679ce2e6')
    expect(jar['commonAuthId']).toBe('abc123')
  })
})

describe('establishAppSession', () => {
  const SOAR = 'https://soar.example'
  const CALLBACK = `${SOAR}/callback`

  it('rides the SSO cookie and returns the code the callback carries', async () => {
    // With the SSO session, authorize 302s straight to the system callback with
    // the code — no login form, no further hops.
    const f = sequenceFetch([redirect(`${CALLBACK}?code=APPCODE&session_state=xyz`)])
    const { code, cookies } = await establishAppSession({
      iamUrl: IAM,
      clientId: 'SOAR_CLIENT',
      redirectUri: CALLBACK,
      cookies: { commonAuthId: 'abc123', D1N: 'waf' },
      fetchImpl: f as any,
    })
    expect(code).toBe('APPCODE')
    // the WAF cookie is carried through for the code exchange that follows
    expect(cookies['D1N']).toBe('waf')
    // the SSO cookie rode the authorize, and it used the system's own client/callback
    const authorize = new URL(String(callsOf(f)[0]![0]))
    expect(String(callsOf(f)[0]![1].headers['cookie'])).toContain('commonAuthId=abc123')
    expect(authorize.searchParams.get('client_id')).toBe('SOAR_CLIENT')
    expect(authorize.searchParams.get('redirect_uri')).toBe(CALLBACK)
  })

  it('fails with a re-login message when the SSO session has lapsed', async () => {
    // No SSO: authorize bounces back to the login form.
    const f = sequenceFetch([redirect(`${IAM}/authenticationendpoint/login.do?sessionDataKey=K1`)])
    await expect(establishAppSession({
      iamUrl: IAM,
      clientId: 'SOAR_CLIENT',
      redirectUri: CALLBACK,
      cookies: {},
      fetchImpl: f as any,
    })).rejects.toThrow(/SSO session has expired|log in again/i)
  })
})

describe('establishSiemSession', () => {
  const SIEM = 'https://siem.example'

  it('follows the gatekeeper\'s IAM callback and returns only the code at the redirect_uri', async () => {
    // SIEM's gatekeeper: authorize sets its session and bounces to IAM; with SSO,
    // IAM comes back to the gatekeeper's own callback on the SIEM origin carrying
    // IAM's code; the gatekeeper redeems that server-side and only then 302s to
    // the app's redirect_uri (the bare origin, path `/`) with the app code.
    const f = sequenceFetch([
      redirect(`${IAM}/oauth2/authorize?response_type=code&client_id=siem-iam&state=S1`, 'gatekeeper_session=gk1; Path=/'),
      redirect(`${SIEM}/oauth/soc_platform_iam/callback?code=IAMCODE&state=S1`),
      redirect(`${SIEM}/?code=APPCODE`),
    ])
    const { code, cookies } = await establishSiemSession({
      siemBaseUrl: SIEM,
      clientId: 'cym_portal',
      audience: 'cym_dashboard_api',
      scope: 'read:db_dashboard',
      cookies: { commonAuthId: 'abc123', D1N: 'waf' },
      fetchImpl: f as any,
    })
    // Returning IAMCODE here is exactly what produced invalid_grant at /oauth/token.
    expect(code).toBe('APPCODE')
    expect(f).toHaveBeenCalledTimes(3)
    // the gatekeeper session rides every later hop, and reaches the token POST
    expect(cookies['gatekeeper_session']).toBe('gk1')
    expect(String(callsOf(f)[2]![1].headers['cookie'])).toContain('gatekeeper_session=gk1')
  })

  it('fails with a re-login message when the chain lands on the login form', async () => {
    const f = sequenceFetch([
      redirect(`${IAM}/oauth2/authorize?response_type=code&client_id=siem-iam`),
      redirect(`${IAM}/authenticationendpoint/login.do?sessionDataKey=K1`),
    ])
    await expect(establishSiemSession({
      siemBaseUrl: SIEM, clientId: 'cym_portal', audience: 'cym_dashboard_api', scope: 'read:db_dashboard',
      cookies: {}, fetchImpl: f as any,
    })).rejects.toThrow(/SSO session has expired|soc_login/i)
  })
})
