import { describe, it, expect, vi } from 'vitest'
import { SocAuthService } from '../src/service.ts'

/** vitest types `mock.calls` from the stub's own signature; these tests read
 * positional args the stubs do not declare, so narrow once here. */
const callsOf = (m: { mock: { calls: unknown[] } }): any[][] =>
  m.mock.calls as unknown as any[][]

const IAM = 'https://iam.example'
const REDIRECT_URI = 'https://app.example/callback'
const SOAR = 'https://soar.example'

const PASSWORD = 'sup3rs3cret'
const OTP = '123456'
const SCOPE = 'read:alert'

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

function html(status: number, body: string) {
  return new Response(body, { status, headers: { 'content-type': 'text/html' } })
}

/** The five WSO2 responses of a successful single-shot login. */
function wso2HappyPath(): Response[] {
  return [
    redirect(
      `${IAM}/authenticationendpoint/login.do?client_id=cid&sessionDataKey=K1`,
      'commonAuthId=abc123; Path=/; HttpOnly',
    ),
    redirect(`${IAM}/authenticationendpoint/totp.do?client_id=cid&sessionDataKey=K2`),
    redirect(`${IAM}/oauth2/authorize?sessionDataKey=K3`),
    redirect(`${REDIRECT_URI}?code=CODE-123`, 'D1N=waf-cookie; Path=/'),
    json(200, { accessToken: 'SOC-TOKEN', idToken: 'ID', item: {}, scopes: [] }),
  ]
}

/**
 * A fetch stub with three routes:
 *  - the WSO2 login sequence, for IAM authorize/commonauth without an SSO cookie;
 *  - the per-system OIDC handshake — the IAM authorize that carries `commonAuthId`
 *    and the SOAR `/callback` that sets the `token` cookie — canned by URL so it
 *    serves every exchange;
 *  - a caller-supplied queue for the `/access_control/access` calls themselves.
 */
function stubFetch(accessResponses: Response[], wso2: Response[] = wso2HappyPath()) {
  let iam = 0
  let access = 0
  const cookieOf = (init: any): string => String(init?.headers?.cookie ?? '')
  const fn = vi.fn(async (url: string, init?: any) => {
    const u = String(url)
    if (u.includes('/access_control/access')) {
      const res = accessResponses[access++]
      if (!res) throw new Error('unexpected extra SOAR access call')
      return res
    }
    // per-system code exchange: returns the session_token, no Set-Cookie
    if (u.startsWith(`${SOAR}/authen/callback`)) {
      return json(200, { session_token: 'SESS-TOKEN', id_token: 'ID-TOKEN', access_token: 'AC' })
    }
    // per-system authorize: carries a redirect_uri and rides the SSO cookie
    // (login's own step-4 authorize carries only a sessionDataKey); 302s
    // straight to the callback with the code.
    if (u.startsWith(`${IAM}/oauth2/authorize`) && u.includes('redirect_uri=')
      && cookieOf(init).includes('commonAuthId')) {
      return redirect(`${SOAR}/callback?code=APPCODE`)
    }
    const res = wso2[iam++]
    if (!res) throw new Error('unexpected extra WSO2 fetch call')
    return res
  })
  return fn
}

/** The `/access_control/access` calls alone — the Bearer exchanges. */
function accessCalls(f: ReturnType<typeof stubFetch>) {
  return callsOf(f).filter((c) => String(c[0]).includes('/access_control/access'))
}

function makeService(
  fetchImpl: any,
  now: () => number = () => 1_000_000,
  extra: Record<string, unknown> = {},
) {
  return new SocAuthService({
    iamUrl: IAM,
    clientId: 'cid',
    redirectUri: REDIRECT_URI,
    soarBaseUrl: SOAR,
    credentials: async () => ({ username: 'alice', password: PASSWORD }),
    fetchImpl,
    now,
    ...extra,
  })
}

/** No thrown message may ever leak the password or the OTP. */
async function expectNoSecrets(p: Promise<unknown>) {
  const err = await p.then(
    () => {
      throw new Error('expected the promise to reject')
    },
    (e: unknown) => e as Error,
  )
  expect(String(err.message)).not.toContain(PASSWORD)
  expect(String(err.message)).not.toContain(OTP)
  return err
}

describe('SocAuthService.login', () => {
  it('starts unauthenticated and becomes authenticated after a successful login', async () => {
    const f = stubFetch([])
    const svc = makeService(f)
    expect(svc.isAuthenticated()).toBe(false)

    await svc.login(OTP)

    expect(svc.isAuthenticated()).toBe(true)
    expect(f).toHaveBeenCalledTimes(5)
  })

  it('stays unauthenticated and hides the secrets when the OTP is rejected', async () => {
    const wso2 = wso2HappyPath()
    wso2[2] = json(200, { status: 'FAILED' })
    const svc = makeService(stubFetch([], wso2))

    const err = await expectNoSecrets(svc.login(OTP))
    expect(err.message).toMatch(/OTP/i)
    expect(svc.isAuthenticated()).toBe(false)
  })
})

describe('SocAuthService.soarBearer', () => {
  it('rejects with a clear error before any login', async () => {
    const svc = makeService(stubFetch([]))
    const err = await expectNoSecrets(svc.soarBearer(SCOPE))
    expect(err.message).toMatch(/not logged in/i)
  })

  it('exchanges the SOC session once and caches the bearer', async () => {
    const f = stubFetch([json(200, { access_token: 'SOAR-1', expires_in: 3600 })])
    const svc = makeService(f)
    await svc.login(OTP)

    expect(await svc.soarBearer(SCOPE)).toBe('SOAR-1')
    expect(await svc.soarBearer(SCOPE)).toBe('SOAR-1')
    expect(accessCalls(f)).toHaveLength(1)

    const [url, init] = accessCalls(f)[0] as [string, any]
    expect(url).toBe(`${SOAR}/access_control/access`)
    expect(init.method).toBe('POST')
    expect(String(init.headers['content-type'])).toMatch(/application\/json/)
    expect(JSON.parse(init.body)).toEqual({
      tenant: 'MASTER',
      client_id: 'SOAR_CLIENT',
      scopes: SCOPE,
    })
    expect(String(init.headers['cookie'])).toContain('D1N=waf-cookie')
    // SOAR authenticates the exchange with the session token as a Bearer AND
    // the same token inside the `token` cookie.
    expect(String(init.headers['authorization'])).toBe('Bearer SESS-TOKEN')
    expect(String(init.headers['cookie'])).toMatch(/token=\{[^}]*SESS-TOKEN/)
  })

  it('honours tenant and soarClientId overrides', async () => {
    const f = stubFetch([json(200, { access_token: 'SOAR-T', expires_in: 3600 })])
    const svc = makeService(f, () => 1_000_000, { tenant: 'VCS', soarClientId: 'OTHER' })
    await svc.login(OTP)
    await svc.soarBearer(SCOPE)

    const init = (accessCalls(f)[0] as [string, any])[1]
    expect(JSON.parse(init.body)).toEqual({ tenant: 'VCS', client_id: 'OTHER', scopes: SCOPE })
  })

  it('re-exchanges once the clock passes expires_in minus the 60s skew', async () => {
    const f = stubFetch([
      json(200, { access_token: 'SOAR-1', expires_in: 3600 }),
      json(200, { access_token: 'SOAR-2', expires_in: 3600 }),
    ])
    let clock = 1_000_000
    const svc = makeService(f, () => clock)
    await svc.login(OTP)

    expect(await svc.soarBearer(SCOPE)).toBe('SOAR-1')

    // Just inside the skew window: still cached.
    clock += (3600 - 61) * 1000
    expect(await svc.soarBearer(SCOPE)).toBe('SOAR-1')
    expect(accessCalls(f)).toHaveLength(1)

    // Past `expires_in - 60s`: a fresh exchange.
    clock += 2000
    expect(await svc.soarBearer(SCOPE)).toBe('SOAR-2')
    expect(accessCalls(f)).toHaveLength(2)
  })

  it('reports a SOAR rejection, naming the cookies sent, on 401', async () => {
    const svc = makeService(stubFetch([json(401, { message: 'unauthorized' })]))
    await svc.login(OTP)

    const err = await expectNoSecrets(svc.soarBearer(SCOPE))
    expect(err.message).toMatch(/SOAR rejected the SOC session/i)
    expect(err.message).toContain('401')
    expect(err.message).toContain('cookies sent: [')
    expect(svc.isAuthenticated()).toBe(false)
  })

  it('reports a SOAR rejection, naming the cookies sent, on 403', async () => {
    const svc = makeService(stubFetch([json(403, {})]))
    await svc.login(OTP)
    const err = await expectNoSecrets(svc.soarBearer(SCOPE))
    expect(err.message).toMatch(/SOAR rejected the SOC session/i)
    expect(err.message).toContain('403')
  })

  it('rejects with a malformed/WAF error on a non-JSON response', async () => {
    const svc = makeService(stubFetch([html(200, '<html><body>Blocked by WAF</body></html>')]))
    await svc.login(OTP)

    const err = await expectNoSecrets(svc.soarBearer(SCOPE))
    expect(err.message).toMatch(/WAF|malformed|non-JSON/i)
  })

  it('rejects listing only safe keys when access_token is missing', async () => {
    const svc = makeService(
      stubFetch([json(200, { refresh_token: 'RT', id_token: 'IDT', status: 'nope' })]),
    )
    await svc.login(OTP)

    const err = await expectNoSecrets(svc.soarBearer(SCOPE))
    expect(err.message).toMatch(/access_token/)
    expect(err.message).toContain('status')
    expect(err.message).not.toContain('RT')
    expect(err.message).not.toContain('IDT')
  })
})

describe('SocAuthService.authHeadersForSoar', () => {
  it('carries the latest bearer plus the session cookies', async () => {
    const f = stubFetch([
      json(200, { access_token: 'SOAR-1', expires_in: 3600 }),
      json(200, { access_token: 'SOAR-2', expires_in: 3600 }),
    ])
    let clock = 1_000_000
    const svc = makeService(f, () => clock)
    await svc.login(OTP)
    await svc.soarBearer(SCOPE)

    const headers = svc.authHeadersForSoar(SCOPE)
    expect(headers.Authorization).toBe('Bearer SOAR-1')
    // SOAR keys on the `token` cookie the SPA builds, carried with the WAF D1N
    expect(headers.Cookie).toContain('D1N=waf-cookie')
    expect(headers.Cookie).toMatch(/token=\{.*SESS-TOKEN/)

    clock += 3600 * 1000
    await svc.soarBearer(SCOPE)
    expect(svc.authHeadersForSoar(SCOPE).Authorization).toBe('Bearer SOAR-2')
  })

  it('omits Authorization until a bearer has been fetched', async () => {
    const svc = makeService(stubFetch([]))
    await svc.login(OTP)
    expect(svc.authHeadersForSoar(SCOPE).Authorization).toBeUndefined()
  })
})

const EDR = 'https://edr.example'

/**
 * A fetch stub for the EDR flow, mirroring `stubFetch` but for EDR's routes:
 *  - the WSO2 login sequence;
 *  - the per-system OIDC authorize (carries the SSO cookie) → EDR `/v2/callback`;
 *  - the IAM `/authen/callback` that returns the `session_token`;
 *  - a caller-supplied queue for `/authentication/GetAccessTokenBySocToken`.
 */
function stubFetchEdr(tokenResponses: Response[], wso2: Response[] = wso2HappyPath()) {
  let iam = 0
  let tok = 0
  const cookieOf = (init: any): string => String(init?.headers?.cookie ?? '')
  const fn = vi.fn(async (url: string, init?: any) => {
    const u = String(url)
    if (u.startsWith(`${EDR}/authentication/GetAccessTokenBySocToken`)) {
      const res = tokenResponses[tok++]
      if (!res) throw new Error('unexpected extra EDR token call')
      return res
    }
    // EDR exchanges the SOC token at the IAM host, not its own host.
    if (u.startsWith(`${IAM}/authen/callback`)) {
      return json(200, { session_token: 'SESS-EDR', id_token: 'ID-EDR', access_token: 'AC' })
    }
    // per-system authorize: rides the SSO cookie, 302s to EDR's callback.
    if (u.startsWith(`${IAM}/oauth2/authorize`) && u.includes('redirect_uri=')
      && cookieOf(init).includes('commonAuthId')) {
      return redirect(`${EDR}/v2/callback?code=EDRCODE`)
    }
    const res = wso2[iam++]
    if (!res) throw new Error('unexpected extra WSO2 fetch call')
    return res
  })
  return fn
}

/** The `/authentication/GetAccessTokenBySocToken` calls alone. */
function edrCalls(f: ReturnType<typeof stubFetchEdr>) {
  return callsOf(f).filter((c) => String(c[0]).includes('/authentication/GetAccessTokenBySocToken'))
}

function makeEdrService(fetchImpl: any, now: () => number = () => 1_000_000) {
  return makeService(fetchImpl, now, { edrBaseUrl: EDR })
}

describe('SocAuthService.edrToken', () => {
  it('rejects with a clear error before any login', async () => {
    const svc = makeEdrService(stubFetchEdr([]))
    const err = await expectNoSecrets(svc.edrToken())
    expect(err.message).toMatch(/not logged in/i)
  })

  it('exchanges the SOC token once and caches the EDR token', async () => {
    const f = stubFetchEdr([json(200, { success: true, access_token: 'EDR-1', refresh_token: 'RT', expired_in_seconds: 3600 })])
    const svc = makeEdrService(f)
    await svc.login(OTP)

    expect(await svc.edrToken()).toBe('EDR-1')
    expect(await svc.edrToken()).toBe('EDR-1')
    expect(edrCalls(f)).toHaveLength(1)

    const [url, init] = edrCalls(f)[0] as [string, any]
    expect(url).toBe(`${EDR}/authentication/GetAccessTokenBySocToken`)
    expect(init.method).toBe('POST')
    expect(String(init.headers['content-type'])).toMatch(/application\/json/)
    // The SOC token from the IAM callback is what EDR exchanges.
    expect(JSON.parse(init.body)).toEqual({ soc_token: 'SESS-EDR' })
  })

  it('posts the code to the IAM host callback with client_id EDR', async () => {
    const f = stubFetchEdr([json(200, { success: true, access_token: 'EDR-1', expired_in_seconds: 3600 })])
    const svc = makeEdrService(f)
    await svc.login(OTP)
    await svc.edrToken()

    const callback = callsOf(f).find((c) => String(c[0]).startsWith(`${IAM}/authen/callback`))
    expect(callback).toBeDefined()
    expect(JSON.parse(callback![1].body)).toEqual({ code: 'EDRCODE', client_id: 'EDR' })
  })

  it('re-exchanges once the clock passes expired_in_seconds minus the 60s skew', async () => {
    const f = stubFetchEdr([
      json(200, { success: true, access_token: 'EDR-1', expired_in_seconds: 3600 }),
      json(200, { success: true, access_token: 'EDR-2', expired_in_seconds: 3600 }),
    ])
    let clock = 1_000_000
    const svc = makeEdrService(f, () => clock)
    await svc.login(OTP)

    expect(await svc.edrToken()).toBe('EDR-1')

    // Just inside the skew window: still cached.
    clock += (3600 - 61) * 1000
    expect(await svc.edrToken()).toBe('EDR-1')
    expect(edrCalls(f)).toHaveLength(1)

    // Past `expired_in_seconds - 60s`: a fresh exchange.
    clock += 2000
    expect(await svc.edrToken()).toBe('EDR-2')
    expect(edrCalls(f)).toHaveLength(2)
  })

  it('reports an EDR rejection and forces a fresh login on 401', async () => {
    const svc = makeEdrService(stubFetchEdr([json(401, { message: 'unauthorized' })]))
    await svc.login(OTP)

    const err = await expectNoSecrets(svc.edrToken())
    expect(err.message).toMatch(/EDR rejected the SOC session/i)
    expect(err.message).toContain('401')
    expect(svc.isAuthenticated()).toBe(false)
  })

  it('rejects with a malformed/WAF error on a non-JSON response', async () => {
    const svc = makeEdrService(stubFetchEdr([html(200, '<html><body>Blocked by WAF</body></html>')]))
    await svc.login(OTP)

    const err = await expectNoSecrets(svc.edrToken())
    expect(err.message).toMatch(/WAF|malformed|non-JSON/i)
  })

  it('rejects listing only safe keys when access_token is missing', async () => {
    const svc = makeEdrService(
      stubFetchEdr([json(200, { success: false, refresh_token: 'RT', id_token: 'IDT', status: 'nope' })]),
    )
    await svc.login(OTP)

    const err = await expectNoSecrets(svc.edrToken())
    expect(err.message).toMatch(/access_token/)
    expect(err.message).toContain('status')
    expect(err.message).not.toContain('RT')
    expect(err.message).not.toContain('IDT')
  })
})

describe('SocAuthService.edrAuthHeaders', () => {
  it('carries the EDR credential as Authorization: Bearer, with the cookies alongside', async () => {
    const f = stubFetchEdr([json(200, { success: true, access_token: 'EDR-1', expired_in_seconds: 3600 })])
    const svc = makeEdrService(f)
    await svc.login(OTP)
    await svc.edrToken()

    // The EDR SPA's request layer sets `Authorization: Bearer <token>`; sending
    // only the cookie read as anonymous (200 with nothing, threatHunting 401).
    const headers = svc.edrAuthHeaders()
    expect(headers.Authorization).toBe('Bearer EDR-1')
    expect(headers.Cookie).toContain('access_token=EDR-1')
    expect(headers.Cookie).toContain('D1N=waf-cookie')
  })

  it('returns no cookie header until a token has been fetched', async () => {
    const svc = makeEdrService(stubFetchEdr([]))
    await svc.login(OTP)
    expect(svc.edrAuthHeaders().Cookie).toBeUndefined()
  })

  it('defaults edrBaseUrl to the the platform EDR host', () => {
    const svc = makeService(stubFetchEdr([]))
    expect(svc.edrBaseUrl).toBe('https://edr.example.com')
  })
})

const SIEM = 'https://siem.example'

/**
 * A fetch stub for the SIEM flow. SIEM has its OWN OAuth server (not the WSO2
 * per-scope authorize nor the EDR token exchange):
 *  - the WSO2 login sequence;
 *  - SIEM's own authorize on its host (carries the SSO cookie) → `${SIEM}?code=…`;
 *  - a caller-supplied queue for `${SIEM}/oauth/token`.
 */
function stubFetchSiem(tokenResponses: Response[], wso2: Response[] = wso2HappyPath()) {
  let iam = 0
  let tok = 0
  const cookieOf = (init: any): string => String(init?.headers?.cookie ?? '')
  const fn = vi.fn(async (url: string, init?: any) => {
    const u = String(url)
    if (u.startsWith(`${SIEM}/oauth/token`)) {
      const res = tokenResponses[tok++]
      if (!res) throw new Error('unexpected extra SIEM token call')
      return res
    }
    // SIEM's own authorize: rides the SSO cookie, 302s to its redirect_uri (the
    // SIEM host itself) carrying the code.
    if (u.startsWith(`${SIEM}/oauth/authorize`) && cookieOf(init).includes('commonAuthId')) {
      return redirect(`${SIEM}?code=SIEMCODE`)
    }
    const res = wso2[iam++]
    if (!res) throw new Error('unexpected extra WSO2 fetch call')
    return res
  })
  return fn
}

/** The `${SIEM}/oauth/token` calls alone. */
function siemCalls(f: ReturnType<typeof stubFetchSiem>) {
  return callsOf(f).filter((c) => String(c[0]).startsWith(`${SIEM}/oauth/token`))
}

function makeSiemService(fetchImpl: any, now: () => number = () => 1_000_000) {
  return makeService(fetchImpl, now, { siemBaseUrl: SIEM })
}

describe('SocAuthService.siemToken', () => {
  it('rejects with a clear error before any login', async () => {
    const svc = makeSiemService(stubFetchSiem([]))
    const err = await expectNoSecrets(svc.siemToken())
    expect(err.message).toMatch(/not logged in/i)
  })

  it('runs SIEM authorize then token exchange once, and caches the token', async () => {
    const f = stubFetchSiem([json(200, { access_token: 'SIEM-1', token_type: 'Bearer', expires_in: 3600 })])
    const svc = makeSiemService(f)
    await svc.login(OTP)

    expect(await svc.siemToken()).toBe('SIEM-1')
    expect(await svc.siemToken()).toBe('SIEM-1')
    expect(siemCalls(f)).toHaveLength(1)

    const [url, init] = siemCalls(f)[0] as [string, any]
    expect(url).toBe(`${SIEM}/oauth/token`)
    expect(init.method).toBe('POST')
    expect(String(init.headers['content-type'])).toMatch(/application\/x-www-form-urlencoded/)
    const body = new URLSearchParams(String(init.body))
    expect(body.get('code')).toBe('SIEMCODE')
    expect(body.get('client_id')).toBe('cym_portal')
    expect(body.get('grant_type')).toBe('authorization_code')
    expect(body.get('redirect_uri')).toBe(SIEM)
    expect(body.get('audience')).toBe('cym_dashboard_api')
  })

  it('parses the token defensively from `token` or `accessToken`', async () => {
    const fromToken = makeSiemService(stubFetchSiem([json(200, { token: 'SIEM-TK' })]))
    await fromToken.login(OTP)
    expect(await fromToken.siemToken()).toBe('SIEM-TK')

    const fromCamel = makeSiemService(stubFetchSiem([json(200, { accessToken: 'SIEM-CAMEL' })]))
    await fromCamel.login(OTP)
    expect(await fromCamel.siemToken()).toBe('SIEM-CAMEL')
  })

  it('caches with a short default TTL when the response omits expires_in', async () => {
    const f = stubFetchSiem([
      json(200, { access_token: 'SIEM-1' }),
      json(200, { access_token: 'SIEM-2' }),
    ])
    let clock = 1_000_000
    const svc = makeSiemService(f, () => clock)
    await svc.login(OTP)

    expect(await svc.siemToken()).toBe('SIEM-1')
    // Inside the 300s default (minus 60s skew): still cached.
    clock += 200 * 1000
    expect(await svc.siemToken()).toBe('SIEM-1')
    expect(siemCalls(f)).toHaveLength(1)
    // Past the default TTL: a fresh acquisition.
    clock += 200 * 1000
    expect(await svc.siemToken()).toBe('SIEM-2')
    expect(siemCalls(f)).toHaveLength(2)
  })

  it('reports the SIEM token endpoint status and message on a non-200, hiding secrets', async () => {
    const svc = makeSiemService(stubFetchSiem([json(401, { error: 'invalid_grant' })]))
    await svc.login(OTP)

    const err = await expectNoSecrets(svc.siemToken())
    expect(err.message).toMatch(/SIEM token endpoint returned HTTP 401/i)
    expect(err.message).toContain('invalid_grant')
  })

  it('rejects listing only safe keys when no token is present', async () => {
    const svc = makeSiemService(stubFetchSiem([json(200, { refresh_token: 'RT', id_token: 'IDT', status: 'nope' })]))
    await svc.login(OTP)

    const err = await expectNoSecrets(svc.siemToken())
    expect(err.message).toMatch(/no access token/i)
    expect(err.message).toContain('status')
    expect(err.message).not.toContain('RT')
    expect(err.message).not.toContain('IDT')
  })

  it('throws the SSO-expired error when SIEM authorize bounces to the login form', async () => {
    // The WSO2 login (IAM host) still succeeds; only the later SIEM authorize
    // bounces to the login form, i.e. the SSO session for SIEM is gone.
    let iam = 0
    const wso2 = wso2HappyPath()
    const f = vi.fn(async (url: string) => {
      const u = String(url)
      if (u.startsWith(`${SIEM}/oauth/authorize`)) {
        return redirect(`${IAM}/authenticationendpoint/login.do?sessionDataKey=K9`)
      }
      const res = wso2[iam++]
      if (!res) throw new Error('unexpected extra WSO2 fetch call')
      return res
    })
    const svc = makeSiemService(f)
    await svc.login(OTP)

    const err = await expectNoSecrets(svc.siemToken())
    expect(err.message).toMatch(/SSO session has expired|soc_login/i)
  })
})

describe('SocAuthService.siemAuthHeaders', () => {
  it('carries a Bearer token plus the WAF D1N cookie', async () => {
    const f = stubFetchSiem([json(200, { access_token: 'SIEM-1', token_type: 'Bearer', expires_in: 3600 })])
    const svc = makeSiemService(f)
    await svc.login(OTP)
    await svc.siemToken()

    const headers = svc.siemAuthHeaders()
    expect(headers.Authorization).toBe('Bearer SIEM-1')
    expect(headers.Cookie).toContain('D1N=waf-cookie')
  })

  it('returns no Authorization until a token has been fetched', async () => {
    const svc = makeSiemService(stubFetchSiem([]))
    await svc.login(OTP)
    expect(svc.siemAuthHeaders().Authorization).toBeUndefined()
  })

  it('defaults siemBaseUrl to the the platform SIEM host', () => {
    const svc = makeService(stubFetchSiem([]))
    expect(svc.siemBaseUrl).toBe('https://siem.example.com')
  })
})
