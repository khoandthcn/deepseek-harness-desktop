import { describe, it, expect, vi } from 'vitest'
import { SocAuthService } from '../src/service.ts'

const IAM = 'https://iam.example'
const REDIRECT_URI = 'https://app.example/callback'
const SOAR = 'https://soar.example'

const PASSWORD = 'sup3rs3cret'
const OTP = '123456'

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
    json(200, { access_token: 'SOC-TOKEN', expires_in: 1800, token_type: 'Bearer' }),
  ]
}

/**
 * A fetch stub that replays the WSO2 sequence for IAM urls and a caller-supplied
 * queue of responses for SOAR `/access_control/access` calls.
 */
function stubFetch(soarResponses: Response[], wso2: Response[] = wso2HappyPath()) {
  let iam = 0
  let soar = 0
  const fn = vi.fn(async (url: string) => {
    if (String(url).startsWith(SOAR)) {
      const res = soarResponses[soar++]
      if (!res) throw new Error('unexpected extra SOAR fetch call')
      return res
    }
    const res = wso2[iam++]
    if (!res) throw new Error('unexpected extra WSO2 fetch call')
    return res
  })
  return fn
}

function soarCalls(f: ReturnType<typeof stubFetch>) {
  return f.mock.calls.filter((c) => String(c[0]).startsWith(SOAR))
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
    username: 'alice',
    password: PASSWORD,
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
    const err = await expectNoSecrets(svc.soarBearer())
    expect(err.message).toMatch(/not logged in/i)
  })

  it('exchanges the SOC session once and caches the bearer', async () => {
    const f = stubFetch([json(200, { access_token: 'SOAR-1', expires_in: 3600 })])
    const svc = makeService(f)
    await svc.login(OTP)

    expect(await svc.soarBearer()).toBe('SOAR-1')
    expect(await svc.soarBearer()).toBe('SOAR-1')
    expect(soarCalls(f)).toHaveLength(1)

    const [url, init] = soarCalls(f)[0] as [string, any]
    expect(url).toBe(`${SOAR}/access_control/access`)
    expect(init.method).toBe('POST')
    expect(String(init.headers['content-type'])).toMatch(/application\/json/)
    expect(JSON.parse(init.body)).toEqual({
      tenant: 'MASTER',
      client_id: 'SOAR_CLIENT',
      scopes: '',
    })
    expect(String(init.headers['cookie'])).toContain('D1N=waf-cookie')
  })

  it('honours tenant and soarClientId overrides', async () => {
    const f = stubFetch([json(200, { access_token: 'SOAR-T', expires_in: 3600 })])
    const svc = makeService(f, () => 1_000_000, { tenant: 'VCS', soarClientId: 'OTHER' })
    await svc.login(OTP)
    await svc.soarBearer()

    const init = (soarCalls(f)[0] as [string, any])[1]
    expect(JSON.parse(init.body)).toEqual({ tenant: 'VCS', client_id: 'OTHER', scopes: '' })
  })

  it('re-exchanges once the clock passes expires_in minus the 60s skew', async () => {
    const f = stubFetch([
      json(200, { access_token: 'SOAR-1', expires_in: 3600 }),
      json(200, { access_token: 'SOAR-2', expires_in: 3600 }),
    ])
    let clock = 1_000_000
    const svc = makeService(f, () => clock)
    await svc.login(OTP)

    expect(await svc.soarBearer()).toBe('SOAR-1')

    // Just inside the skew window: still cached.
    clock += (3600 - 61) * 1000
    expect(await svc.soarBearer()).toBe('SOAR-1')
    expect(soarCalls(f)).toHaveLength(1)

    // Past `expires_in - 60s`: a fresh exchange.
    clock += 2000
    expect(await svc.soarBearer()).toBe('SOAR-2')
    expect(soarCalls(f)).toHaveLength(2)
  })

  it('rejects with a session-expired error on 401', async () => {
    const svc = makeService(stubFetch([json(401, { message: 'unauthorized' })]))
    await svc.login(OTP)

    const err = await expectNoSecrets(svc.soarBearer())
    expect(err.message).toMatch(/session expired|expired/i)
    expect(err.message).toContain('401')
    expect(svc.isAuthenticated()).toBe(false)
  })

  it('rejects with a session-expired error on 403', async () => {
    const svc = makeService(stubFetch([json(403, {})]))
    await svc.login(OTP)
    const err = await expectNoSecrets(svc.soarBearer())
    expect(err.message).toMatch(/expired/i)
  })

  it('rejects with a malformed/WAF error on a non-JSON response', async () => {
    const svc = makeService(stubFetch([html(200, '<html><body>Blocked by WAF</body></html>')]))
    await svc.login(OTP)

    const err = await expectNoSecrets(svc.soarBearer())
    expect(err.message).toMatch(/WAF|malformed|non-JSON/i)
  })

  it('rejects listing only safe keys when access_token is missing', async () => {
    const svc = makeService(
      stubFetch([json(200, { refresh_token: 'RT', id_token: 'IDT', status: 'nope' })]),
    )
    await svc.login(OTP)

    const err = await expectNoSecrets(svc.soarBearer())
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
    await svc.soarBearer()

    const headers = svc.authHeadersForSoar()
    expect(headers.Authorization).toBe('Bearer SOAR-1')
    expect(headers.Cookie).toContain('commonAuthId=abc123')
    expect(headers.Cookie).toContain('D1N=waf-cookie')

    clock += 3600 * 1000
    await svc.soarBearer()
    expect(svc.authHeadersForSoar().Authorization).toBe('Bearer SOAR-2')
  })

  it('omits Authorization until a bearer has been fetched', async () => {
    const svc = makeService(stubFetch([]))
    await svc.login(OTP)
    expect(svc.authHeadersForSoar().Authorization).toBeUndefined()
  })
})
