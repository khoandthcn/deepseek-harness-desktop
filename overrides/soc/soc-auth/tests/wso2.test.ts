import { describe, it, expect, vi } from 'vitest'
import { parseSessionDataKey, runWso2Login } from '../src/wso2.ts'

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
    json(200, { access_token: 'TOKEN-XYZ', expires_in: 1800, token_type: 'Bearer' }),
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

    expect(out).toEqual({ accessToken: 'TOKEN-XYZ', expiresIn: 1800 })
    expect(f).toHaveBeenCalledTimes(5)

    // Step 1: authorize
    const authorize = new URL(String(f.mock.calls[0][0]))
    expect(authorize.pathname).toBe('/oauth2/authorize')
    expect(authorize.searchParams.get('response_type')).toBe('code')
    expect(authorize.searchParams.get('client_id')).toBe('cid')
    expect(authorize.searchParams.get('redirect_uri')).toBe(REDIRECT_URI)
    expect(authorize.searchParams.get('scope')).toBe('openid')
    expect((f.mock.calls[0][1] as any).redirect).toBe('manual')

    // Step 2: password POST
    const pwCall = f.mock.calls[1] as any
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
    const otpCall = f.mock.calls[2] as any
    expect(String(otpCall[0])).toBe(`${IAM}/commonauth`)
    const otpBody = bodyOf(otpCall)
    expect(otpBody.get('token')).toBe('123456')
    expect(otpBody.get('sessionDataKey')).toBe('K2')
    expect(otpBody.get('password')).toBeNull()

    // Step 4: follow the authorize redirect
    expect(String(f.mock.calls[3][0])).toBe(`${IAM}/oauth2/authorize?sessionDataKey=K3`)

    // Step 5: token exchange
    const tokenCall = f.mock.calls[4] as any
    expect(String(tokenCall[0])).toBe(`${IAM}/oauth2/token`)
    const tokenBody = bodyOf(tokenCall)
    expect(tokenBody.get('grant_type')).toBe('authorization_code')
    expect(tokenBody.get('code')).toBe('CODE-123')
    expect(tokenBody.get('redirect_uri')).toBe(REDIRECT_URI)
    expect(tokenBody.get('client_id')).toBe('cid')
  })

  it('defaults expiresIn to 3600 when the token response omits it', async () => {
    const rs = happyPathResponses()
    rs[4] = json(200, { access_token: 'T' })
    const out = await runWso2Login({ ...baseOpts, fetchImpl: sequenceFetch(rs) as any })
    expect(out.expiresIn).toBe(3600)
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

  it('rejects when the token response has no access_token', async () => {
    const rs = happyPathResponses()
    rs[4] = json(200, { error: 'invalid_grant' })
    await expect(
      runWso2Login({ ...baseOpts, fetchImpl: sequenceFetch(rs) as any }),
    ).rejects.toThrow(/access_token/i)
  })
})
