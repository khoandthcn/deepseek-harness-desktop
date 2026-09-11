/**
 * WSO2 Identity Server single-shot login: username + password + a runtime OTP,
 * driven as pure functions over an injectable `fetch`.
 *
 * The flow below is transcribed from a real HAR capture. Every request uses
 * `redirect: 'manual'` and the session cookies (`commonAuthId`, ...) are carried
 * across steps by a small per-login cookie jar.
 *
 * Secrets rule: the password and the OTP value are NEVER logged nor included in
 * any error message thrown from this module.
 */

export class SocAuthError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'SocAuthError'
  }
}

export type FetchLike = (input: string, init?: any) => Promise<Response>

export interface Wso2LoginOptions {
  /** Base URL of the WSO2 IAM server, e.g. `https://iam.example`. */
  iamUrl: string
  clientId: string
  redirectUri: string
  username: string
  password: string
  /** Current one-time password from the user's authenticator. */
  otp: string
  /** OAuth scope; defaults to `openid`. */
  scope?: string
  /** Injectable fetch, for tests. Defaults to the global `fetch`. */
  fetchImpl?: FetchLike
}

export interface Wso2LoginResult {
  accessToken: string
  expiresIn: number
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])

/** Extract the `sessionDataKey` query parameter from a (possibly relative) URL. */
export function parseSessionDataKey(location: string): string {
  const key = readQueryParam(location, 'sessionDataKey')
  if (!key) {
    throw new SocAuthError(
      `WSO2 login: no sessionDataKey in the redirect target (${redactUrl(location)}).`,
    )
  }
  return key
}

function readQueryParam(location: string, name: string): string | null {
  let url: URL
  try {
    url = new URL(location, 'http://localhost')
  } catch (cause) {
    throw new SocAuthError(`WSO2 login: could not parse the redirect target.`, { cause })
  }
  return url.searchParams.get(name)
}

/** Drop the query string, so no sensitive parameter can leak into an error. */
function redactUrl(location: string): string {
  const cut = location.indexOf('?')
  return cut === -1 ? location : `${location.slice(0, cut)}?…`
}

/** Minimal cookie jar: accumulates `set-cookie` values into a `Cookie` header. */
class CookieJar {
  private readonly jar = new Map<string, string>()

  absorb(res: Response): void {
    for (const raw of readSetCookies(res)) {
      const pair = raw.split(';', 1)[0]?.trim()
      if (!pair) continue
      const eq = pair.indexOf('=')
      if (eq <= 0) continue
      this.jar.set(pair.slice(0, eq), pair.slice(eq + 1))
    }
  }

  header(): string | undefined {
    if (this.jar.size === 0) return undefined
    return [...this.jar].map(([k, v]) => `${k}=${v}`).join('; ')
  }
}

function readSetCookies(res: Response): string[] {
  const headers = res.headers as Headers & { getSetCookie?: () => string[] }
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie()
  const single = res.headers.get('set-cookie')
  return single ? [single] : []
}

export async function runWso2Login(opts: Wso2LoginOptions): Promise<Wso2LoginResult> {
  const doFetch: FetchLike = opts.fetchImpl ?? ((input, init) => fetch(input, init))
  const iam = opts.iamUrl.replace(/\/+$/, '')
  const jar = new CookieJar()

  const request = async (url: string, init: Record<string, any> = {}): Promise<Response> => {
    const headers: Record<string, string> = { ...(init.headers ?? {}) }
    const cookie = jar.header()
    if (cookie) headers['cookie'] = cookie
    let res: Response
    try {
      res = await doFetch(url, { ...init, headers, redirect: 'manual' })
    } catch (cause) {
      throw new SocAuthError(
        `WSO2 login: request to ${redactUrl(url)} failed (network error).`,
        { cause },
      )
    }
    jar.absorb(res)
    return res
  }

  const form = (fields: Record<string, string>) => ({
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
  })

  const locationOf = (res: Response, step: string): string => {
    const location = res.headers.get('location')
    if (!location) {
      throw new SocAuthError(`WSO2 login: ${step} returned a redirect without a location header.`)
    }
    return new URL(location, `${iam}/`).toString()
  }

  // Step 1 — start the authorization code flow, collect sessionDataKey K1.
  const authorizeUrl = `${iam}/oauth2/authorize?${new URLSearchParams({
    response_type: 'code',
    client_id: opts.clientId,
    redirect_uri: opts.redirectUri,
    scope: opts.scope ?? 'openid',
  }).toString()}`
  const res1 = await request(authorizeUrl)
  if (!REDIRECT_STATUSES.has(res1.status)) {
    throw new SocAuthError(
      `WSO2 login: the authorize endpoint returned HTTP ${res1.status}, expected a redirect to the login page.`,
    )
  }
  const key1 = parseSessionDataKey(locationOf(res1, 'the authorize step'))

  // Step 2 — username + password; must land on the TOTP page.
  const res2 = await request(
    `${iam}/commonauth`,
    form({
      usernameUserInput: opts.username,
      username: opts.username,
      password: opts.password,
      sessionDataKey: key1,
    }),
  )
  if (!REDIRECT_STATUSES.has(res2.status)) {
    throw new SocAuthError(
      `WSO2 login: the password step returned HTTP ${res2.status}, expected a redirect to the OTP step.`,
    )
  }
  const loc2 = locationOf(res2, 'the password step')
  if (!loc2.includes('totp.do')) {
    throw new SocAuthError(
      'WSO2 login: the password step did not reach the OTP step (likely a wrong username or password).',
    )
  }
  const key2 = parseSessionDataKey(loc2)

  // Step 3 — submit the OTP; success is a redirect back to /oauth2/authorize.
  const res3 = await request(`${iam}/commonauth`, form({ token: opts.otp, sessionDataKey: key2 }))
  if (!REDIRECT_STATUSES.has(res3.status)) {
    throw new SocAuthError(
      `WSO2 login: OTP rejected (the OTP step returned HTTP ${res3.status} instead of a redirect).`,
    )
  }
  const loc3 = locationOf(res3, 'the OTP step')

  // Step 4 — follow the authorize redirect to pick up the authorization code.
  const res4 = await request(loc3)
  if (!REDIRECT_STATUSES.has(res4.status)) {
    throw new SocAuthError(
      `WSO2 login: the authorize callback returned HTTP ${res4.status}, expected a redirect carrying the authorization code.`,
    )
  }
  const code = readQueryParam(locationOf(res4, 'the authorize callback'), 'code')
  if (!code) {
    throw new SocAuthError('WSO2 login: the redirect back carried no authorization code.')
  }

  // Step 5 — exchange the code for an access token.
  const res5 = await request(
    `${iam}/oauth2/token`,
    form({
      grant_type: 'authorization_code',
      code,
      redirect_uri: opts.redirectUri,
      client_id: opts.clientId,
    }),
  )
  if (res5.status !== 200) {
    throw new SocAuthError(`WSO2 login: the token endpoint returned HTTP ${res5.status}.`)
  }
  let payload: any
  try {
    payload = await res5.json()
  } catch (cause) {
    throw new SocAuthError('WSO2 login: the token endpoint returned a non-JSON body.', { cause })
  }
  const accessToken = payload?.access_token
  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    throw new SocAuthError('WSO2 login: the token response contained no access_token.')
  }
  const expiresIn = Number(payload?.expires_in ?? 3600)
  return { accessToken, expiresIn: Number.isFinite(expiresIn) ? expiresIn : 3600 }
}
