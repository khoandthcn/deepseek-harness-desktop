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

import { D1N_COOKIE, parseD1nBootstrap } from '@deepseek-ai/dsh-soc-client'

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
  scope?: string | undefined
  /** Injectable fetch, for tests. Defaults to the global `fetch`. */
  fetchImpl?: FetchLike | undefined
  /**
   * Called once, on success, with a snapshot of the cookie jar built during the
   * flow (`commonAuthId`, the WAF `D1N` cookie, ...). Downstream systems such as
   * SOAR authenticate with these session cookies, so the caller needs a copy.
   */
  onCookies?: ((cookies: Record<string, string>) => void) | undefined
}

export interface Wso2LoginResult {
  /** The SOC access token from the portal exchange. */
  accessToken: string
  /** Cookies collected across the flow: `commonAuthId`, `D1N`, and the portal's `token` when it set one. */
  cookies: Record<string, string>
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

  set(name: string, value: string): void {
    this.jar.set(name, value)
  }

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

  snapshot(): Record<string, string> {
    return Object.fromEntries(this.jar)
  }
}

function readSetCookies(res: Response): string[] {
  const headers = res.headers as Headers & { getSetCookie?: () => string[] }
  if (typeof headers.getSetCookie === 'function') return headers.getSetCookie()
  const single = res.headers.get('set-cookie')
  return single ? [single] : []
}

export interface AppSessionOptions {
  /** WSO2 IAM base URL. */
  iamUrl: string
  /** This system's registered OIDC client id (SOAR uses `SOAR_CLIENT`). */
  clientId: string
  /** This system's callback URL (SOAR: `https://soar.../callback`). */
  redirectUri: string
  /** Cookies from a completed WSO2 login: the SSO session (`commonAuthId`) and `D1N`. */
  cookies: Record<string, string>
  /** OAuth scope; defaults to `openid`. */
  scope?: string | undefined
  fetchImpl?: FetchLike | undefined
}

/**
 * Obtain a per-system session on top of an existing WSO2 SSO login.
 *
 * Each SOC system (SOAR, SIEM, EDR, NSM) has its own OIDC client and callback.
 * Because the WSO2 login already set the SSO cookie (`commonAuthId`), the
 * system's authorize skips the username/password/OTP form and redirects
 * straight to its callback, which sets the cookie the system's API keys on
 * (SOAR: `token`). This follows that redirect chain — carrying and collecting
 * cookies, adopting the WAF `D1N` bootstrap if it appears — and returns the jar.
 *
 * @returns the authorization `code` from the system callback and the cookies
 *   collected on the way (the WAF `D1N`), for the caller to exchange the code
 *   for the system's session and to send on its API requests.
 * @throws when the chain lands back on the login form: the SSO session is gone,
 *   so a fresh {@link runWso2Login} (a new OTP) is required.
 */
export async function establishAppSession(
  opts: AppSessionOptions,
): Promise<{ code: string, cookies: Record<string, string> }> {
  const doFetch: FetchLike = opts.fetchImpl ?? ((input, init) => fetch(input, init))
  const iam = opts.iamUrl.replace(/\/+$/, '')
  const jar = new CookieJar()
  for (const [name, value] of Object.entries(opts.cookies)) jar.set(name, value)

  const request = async (url: string, afterBootstrap = false): Promise<Response> => {
    const headers: Record<string, string> = {}
    const cookie = jar.header()
    if (cookie) headers['cookie'] = cookie
    let res: Response
    try {
      res = await doFetch(url, { headers, redirect: 'manual' })
    } catch (cause) {
      throw new SocAuthError(
        `SOC auth: the ${opts.clientId} authorize request to ${redactUrl(url)} failed (network error).`,
        { cause },
      )
    }
    jar.absorb(res)
    if (!afterBootstrap && res.status === 200) {
      const d1n = parseD1nBootstrap(await res.clone().text())
      if (d1n !== undefined) {
        jar.set(D1N_COOKIE, d1n)
        return request(url, true)
      }
    }
    return res
  }

  let next = `${iam}/oauth2/authorize?${new URLSearchParams({
    response_type: 'code',
    client_id: opts.clientId,
    redirect_uri: opts.redirectUri,
    scope: opts.scope ?? 'openid',
  }).toString()}`
  const callbackBase = opts.redirectUri.split('?')[0]

  // authorize → system callback: with the SSO cookie the authorize skips the
  // login form and 302s straight to the callback carrying `code`. Cap the hops
  // so a misconfiguration surfaces as an error rather than an infinite loop.
  for (let hop = 0; hop < 8; hop++) {
    const res = await request(next)
    if (!REDIRECT_STATUSES.has(res.status)) {
      throw new SocAuthError(
        `SOC auth: the ${opts.clientId} authorize did not redirect to its callback (HTTP ${res.status}).`,
      )
    }
    const location = res.headers.get('location')
    if (!location) {
      throw new SocAuthError(
        `SOC auth: the ${opts.clientId} authorize returned a redirect without a location.`,
      )
    }
    const abs = new URL(location, `${iam}/`)
    if (/login\.do|sessionDataKey/.test(abs.href)) {
      throw new SocAuthError(
        'SOC auth: the WSO2 SSO session has expired — log in again with a new OTP.',
      )
    }
    const code = abs.searchParams.get('code')
    if (code && `${abs.origin}${abs.pathname}` === callbackBase) {
      return { code, cookies: jar.snapshot() }
    }
    next = abs.href
  }
  throw new SocAuthError(
    `SOC auth: the ${opts.clientId} authorize never reached its callback with a code.`,
  )
}

export async function runWso2Login(opts: Wso2LoginOptions): Promise<Wso2LoginResult> {
  const doFetch: FetchLike = opts.fetchImpl ?? ((input, init) => fetch(input, init))
  const iam = opts.iamUrl.replace(/\/+$/, '')
  const jar = new CookieJar()

  const request = async (
    url: string,
    init: Record<string, any> = {},
    afterBootstrap = false,
  ): Promise<Response> => {
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
    // The WAF answers a cookie-less client with a page that sets `D1N` via
    // script and reloads. Peek at a clone so the caller still gets the body;
    // adopt the cookie and reissue this same request, once.
    if (!afterBootstrap && res.status === 200) {
      const d1n = parseD1nBootstrap(await res.clone().text())
      if (d1n !== undefined) {
        jar.set(D1N_COOKIE, d1n)
        return request(url, init, true)
      }
    }
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

  // Step 5 — hand the code to the SOC portal. The browser never calls
  // /oauth2/token itself: the portal does, server-side, with a client secret we
  // do not hold, and answers with the SOC access token. The session cookie SOAR
  // keys on (`token`) rides the same response as Set-Cookie, into the jar.
  const portal = opts.redirectUri.replace(/\/+$/, '')
  const res5 = await request(`${portal}/authen-api/auth`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ clientId: opts.clientId, code }),
  })
  if (res5.status !== 200) {
    throw new SocAuthError(
      `WSO2 login: the portal code exchange (${portal}/authen-api/auth) returned HTTP ${res5.status}.`,
    )
  }
  let payload: any
  try {
    payload = await res5.json()
  } catch (cause) {
    throw new SocAuthError('WSO2 login: the portal code exchange returned a non-JSON body.', { cause })
  }
  const accessToken = payload?.accessToken
  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    throw new SocAuthError(
      `WSO2 login: the portal code exchange returned no accessToken (keys: ${Object.keys(payload ?? {}).join(', ') || 'none'}).`,
    )
  }
  const cookies = jar.snapshot()
  if (cookies['token'] === undefined) {
    // Not fatal here — SOAR may still accept the access token — but say so
    // precisely, since this is the one step the capture could not show us.
    console.warn(
      `soc-auth: the portal code exchange set no "token" cookie; cookies held: [${Object.keys(cookies).join(', ')}]`,
    )
  }

  const snapshot = jar.snapshot()
  opts.onCookies?.(snapshot)
  return { accessToken, cookies: snapshot }
}
