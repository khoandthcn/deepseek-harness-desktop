/**
 * `SocAuthService` — the single holder of SOC session state.
 *
 * It is deliberately **dependency-free** (no `@deepseek-ai/*` imports) so it can
 * be unit-tested standalone; `index.ts` is the thin Cordis wrapper that exposes
 * an instance as `ctx.socAuth`.
 *
 * Responsibilities:
 *  - `login(otp)` drives the WSO2 single-shot flow (`runWso2Login`) and keeps the
 *    resulting SOC access token plus the session cookie jar.
 *  - `soarBearer()` exchanges that session for a SOAR Bearer via
 *    `POST {soarBaseUrl}/access_control/access` and caches it until it expires.
 *
 * Ported from the tested Python equivalent `socp_mcp/auth/soar_refresh.py`.
 *
 * Secrets rule: the password and the OTP are never logged and never appear in a
 * thrown message.
 */

import { establishAppSession, runWso2Login, SocAuthError, type FetchLike } from './wso2.ts'

/** Refresh a little before the real expiry, so an in-flight call cannot race it. */
const REFRESH_SKEW_MS = 60_000

/** Keys that must never be echoed back in an error message. */
const SECRET_KEYS = new Set(['access_token', 'refresh_token', 'id_token'])

export interface SocAuthServiceOptions {
  /** Base URL of the WSO2 IAM server, e.g. `https://iam.example`. */
  iamUrl: string
  clientId: string
  redirectUri: string
  /** Base URL of the SOAR API, e.g. `https://soar.example`. */
  soarBaseUrl: string
  /** SOAR tenant; `MASTER` unless the deployment says otherwise. */
  tenant?: string | undefined
  /** SOAR OAuth client id used by its authorize. Defaults to `SOAR_CLIENT`. */
  soarClientId?: string | undefined
  /** SOAR OIDC callback URL. Defaults to `${soarBaseUrl}/callback`. */
  soarRedirectUri?: string | undefined
  /** SOAR `authen` base that exchanges the code for a session. Defaults to `${soarBaseUrl}/authen`. */
  soarAuthenUrl?: string | undefined
  /**
   * Supplies the login credentials when a login actually runs. A callback,
   * not two strings: the credentials seam is asynchronous, and the secret
   * should not be held in memory for the life of the session.
   */
  credentials: () => Promise<{ username: string, password: string }>
  /** Injectable fetch, for tests. Defaults to the global `fetch`. */
  fetchImpl?: FetchLike | undefined
  /** Injectable clock in epoch milliseconds, for expiry tests. */
  now?: (() => number) | undefined
}

export class SocAuthService {
  private readonly iamUrl: string
  private readonly clientId: string
  private readonly redirectUri: string
  /**
   * Base URL of the SOAR API, without a trailing slash. Public because the
   * SOAR tool plugin reads it from here: the endpoint is configured once, on
   * this plugin, so the two cannot drift apart.
   */
  readonly soarBaseUrl: string
  /** SOAR tenant, defaulted at construction. Public for the same reason. */
  readonly tenant: string
  private readonly soarClientId: string
  private readonly soarRedirectUri: string
  private readonly soarAuthenUrl: string
  private readonly credentials: () => Promise<{ username: string, password: string }>
  private readonly fetchImpl?: FetchLike | undefined
  private readonly now: () => number

  /** SOC session state, set by `login()` and cleared when it is invalidated. */
  private socToken: string | null = null
  /** The WSO2 SSO login jar: `commonAuthId`, `D1N`. Seeds each per-system authorize. */
  private cookies: Record<string, string> = {}
  /** The SOAR per-system jar: `token`, `D1N`. Sent on SOAR API calls. */
  private soarCookies: Record<string, string> = {}

  /** The SOAR session (cookies + session token), acquired once, reused for every scope. */
  private soarSession: { cookies: Record<string, string>, sessionToken: string } | null = null
  private sessionInflight: Promise<{ cookies: Record<string, string>, sessionToken: string }> | null = null
  /** SOAR Bearer cache, keyed by scope: the access exchange mints one Bearer per scope. */
  private readonly soarBearers = new Map<string, { token: string, exp: number }>()
  /** De-duplicates concurrent exchanges for the same scope. */
  private readonly bearerInflight = new Map<string, Promise<string>>()

  constructor(opts: SocAuthServiceOptions) {
    this.iamUrl = opts.iamUrl.replace(/\/+$/, '')
    this.clientId = opts.clientId
    this.redirectUri = opts.redirectUri
    this.soarBaseUrl = opts.soarBaseUrl.replace(/\/+$/, '')
    this.tenant = opts.tenant ?? 'MASTER'
    this.soarClientId = opts.soarClientId ?? 'SOAR_CLIENT'
    this.soarRedirectUri = opts.soarRedirectUri ?? `${this.soarBaseUrl}/callback`
    this.soarAuthenUrl = (opts.soarAuthenUrl ?? `${this.soarBaseUrl}/authen`).replace(/\/+$/, '')
    this.credentials = opts.credentials
    this.fetchImpl = opts.fetchImpl
    this.now = opts.now ?? (() => Date.now())
  }

  /** True once a SOC login has succeeded and the session has not been invalidated. */
  isAuthenticated(): boolean {
    return this.socToken !== null
  }

  /**
   * Run the whole WSO2 flow with the stored username/password and the OTP the
   * user just read from their authenticator. Throws on any failure.
   */
  async login(otp: string): Promise<void> {
    this.invalidate()
    let cookies: Record<string, string> = {}
    const { username, password } = await this.credentials()
    const result = await runWso2Login({
      iamUrl: this.iamUrl,
      clientId: this.clientId,
      redirectUri: this.redirectUri,
      username,
      password,
      otp,
      fetchImpl: this.fetchImpl,
      onCookies: (jar) => {
        cookies = jar
      },
    })
    this.socToken = result.accessToken
    this.cookies = cookies
  }

  /** Forget the SOC session and any cached SOAR bearer. */
  invalidate(): void {
    this.socToken = null
    this.cookies = {}
    this.soarCookies = {}
    this.soarSession = null
    this.sessionInflight = null
    this.soarBearers.clear()
    this.bearerInflight.clear()
  }

  /**
   * The SOAR Bearer for one scope, exchanged lazily and cached per scope until
   * `expires_in` (minus a 60s skew). SOAR mints a Bearer per scope, so each API
   * family (`read:alert`, `read:ticket`, …) needs its own.
   * @param scope - the scope the target endpoint requires.
   */
  async soarBearer(scope: string): Promise<string> {
    if (!this.isAuthenticated()) {
      throw new SocAuthError(
        'SOC auth: not logged in — ask the user for their current OTP and call soc_login first.',
      )
    }
    const cached = this.soarBearers.get(scope)
    if (cached && this.now() < cached.exp - REFRESH_SKEW_MS) {
      return cached.token
    }
    let inflight = this.bearerInflight.get(scope)
    if (!inflight) {
      inflight = this.exchangeSoarBearer(scope).finally(() => {
        this.bearerInflight.delete(scope)
      })
      this.bearerInflight.set(scope, inflight)
    }
    return inflight
  }

  /**
   * Headers for a SOAR request: the cached Bearer (when one has been fetched)
   * plus the session cookies, including the WAF `D1N` cookie when present.
   */
  authHeadersForSoar(scope: string): Record<string, string> {
    const headers: Record<string, string> = {}
    const bearer = this.soarBearers.get(scope)
    if (bearer) headers.Authorization = `Bearer ${bearer.token}`
    headers.Cookie = this.cookieHeader()
    return headers
  }

  /** The SOAR per-system cookies (`token`, `D1N`), set by the per-system authorize. */
  private cookieJar(): Record<string, string> {
    return { ...this.soarCookies }
  }

  private cookieHeader(): string {
    const jar = this.cookieJar()
    return Object.entries(jar)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ')
  }

  /**
   * Acquire the SOAR per-system session: run SOAR's own authorize on top of the
   * SSO login, exchange the returned code at `authen/callback` for a
   * `session_token`, and build the `token` cookie SOAR keys on. That cookie is
   * not a Set-Cookie — the SOAR SPA builds it in the browser as
   * `JSON.stringify({ token: session_token, id_token })`, so we build it the
   * same way here. The value is never logged.
   * @returns the cookie jar to send on SOAR requests: `token` plus the WAF `D1N`.
   */
  /** Acquire the SOAR session once and reuse it for every scope exchange. */
  private async ensureSoarSession(
    doFetch: FetchLike,
  ): Promise<{ cookies: Record<string, string>, sessionToken: string }> {
    if (this.soarSession) return this.soarSession
    if (!this.sessionInflight) {
      this.sessionInflight = this.acquireSoarSession(doFetch)
        .then((session) => {
          this.soarSession = session
          this.soarCookies = session.cookies
          return session
        })
        .finally(() => { this.sessionInflight = null })
    }
    return this.sessionInflight
  }

  private async acquireSoarSession(
    doFetch: FetchLike,
  ): Promise<{ cookies: Record<string, string>, sessionToken: string }> {
    const { code, cookies } = await establishAppSession({
      iamUrl: this.iamUrl,
      clientId: this.soarClientId,
      redirectUri: this.soarRedirectUri,
      cookies: this.cookies,
      fetchImpl: this.fetchImpl,
    })
    const cookieHeader = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ')
    const callbackUrl = `${this.soarAuthenUrl}/callback`
    let res: Response
    try {
      res = await doFetch(callbackUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(cookieHeader ? { cookie: cookieHeader } : {}) },
        body: JSON.stringify({ code, client_id: this.soarClientId }),
      })
    } catch (cause) {
      throw new SocAuthError(`SOC auth: the SOAR code exchange (${callbackUrl}) failed (network error).`, { cause })
    }
    if (res.status !== 200) {
      throw new SocAuthError(`SOC auth: the SOAR code exchange (${callbackUrl}) returned HTTP ${res.status}.`)
    }
    let payload: any
    try {
      payload = await res.json()
    } catch (cause) {
      throw new SocAuthError('SOC auth: the SOAR code exchange returned a non-JSON body.', { cause })
    }
    const sessionToken = payload?.session_token
    if (typeof sessionToken !== 'string' || sessionToken.length === 0) {
      throw new SocAuthError(
        `SOC auth: the SOAR code exchange returned no session_token (response keys: ${safeKeys(payload)}).`,
      )
    }
    const idToken = payload?.id_token
    const tokenValue: Record<string, string> = { token: sessionToken }
    if (typeof idToken === 'string' && idToken.length > 0 && idToken !== 'undefined') {
      tokenValue.id_token = idToken
    }
    const jar: Record<string, string> = { token: JSON.stringify(tokenValue) }
    if (cookies.D1N !== undefined) jar.D1N = cookies.D1N
    return { cookies: jar, sessionToken }
  }

  private async exchangeSoarBearer(scope: string): Promise<string> {
    const doFetch: FetchLike = this.fetchImpl ?? ((input, init) => fetch(input, init))
    // SOAR runs its own OIDC authorize on top of the SSO login; the session is
    // scope-independent, so it is acquired once and reused across scopes.
    const session = await this.ensureSoarSession(doFetch)
    const url = `${this.soarBaseUrl}/access_control/access`
    let res: Response
    try {
      res = await doFetch(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          // SOAR authenticates the exchange with BOTH the session token as a
          // Bearer and the same token inside the `token` cookie.
          authorization: `Bearer ${session.sessionToken}`,
          cookie: this.cookieHeader(),
        },
        body: JSON.stringify({
          tenant: this.tenant,
          client_id: this.soarClientId,
          scopes: scope,
        }),
      })
    } catch (cause) {
      throw new SocAuthError(
        `SOC auth: the SOAR access exchange (${url}) failed (network error).`,
        { cause },
      )
    }

    if (res.status === 401 || res.status === 403) {
      // SOAR did not accept what we sent as the SOC session. Say exactly what
      // that was — cookie names, never values — and what SOAR answered, so a
      // failed attempt reports rather than guesses. Then force a fresh login.
      const held = Object.keys(this.cookieJar()).sort().join(', ') || 'none'
      const detail = await res.text().then(text => {
        try {
          const body = JSON.parse(text)
          return typeof body?.message === 'string' ? body.message : ''
        } catch {
          return ''
        }
      }).catch(() => '')
      this.invalidate()
      throw new SocAuthError(
        `SOC auth: SOAR rejected the SOC session (HTTP ${res.status}${detail ? `: ${detail}` : ''}); `
        + `cookies sent: [${held}]. Log in again with a new OTP.`,
      )
    }

    let payload: any
    try {
      payload = await res.json()
    } catch (cause) {
      throw new SocAuthError(
        `SOC auth: the SOAR access exchange returned a non-JSON body (HTTP ${res.status}) — likely blocked by the WAF or a malformed response.`,
        { cause },
      )
    }

    const token = payload?.access_token
    if (typeof token !== 'string' || token.length === 0) {
      throw new SocAuthError(
        `SOC auth: the SOAR access exchange returned no access_token (response keys: ${safeKeys(payload)}).`,
      )
    }

    const expiresIn = Number(payload?.expires_in ?? 3600)
    this.soarBearers.set(scope, {
      token,
      exp: this.now() + (Number.isFinite(expiresIn) ? expiresIn : 3600) * 1000,
    })
    return token
  }
}

/** List the response's key names, dropping anything that could hold a secret. */
function safeKeys(payload: unknown): string {
  if (!payload || typeof payload !== 'object') return 'none'
  const keys = Object.keys(payload as Record<string, unknown>).filter((k) => !SECRET_KEYS.has(k))
  return keys.length > 0 ? keys.join(', ') : 'none'
}
