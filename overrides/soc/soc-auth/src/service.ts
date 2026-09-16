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

import { D1N_COOKIE, parseD1nBootstrap } from '@deepseek-ai/dsh-soc-client'
import { establishAppSession, establishSiemSession, runWso2Login, SocAuthError, type FetchLike } from './wso2.ts'

/** Refresh a little before the real expiry, so an in-flight call cannot race it. */
const REFRESH_SKEW_MS = 60_000

/**
 * SIEM tokens carry an unknown lifetime (the observed capture 401'd before it
 * could show `expires_in`). When the token response omits it, cache for a short
 * default rather than forever, so a stale token is retried soon.
 */
const SIEM_DEFAULT_TTL_MS = 300_000

/** Keys that must never be echoed back in an error message. */
const SECRET_KEYS = new Set(['access_token', 'refresh_token', 'id_token', 'token', 'accessToken'])

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
  /** Base URL of the EDR API, e.g. `https://edr.example`. Defaults to `https://edr.example.com`. */
  edrBaseUrl?: string | undefined
  /** EDR OAuth client id used by its authorize. Defaults to `EDR`. */
  edrClientId?: string | undefined
  /** EDR OIDC callback URL. Defaults to `${edrBaseUrl}/v2/callback`. */
  edrRedirectUri?: string | undefined
  /** Base URL of the SIEM API. Defaults to `https://siem.example.com`. */
  siemBaseUrl?: string | undefined
  /** SIEM OAuth client id used by its own authorize/token. Defaults to `cym_portal`. */
  siemClientId?: string | undefined
  /** SIEM OAuth audience. Defaults to `cym_dashboard_api`. */
  siemAudience?: string | undefined
  /** SIEM OAuth scope. Defaults to `read:db_dashboard`. */
  siemScope?: string | undefined
  /** SIEM management client id sent by probe tools. Defaults to `cym_api`. */
  siemMgmtClientId?: string | undefined
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
  /**
   * Base URL of the EDR API, without a trailing slash. Public because the EDR
   * tool plugin reads it from here, so endpoint and tools cannot drift apart.
   */
  readonly edrBaseUrl: string
  private readonly edrClientId: string
  private readonly edrRedirectUri: string
  /**
   * Base URL of the SIEM API, without a trailing slash. Public because the SIEM
   * tool plugin reads it from here, so endpoint and tools cannot drift apart.
   */
  readonly siemBaseUrl: string
  private readonly siemClientId: string
  private readonly siemAudience: string
  private readonly siemScope: string
  /**
   * SIEM management client id. Public because the SIEM probe tool sends it as the
   * `client_id` of its permission check, so it is configured once, here.
   */
  readonly siemMgmtClientId: string
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

  /**
   * The EDR credential, exchanged once and cached until it expires. Unlike SOAR
   * there is no per-scope map: one EDR token is global for every EDR endpoint.
   */
  private edrCred: { token: string, exp: number } | null = null
  /** De-duplicates concurrent EDR token exchanges. */
  private edrInflight: Promise<string> | null = null
  /** The cookie jar sent on EDR API calls: `access_token`, plus the WAF `D1N`. */
  private edrCookies: Record<string, string> = {}

  /**
   * The SIEM credential, acquired once and cached until it expires. The response
   * shape is unknown (the capture 401'd), so the token is parsed defensively.
   */
  private siemCred: { token: string, exp: number } | null = null
  /** De-duplicates concurrent SIEM token acquisitions. */
  private siemInflight: Promise<string> | null = null
  /** The token type from the SIEM token response; `Bearer` unless it says otherwise. */
  private siemTokenType = 'Bearer'
  /** Cookies to attach on SIEM API calls: the WAF `D1N` when present. */
  private siemCookies: Record<string, string> = {}

  constructor(opts: SocAuthServiceOptions) {
    this.iamUrl = opts.iamUrl.replace(/\/+$/, '')
    this.clientId = opts.clientId
    this.redirectUri = opts.redirectUri
    this.soarBaseUrl = opts.soarBaseUrl.replace(/\/+$/, '')
    this.tenant = opts.tenant ?? 'MASTER'
    this.soarClientId = opts.soarClientId ?? 'SOAR_CLIENT'
    this.soarRedirectUri = opts.soarRedirectUri ?? `${this.soarBaseUrl}/callback`
    this.soarAuthenUrl = (opts.soarAuthenUrl ?? `${this.soarBaseUrl}/authen`).replace(/\/+$/, '')
    this.edrBaseUrl = (opts.edrBaseUrl ?? 'https://edr.example.com').replace(/\/+$/, '')
    this.edrClientId = opts.edrClientId ?? 'EDR'
    this.edrRedirectUri = opts.edrRedirectUri ?? `${this.edrBaseUrl}/v2/callback`
    this.siemBaseUrl = (opts.siemBaseUrl ?? 'https://siem.example.com').replace(/\/+$/, '')
    this.siemClientId = opts.siemClientId ?? 'cym_portal'
    this.siemAudience = opts.siemAudience ?? 'cym_dashboard_api'
    this.siemScope = opts.siemScope ?? 'read:db_dashboard'
    this.siemMgmtClientId = opts.siemMgmtClientId ?? 'cym_api'
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
    this.edrCred = null
    this.edrInflight = null
    this.edrCookies = {}
    this.siemCred = null
    this.siemInflight = null
    this.siemTokenType = 'Bearer'
    this.siemCookies = {}
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
    const { sessionToken, idToken, cookies } = await this.acquireSessionToken(doFetch, {
      system: 'SOAR',
      clientId: this.soarClientId,
      redirectUri: this.soarRedirectUri,
      callbackUrl: `${this.soarAuthenUrl}/callback`,
    })
    const tokenValue: Record<string, string> = { token: sessionToken }
    if (idToken !== undefined) tokenValue.id_token = idToken
    const jar: Record<string, string> = { token: JSON.stringify(tokenValue) }
    if (cookies.D1N !== undefined) jar.D1N = cookies.D1N
    return { cookies: jar, sessionToken }
  }

  /**
   * Run a per-system OIDC authorize on top of the SSO login and exchange the
   * returned code at that system's `authen/callback` for a `session_token`
   * (a JWT — the SOC token). Shared by SOAR and EDR, which differ only in the
   * OIDC client, its callback host, and the authorize scope; SOAR posts to its
   * own host (`${soarBaseUrl}/authen/callback`), EDR to the IAM host
   * (`${iamUrl}/authen/callback`). The session token is never logged.
   * @returns the session token, the optional id_token, and the cookies
   *   collected during the authorize (the WAF `D1N`).
   */
  private async acquireSessionToken(
    doFetch: FetchLike,
    params: { system: string, clientId: string, redirectUri: string, callbackUrl: string, scope?: string },
  ): Promise<{ sessionToken: string, idToken: string | undefined, cookies: Record<string, string> }> {
    const { code, cookies } = await establishAppSession({
      iamUrl: this.iamUrl,
      clientId: params.clientId,
      redirectUri: params.redirectUri,
      scope: params.scope,
      cookies: this.cookies,
      fetchImpl: this.fetchImpl,
    })
    const cookieHeader = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ')
    let res: Response
    try {
      res = await doFetch(params.callbackUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(cookieHeader ? { cookie: cookieHeader } : {}) },
        body: JSON.stringify({ code, client_id: params.clientId }),
      })
    } catch (cause) {
      throw new SocAuthError(`SOC auth: the ${params.system} code exchange (${params.callbackUrl}) failed (network error).`, { cause })
    }
    if (res.status !== 200) {
      throw new SocAuthError(`SOC auth: the ${params.system} code exchange (${params.callbackUrl}) returned HTTP ${res.status}.`)
    }
    let payload: any
    try {
      payload = await res.json()
    } catch (cause) {
      throw new SocAuthError(`SOC auth: the ${params.system} code exchange returned a non-JSON body.`, { cause })
    }
    const sessionToken = payload?.session_token
    if (typeof sessionToken !== 'string' || sessionToken.length === 0) {
      throw new SocAuthError(
        `SOC auth: the ${params.system} code exchange returned no session_token (response keys: ${safeKeys(payload)}).`,
      )
    }
    const idToken = payload?.id_token
    return {
      sessionToken,
      idToken: typeof idToken === 'string' && idToken.length > 0 && idToken !== 'undefined' ? idToken : undefined,
      cookies,
    }
  }

  /**
   * The EDR access token, exchanged lazily and cached until `expired_in_seconds`
   * (minus a 60s skew). One token is global for every EDR endpoint (there is no
   * per-scope access step), and concurrent calls are de-duplicated.
   */
  async edrToken(): Promise<string> {
    if (!this.isAuthenticated()) {
      throw new SocAuthError(
        'SOC auth: not logged in — ask the user for their current OTP and call soc_login first.',
      )
    }
    const cached = this.edrCred
    if (cached && this.now() < cached.exp - REFRESH_SKEW_MS) {
      return cached.token
    }
    if (!this.edrInflight) {
      this.edrInflight = this.exchangeEdrToken().finally(() => {
        this.edrInflight = null
      })
    }
    return this.edrInflight
  }

  /**
   * Headers for an EDR request. The EDR SPA carries its credential as a cookie
   * named `access_token` (no Authorization header), so that is what we send,
   * plus the WAF `D1N` cookie when present. If a real run ever answers 401 with
   * this carrier, switch here to a Bearer header instead:
   *   `return { Authorization: \`Bearer ${this.edrCred?.token}\` }`
   */
  edrAuthHeaders(): Record<string, string> {
    const cookie = Object.entries(this.edrCookies).map(([k, v]) => `${k}=${v}`).join('; ')
    return cookie ? { Cookie: cookie } : {}
  }

  private async exchangeEdrToken(): Promise<string> {
    const doFetch: FetchLike = this.fetchImpl ?? ((input, init) => fetch(input, init))
    // EDR reuses the WSO2 SSO login; the session token is the SOC token it
    // exchanges for an EDR credential. Scope is EDR's own read scope.
    const { sessionToken, cookies } = await this.acquireSessionToken(doFetch, {
      system: 'EDR',
      clientId: this.edrClientId,
      redirectUri: this.edrRedirectUri,
      callbackUrl: `${this.iamUrl}/authen/callback`,
      scope: 'openid profile email read_user',
    })
    const url = `${this.edrBaseUrl}/authentication/GetAccessTokenBySocToken`
    let res: Response
    try {
      res = await doFetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ soc_token: sessionToken }),
      })
    } catch (cause) {
      throw new SocAuthError(`SOC auth: the EDR token exchange (${url}) failed (network error).`, { cause })
    }

    if (res.status === 401 || res.status === 403) {
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
        `SOC auth: EDR rejected the SOC session (HTTP ${res.status}${detail ? `: ${detail}` : ''}). Log in again with a new OTP.`,
      )
    }

    let payload: any
    try {
      payload = await res.json()
    } catch (cause) {
      throw new SocAuthError(
        `SOC auth: the EDR token exchange returned a non-JSON body (HTTP ${res.status}) — likely blocked by the WAF or a malformed response.`,
        { cause },
      )
    }

    const token = payload?.access_token
    if (typeof token !== 'string' || token.length === 0) {
      throw new SocAuthError(
        `SOC auth: the EDR token exchange returned no access_token (response keys: ${safeKeys(payload)}).`,
      )
    }

    const expiresIn = Number(payload?.expired_in_seconds ?? 3600)
    this.edrCred = {
      token,
      exp: this.now() + (Number.isFinite(expiresIn) ? expiresIn : 3600) * 1000,
    }
    // The EDR SPA stores the credential as a `access_token` cookie (path=/) and
    // sends no Authorization header; carry the WAF `D1N` alongside it if present.
    const jar: Record<string, string> = { access_token: token }
    if (cookies.D1N !== undefined) jar.D1N = cookies.D1N
    this.edrCookies = jar
    return token
  }

  /**
   * The SIEM access token, acquired lazily and cached until `expires_in` (minus
   * a 60s skew) or, when the response omits it, a short default. Concurrent calls
   * are de-duplicated. Best-effort: the success response shape is unknown, so the
   * token is parsed defensively and every failure throws a precise message.
   */
  async siemToken(): Promise<string> {
    if (!this.isAuthenticated()) {
      throw new SocAuthError(
        'SOC auth: not logged in — ask the user for their current OTP and call soc_login first.',
      )
    }
    const cached = this.siemCred
    if (cached && this.now() < cached.exp - REFRESH_SKEW_MS) {
      return cached.token
    }
    if (!this.siemInflight) {
      this.siemInflight = this.exchangeSiemToken().finally(() => {
        this.siemInflight = null
      })
    }
    return this.siemInflight
  }

  /**
   * Headers for a SIEM request. The credential carrier is UNKNOWN — the observed
   * capture 401'd before it could show one. SIEM's audience is a dashboard API
   * and its SPA is an OAuth client, so we DEFAULT to a Bearer header. If a live
   * test 401s with this carrier, the alternative to try is a cookie (carry the
   * token in a cookie the SPA would set) — switch it here. The WAF `D1N` cookie
   * is attached when present.
   */
  siemAuthHeaders(): Record<string, string> {
    const headers: Record<string, string> = {}
    const token = this.siemCred?.token
    if (token) headers.Authorization = `${this.siemTokenType} ${token}`
    const cookie = Object.entries(this.siemCookies).map(([k, v]) => `${k}=${v}`).join('; ')
    if (cookie) headers.Cookie = cookie
    return headers
  }

  private async exchangeSiemToken(): Promise<string> {
    const doFetch: FetchLike = this.fetchImpl ?? ((input, init) => fetch(input, init))
    // SIEM has its OWN OAuth server: run its authorize on the SSO login for a
    // code, then exchange the code at its token endpoint.
    const { code, cookies } = await establishSiemSession({
      siemBaseUrl: this.siemBaseUrl,
      clientId: this.siemClientId,
      audience: this.siemAudience,
      scope: this.siemScope,
      cookies: this.cookies,
      fetchImpl: this.fetchImpl,
    })
    const url = `${this.siemBaseUrl}/oauth/token`
    const body = new URLSearchParams({
      code,
      client_id: this.siemClientId,
      grant_type: 'authorization_code',
      redirect_uri: this.siemBaseUrl,
      audience: this.siemAudience,
    }).toString()
    // The token POST must carry the session cookies (commonAuthId, D1N) from the
    // authorize step; a cookie-less request is answered by the WAF's D1N
    // bootstrap page (HTTP 200 HTML), not the token. If that page comes back
    // anyway, adopt its D1N and reissue once.
    const post = async (jar: Record<string, string>, afterBootstrap = false): Promise<Response> => {
      const cookie = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ')
      let response: Response
      try {
        response = await doFetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', ...(cookie ? { cookie } : {}) },
          body,
        })
      } catch (cause) {
        throw new SocAuthError(`SOC auth: the SIEM token exchange (${url}) failed (network error).`, { cause })
      }
      if (!afterBootstrap && response.status === 200) {
        const d1n = parseD1nBootstrap(await response.clone().text())
        if (d1n !== undefined) return post({ ...jar, [D1N_COOKIE]: d1n }, true)
      }
      return response
    }
    const res = await post(cookies)

    if (res.status !== 200) {
      // Never echo the code or the body beyond a short `message` field.
      const message = await res.text().then((text) => {
        try {
          const body = JSON.parse(text)
          if (typeof body?.message === 'string') return body.message
          if (typeof body?.error === 'string') return body.error
          return ''
        } catch {
          return ''
        }
      }).catch(() => '')
      throw new SocAuthError(
        `SIEM auth: the SIEM token endpoint returned HTTP ${res.status}${message ? `: ${message}` : ''}`,
      )
    }

    let payload: any
    try {
      payload = await res.json()
    } catch (cause) {
      throw new SocAuthError(
        `SOC auth: the SIEM token exchange returned a non-JSON body (HTTP ${res.status}) — likely blocked by the WAF or a malformed response.`,
        { cause },
      )
    }

    // Success shape unknown: accept the token under any of the plausible keys.
    const token = payload?.access_token ?? payload?.token ?? payload?.accessToken
    if (typeof token !== 'string' || token.length === 0) {
      throw new SocAuthError(
        `SOC auth: the SIEM token exchange returned no access token (response keys: ${safeKeys(payload)}).`,
      )
    }

    this.siemTokenType = typeof payload?.token_type === 'string' && payload.token_type.length > 0
      ? payload.token_type
      : 'Bearer'
    const expiresIn = Number(payload?.expires_in)
    const ttlMs = Number.isFinite(expiresIn) && expiresIn > 0 ? expiresIn * 1000 : SIEM_DEFAULT_TTL_MS
    this.siemCred = { token, exp: this.now() + ttlMs }
    const jar: Record<string, string> = {}
    if (cookies.D1N !== undefined) jar.D1N = cookies.D1N
    this.siemCookies = jar
    return token
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
