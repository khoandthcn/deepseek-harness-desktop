/**
 * `SocAuthService` — the single holder of SOC session state.
 *
 * It depends on no Cordis surface (only the HTTP client and the WSO2 flow next
 * to it), so it is unit-testable standalone; `index.ts` is the thin Cordis
 * wrapper that exposes an instance as `ctx.socAuth`.
 *
 * Responsibilities:
 *  - `login(otp)` drives the WSO2 single-shot flow (`runWso2Login`) and keeps the
 *    resulting SOC access token plus the session cookie jar.
 *  - One credential per system, each acquired lazily from that session and cached
 *    until it expires: SOAR Bearers per scope, the EDR access token, SIEM tokens
 *    per audience and scope, and the NSM session cookies.
 *
 * Secrets rule: the password and the OTP are never logged and never appear in a
 * thrown message.
 */

import { D1N_COOKIE, parseD1nBootstrap } from '@deepseek-ai/dsh-soc-client'
import { establishAppSession, establishSiemSession, runWso2Login, setCookiesOf, SiemRefusalError, SocAuthError, type FetchLike } from './wso2.ts'

/** Refresh a little before the real expiry, so an in-flight call cannot race it. */
const REFRESH_SKEW_MS = 60_000

/**
 * SIEM tokens carry an unknown lifetime (the observed capture 401'd before it
 * could show `expires_in`). When the token response omits it, cache for a short
 * default rather than forever, so a stale token is retried soon.
 */
const SIEM_DEFAULT_TTL_MS = 300_000

/**
 * SIEM login, exactly as its SPA does it: the login page's authorize asks for
 * audience `cym_api` with scope `login`, and the route guard redeems the code
 * with audience `cym_portal`. Only after that does the gatekeeper hand out
 * per-API codes; asking for an API audience first answers `invalid_request`.
 */
const SIEM_LOGIN_AUDIENCE = 'cym_api'
const SIEM_LOGIN_SCOPE = 'login'
const SIEM_PORTAL_AUDIENCE = 'cym_portal'

/**
 * NSM hands out no expiry: its session is a cookie jar whose CSRF token the
 * server retires on its own ("The CSRF token has expired"). Re-establish it
 * regularly rather than discovering the expiry through a failed search.
 */
const NSM_SESSION_TTL_MS = 900_000

/** The audience and scope of the gatekeeper's own management API (`/oauth/management/*`). */
export const SIEM_GATEKEEPER_AUDIENCE = 'gatekeeper'
export const SIEM_GATEKEEPER_SCOPE = 'login'

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
  /** SIEM management client id sent by probe tools. Defaults to `cym_api`. */
  siemMgmtClientId?: string | undefined
  /** Base URL of the NSM (NDR) API. Defaults to `https://nsm.example.com`. */
  nsmBaseUrl?: string | undefined
  /** NSM's registered OIDC client id. Defaults to `NSM`. */
  nsmClientId?: string | undefined
  /** NSM OIDC callback URL; defaults to `${nsmBaseUrl}/callback`. */
  nsmRedirectUri?: string | undefined
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
  /**
   * SIEM management client id. Public because the SIEM probe tool sends it as the
   * `client_id` of its permission check, so it is configured once, here.
   */
  readonly siemMgmtClientId: string
  /**
   * Base URL of the NSM API, without a trailing slash. Public because the NSM
   * tool plugin reads it from here, so endpoint and tools cannot drift apart.
   */
  readonly nsmBaseUrl: string
  private readonly nsmClientId: string
  private readonly nsmRedirectUri: string
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
   * The SIEM gatekeeper session: every cookie the login chain left (SSO, WAF and
   * `gatekeeper_session`). Per-API authorizations ride it. Null until logged in.
   */
  private siemJar: Record<string, string> | null = null
  /** De-duplicates concurrent SIEM logins. */
  private siemLoginInflight: Promise<Record<string, string>> | null = null
  /**
   * The NSM session: the cookies its `sso/login` set, the CSRF header those
   * cookies dictate, and when to establish it again. Null until signed in.
   */
  private nsmCred: { cookies: Record<string, string>, csrfHeader: string, csrfValue: string, exp: number } | null = null
  /** De-duplicates concurrent NSM sign-ins. */
  private nsmInflight: Promise<void> | null = null
  /** SIEM per-API credentials, keyed `audience/scope`, each cached until it expires. */
  private readonly siemCreds = new Map<string, { token: string, type: string, exp: number }>()
  /** De-duplicates concurrent acquisitions of one per-API token. */
  private readonly siemInflight = new Map<string, Promise<string>>()

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
    this.siemMgmtClientId = opts.siemMgmtClientId ?? 'cym_api'
    this.nsmBaseUrl = (opts.nsmBaseUrl ?? 'https://nsm.example.com').replace(/\/+$/, '')
    this.nsmClientId = opts.nsmClientId ?? 'NSM'
    this.nsmRedirectUri = opts.nsmRedirectUri ?? `${this.nsmBaseUrl}/callback`
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

  /**
   * The session's generation. Every credential exchange reads it when it starts
   * and again before it writes: an exchange that was in flight when the session
   * was dropped must not repopulate a credential behind it.
   */
  private generation = 0

  /**
   * Refuse a write from an exchange that outlived its session.
   * @param generation - the generation the exchange started in.
   * @throws when the session has been invalidated since.
   */
  private assertCurrent(generation: number): void {
    if (generation !== this.generation) {
      throw new SocAuthError(
        'SOC auth: the SOC session was logged out while this request was in flight — log in again with a new OTP.',
      )
    }
  }

  /** Forget the SOC session and any cached SOAR bearer. */
  invalidate(): void {
    this.generation += 1
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
    this.siemJar = null
    this.siemLoginInflight = null
    this.siemCreds.clear()
    this.siemInflight.clear()
    this.nsmCred = null
    this.nsmInflight = null
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

  /** Acquire the SOAR session once and reuse it for every scope exchange. */
  private async ensureSoarSession(
    doFetch: FetchLike,
  ): Promise<{ cookies: Record<string, string>, sessionToken: string }> {
    if (this.soarSession) return this.soarSession
    if (!this.sessionInflight) {
      const generation = this.generation
      this.sessionInflight = this.acquireSoarSession(doFetch)
        .then((session) => {
          this.assertCurrent(generation)
          this.soarSession = session
          this.soarCookies = session.cookies
          return session
        })
        .finally(() => { this.sessionInflight = null })
    }
    return this.sessionInflight
  }

  /**
   * Acquire the SOAR per-system session: run SOAR's own authorize on top of the
   * SSO login, exchange the returned code at `authen/callback` for a
   * `session_token`, and build the `token` cookie SOAR keys on. That cookie is
   * not a Set-Cookie — the SOAR SPA builds it in the browser as
   * `JSON.stringify({ token: session_token, id_token })`, so we build it the
   * same way here. The value is never logged.
   * @param doFetch - the fetch implementation to drive.
   * @returns the session token and the cookie jar to send on SOAR requests.
   */
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
   * Headers for an EDR request: the access token as a Bearer, plus the cookies
   * EDR also sets. The SPA's request layer sets `Authorization: Bearer <token>`
   * from the stored access token (`setAuthData`), while the `access_token`
   * cookie it writes alongside only tracks expiry — sending that cookie alone
   * reads as anonymous, which a live run confirmed (most endpoints answered 200
   * with nothing, and threat hunting answered 401).
   */
  edrAuthHeaders(): Record<string, string> {
    const headers: Record<string, string> = {}
    if (this.edrCred) headers.Authorization = `Bearer ${this.edrCred.token}`
    const cookie = Object.entries(this.edrCookies).map(([k, v]) => `${k}=${v}`).join('; ')
    if (cookie) headers.Cookie = cookie
    return headers
  }

  private async exchangeEdrToken(): Promise<string> {
    const generation = this.generation
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
      // EDR alone refused: drop only what EDR holds. Tearing the whole SOC
      // session down here would force a new OTP for SOAR, SIEM and NSM, which
      // may well still be working — an account not enabled on EDR reads the same.
      this.edrCred = null
      this.edrCookies = {}
      throw new SocAuthError(
        `SOC auth: EDR rejected the SOC session (HTTP ${res.status}${detail ? `: ${detail}` : ''}). `
        + 'The account may not be enabled on EDR; if the other systems fail too, log in again with a new OTP.',
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
    this.assertCurrent(generation)
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
   * The SIEM token for one API group, acquired lazily and cached per
   * `audience/scope` until `expires_in` (minus a 60s skew). SIEM has its own
   * OAuth server with one audience per API group, so a token is per API, as its
   * SPA's TokenManager keeps them. The first call logs in to SIEM (see
   * `ensureSiemLogin`). Defaults to the gatekeeper management API.
   */
  async siemToken(audience = SIEM_GATEKEEPER_AUDIENCE, scope = SIEM_GATEKEEPER_SCOPE): Promise<string> {
    if (!this.isAuthenticated()) {
      throw new SocAuthError(
        'SOC auth: not logged in — ask the user for their current OTP and call soc_login first.',
      )
    }
    const key = `${audience}/${scope}`
    const cached = this.siemCreds.get(key)
    if (cached && this.now() < cached.exp - REFRESH_SKEW_MS) {
      return cached.token
    }
    let inflight = this.siemInflight.get(key)
    if (!inflight) {
      inflight = this.exchangeSiemToken(audience, scope).finally(() => {
        this.siemInflight.delete(key)
      })
      this.siemInflight.set(key, inflight)
    }
    return inflight
  }

  /**
   * Headers for a SIEM API request: the per-API token as a Bearer (its SPA's
   * APIClient sends `Authorization: Bearer`), plus the WAF `D1N` cookie.
   */
  siemAuthHeaders(audience = SIEM_GATEKEEPER_AUDIENCE, scope = SIEM_GATEKEEPER_SCOPE): Record<string, string> {
    const headers: Record<string, string> = {}
    const cred = this.siemCreds.get(`${audience}/${scope}`)
    if (cred) headers.Authorization = `${cred.type} ${cred.token}`
    const d1n = this.siemJar?.[D1N_COOKIE] ?? this.cookies[D1N_COOKIE]
    if (d1n !== undefined) headers.Cookie = `${D1N_COOKIE}=${d1n}`
    return headers
  }

  /**
   * Log in to SIEM once per SOC session: authorize `cym_api`/`login` on the SSO
   * session, redeem the code with audience `cym_portal`, and keep the cookie
   * jar — the gatekeeper's session in it is what later per-API authorizations
   * are granted on.
   */
  private async ensureSiemLogin(doFetch: FetchLike): Promise<Record<string, string>> {
    if (this.siemJar) return this.siemJar
    if (!this.siemLoginInflight) {
      const generation = this.generation
      this.siemLoginInflight = (async () => {
        const { code, cookies } = await establishSiemSession({
          siemBaseUrl: this.siemBaseUrl,
          clientId: this.siemClientId,
          audience: SIEM_LOGIN_AUDIENCE,
          scope: SIEM_LOGIN_SCOPE,
          cookies: this.cookies,
          fetchImpl: this.fetchImpl,
        }).catch((error: unknown) => {
          if (error instanceof SiemRefusalError) {
            throw new SocAuthError(
              `SIEM auth: SIEM refused the login itself (${error.oauthError}) — the account may not be enabled on SIEM. ${error.message}`,
            )
          }
          throw error
        })
        const { jar } = await this.redeemSiemCode(doFetch, code, SIEM_PORTAL_AUDIENCE, cookies, 'login')
        this.assertCurrent(generation)
        this.siemJar = jar
        return jar
      })().finally(() => {
        this.siemLoginInflight = null
      })
    }
    return this.siemLoginInflight
  }

  private async exchangeSiemToken(audience: string, scope: string): Promise<string> {
    const generation = this.generation
    const doFetch: FetchLike = this.fetchImpl ?? ((input, init) => fetch(input, init))
    const jar = await this.ensureSiemLogin(doFetch)
    const { code, cookies } = await establishSiemSession({
      siemBaseUrl: this.siemBaseUrl,
      clientId: this.siemClientId,
      audience,
      scope,
      cookies: jar,
      fetchImpl: this.fetchImpl,
    }).catch((error: unknown) => {
      if (error instanceof SiemRefusalError) {
        throw new SocAuthError(
          `SIEM auth: SIEM denied scope "${scope}" on audience "${audience}" (${error.oauthError}) — `
          + 'the account most likely lacks that SIEM permission; siem_check_access lists what it has.',
        )
      }
      throw error
    })
    const { payload, jar: after } = await this.redeemSiemCode(doFetch, code, audience, cookies, `${audience}/${scope}`)
    this.assertCurrent(generation)
    this.siemJar = after
    const token = payload.access_token as string
    const type = typeof payload?.token_type === 'string' && payload.token_type.length > 0
      ? payload.token_type
      : 'Bearer'
    const expiresIn = Number(payload?.expires_in)
    const ttlMs = Number.isFinite(expiresIn) && expiresIn > 0 ? expiresIn * 1000 : SIEM_DEFAULT_TTL_MS
    this.siemCreds.set(`${audience}/${scope}`, { token, type, exp: this.now() + ttlMs })
    return token
  }

  /**
   * POST a SIEM authorization code to `/oauth/token` for `audience`, carrying the
   * chain's cookies, and return the parsed body (which must hold an
   * `access_token`) with the cookie jar to keep.
   */
  private async redeemSiemCode(
    doFetch: FetchLike,
    code: string,
    audience: string,
    cookies: Record<string, string>,
    what: string,
  ): Promise<{ payload: any, jar: Record<string, string> }> {
    const url = `${this.siemBaseUrl}/oauth/token`
    const body = new URLSearchParams({
      code,
      client_id: this.siemClientId,
      grant_type: 'authorization_code',
      redirect_uri: this.siemBaseUrl,
      audience,
    }).toString()
    // The token POST must carry the session cookies; a cookie-less request is
    // answered by the WAF's D1N bootstrap page (HTTP 200 HTML), not the token.
    // If that page comes back anyway, adopt its D1N and reissue once.
    let jar = { ...cookies }
    const post = async (afterBootstrap = false): Promise<Response> => {
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
        if (d1n !== undefined) {
          jar = { ...jar, [D1N_COOKIE]: d1n }
          return post(true)
        }
      }
      return response
    }
    const res = await post()
    jar = { ...jar, ...setCookiesOf(res) }

    if (res.status !== 200) {
      // Never echo the code or the body beyond a short `message` field.
      const message = await res.text().then((text) => {
        try {
          const parsed = JSON.parse(text)
          if (typeof parsed?.message === 'string') return parsed.message
          if (typeof parsed?.error === 'string') return parsed.error
          return ''
        } catch {
          return ''
        }
      }).catch(() => '')
      throw new SocAuthError(
        `SIEM auth: the SIEM token endpoint returned HTTP ${res.status}${message ? `: ${message}` : ''} (${what}).`,
      )
    }

    let payload: any
    try {
      payload = await res.json()
    } catch (cause) {
      throw new SocAuthError(
        `SOC auth: the SIEM token exchange returned a non-JSON body (HTTP ${res.status}) — likely blocked by the WAF or a malformed response (${what}).`,
        { cause },
      )
    }
    const token = payload?.access_token
    if (typeof token !== 'string' || token.length === 0) {
      throw new SocAuthError(
        `SOC auth: the SIEM token exchange returned no access token (${what}; response keys: ${safeKeys(payload)}).`,
      )
    }
    return { payload, jar }
  }

  /**
   * Ensure a live NSM session, establishing one on first use and again once the
   * previous one has aged out. Concurrent calls are de-duplicated. NSM signs in
   * with the SOC session rather than a token of its own: its SPA exchanges the
   * IAM code at the portal callback and posts the resulting session token to
   * NSM's `sso/login`, which answers with the session cookies.
   */
  async nsmSession(): Promise<void> {
    if (!this.isAuthenticated()) {
      throw new SocAuthError(
        'SOC auth: not logged in — ask the user for their current OTP and call soc_login first.',
      )
    }
    const cached = this.nsmCred
    if (cached && this.now() < cached.exp) return
    if (!this.nsmInflight) {
      this.nsmInflight = this.establishNsmSession().finally(() => {
        this.nsmInflight = null
      })
    }
    return this.nsmInflight
  }

  /**
   * Headers for an NSM request: the session cookies, plus the CSRF token echoed
   * into the header NSM names after the front end it served (`X-CSRFToken-MANAGER`).
   * Empty until `nsmSession()` has run.
   */
  nsmAuthHeaders(): Record<string, string> {
    const cred = this.nsmCred
    if (!cred) return {}
    const cookie = Object.entries(cred.cookies).map(([k, v]) => `${k}=${v}`).join('; ')
    const headers: Record<string, string> = { [cred.csrfHeader]: cred.csrfValue }
    if (cookie) headers.Cookie = cookie
    return headers
  }

  private async establishNsmSession(): Promise<void> {
    const generation = this.generation
    const doFetch: FetchLike = this.fetchImpl ?? ((input, init) => fetch(input, init))
    const { sessionToken, cookies } = await this.acquireSessionToken(doFetch, {
      system: 'NSM',
      clientId: this.nsmClientId,
      redirectUri: this.nsmRedirectUri,
      callbackUrl: `${this.iamUrl}/authen/callback`,
      scope: 'openid profile email read_user',
    })
    const url = `${this.nsmBaseUrl}/api/v1/sso/login/`
    // Carry the login jar: the WAF cookie rides here too, and a cookie-less
    // request is answered by its bootstrap page rather than by NSM.
    let jar: Record<string, string> = { ...cookies }
    const post = async (afterBootstrap = false): Promise<Response> => {
      const cookie = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ')
      let response: Response
      try {
        response = await doFetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
          body: JSON.stringify({ session_token: sessionToken }),
        })
      } catch (cause) {
        throw new SocAuthError(`SOC auth: the NSM sign-in (${url}) failed (network error).`, { cause })
      }
      if (!afterBootstrap && response.status === 200) {
        const d1n = parseD1nBootstrap(await response.clone().text())
        if (d1n !== undefined) {
          jar = { ...jar, [D1N_COOKIE]: d1n }
          return post(true)
        }
      }
      return response
    }
    const res = await post()
    if (res.status !== 200) {
      throw new SocAuthError(`SOC auth: the NSM sign-in (${url}) returned HTTP ${res.status}.`)
    }
    jar = { ...jar, ...setCookiesOf(res) }
    // NSM names the header after the front end it serves, and the cookie of that
    // same name holds the value: find it rather than hardcoding `MANAGER`.
    const csrf = Object.keys(jar).find((name) => /^x-csrftoken-/i.test(name))
    if (csrf === undefined) {
      throw new SocAuthError(
        'SOC auth: the NSM sign-in set no CSRF cookie, so its API would refuse every later request '
        + `(cookies held: [${Object.keys(jar).sort().join(', ')}]).`,
      )
    }
    this.assertCurrent(generation)
    this.nsmCred = {
      cookies: jar,
      csrfHeader: csrf,
      csrfValue: jar[csrf] as string,
      exp: this.now() + NSM_SESSION_TTL_MS,
    }
  }

  private async exchangeSoarBearer(scope: string): Promise<string> {
    const generation = this.generation
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
      // Only SOAR's own credentials go: see the EDR path above.
      this.soarSession = null
      this.soarCookies = {}
      this.soarBearers.clear()
      throw new SocAuthError(
        `SOC auth: SOAR rejected the SOC session (HTTP ${res.status}${detail ? `: ${detail}` : ''}); `
        + `cookies sent: [${held}]. If the other systems fail too, log in again with a new OTP.`,
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
    this.assertCurrent(generation)
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
