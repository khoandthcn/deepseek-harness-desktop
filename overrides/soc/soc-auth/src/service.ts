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

import { runWso2Login, SocAuthError, type FetchLike } from './wso2.ts'

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
  /** SOAR OAuth client id used by the access exchange. */
  soarClientId?: string | undefined
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
  private readonly credentials: () => Promise<{ username: string, password: string }>
  private readonly fetchImpl?: FetchLike | undefined
  private readonly now: () => number

  /** SOC session state, set by `login()` and cleared when it is invalidated. */
  private socToken: string | null = null
  private cookies: Record<string, string> = {}

  /** SOAR bearer cache. */
  private soarToken: string | null = null
  private soarExpiresAt = 0
  /** De-duplicates concurrent `soarBearer()` calls into one exchange. */
  private inflight: Promise<string> | null = null

  constructor(opts: SocAuthServiceOptions) {
    this.iamUrl = opts.iamUrl.replace(/\/+$/, '')
    this.clientId = opts.clientId
    this.redirectUri = opts.redirectUri
    this.soarBaseUrl = opts.soarBaseUrl.replace(/\/+$/, '')
    this.tenant = opts.tenant ?? 'MASTER'
    this.soarClientId = opts.soarClientId ?? 'SOAR_CLIENT'
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
    this.soarToken = null
    this.soarExpiresAt = 0
    this.inflight = null
  }

  /**
   * The SOAR Bearer for this session, exchanged lazily and cached until
   * `expires_in` (minus a 60s skew).
   */
  async soarBearer(): Promise<string> {
    if (!this.isAuthenticated()) {
      throw new SocAuthError(
        'SOC auth: not logged in — ask the user for their current OTP and call soc_login first.',
      )
    }
    if (this.soarToken && this.now() < this.soarExpiresAt - REFRESH_SKEW_MS) {
      return this.soarToken
    }
    if (!this.inflight) {
      this.inflight = this.exchangeSoarBearer().finally(() => {
        this.inflight = null
      })
    }
    return this.inflight
  }

  /**
   * Headers for a SOAR request: the cached Bearer (when one has been fetched)
   * plus the session cookies, including the WAF `D1N` cookie when present.
   */
  authHeadersForSoar(): Record<string, string> {
    const headers: Record<string, string> = {}
    if (this.soarToken) headers.Authorization = `Bearer ${this.soarToken}`
    headers.Cookie = this.cookieHeader()
    return headers
  }

  /**
   * The session cookies as a `Cookie` header. SOAR identifies the SOC session by
   * a cookie named `token`; when WSO2 did not set one we supply the SOC access
   * token under that name, matching the Python reference implementation.
   */
  private cookieHeader(): string {
    const jar: Record<string, string> = { ...this.cookies }
    if (!jar.token && this.socToken) jar.token = this.socToken
    return Object.entries(jar)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ')
  }

  private async exchangeSoarBearer(): Promise<string> {
    const doFetch: FetchLike = this.fetchImpl ?? ((input, init) => fetch(input, init))
    const url = `${this.soarBaseUrl}/access_control/access`
    let res: Response
    try {
      res = await doFetch(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          cookie: this.cookieHeader(),
        },
        body: JSON.stringify({
          tenant: this.tenant,
          client_id: this.soarClientId,
          scopes: '',
        }),
      })
    } catch (cause) {
      throw new SocAuthError(
        `SOC auth: the SOAR access exchange (${url}) failed (network error).`,
        { cause },
      )
    }

    if (res.status === 401 || res.status === 403) {
      // The SOC session no longer authenticates: force a fresh login.
      this.invalidate()
      throw new SocAuthError(
        `SOC auth: SOAR rejected the SOC session (HTTP ${res.status}) — the session expired, log in again with a new OTP.`,
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
    this.soarToken = token
    this.soarExpiresAt = this.now() + (Number.isFinite(expiresIn) ? expiresIn : 3600) * 1000
    return token
  }
}

/** List the response's key names, dropping anything that could hold a secret. */
function safeKeys(payload: unknown): string {
  if (!payload || typeof payload !== 'object') return 'none'
  const keys = Object.keys(payload as Record<string, unknown>).filter((k) => !SECRET_KEYS.has(k))
  return keys.length > 0 ? keys.join(', ') : 'none'
}
