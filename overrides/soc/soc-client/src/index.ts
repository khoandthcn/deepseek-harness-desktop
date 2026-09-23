import {
  SocAuthError,
  SocMalformedError,
  SocNotFoundError,
  SocRateLimitedError,
  SocUpstreamError,
} from './errors.ts'

export * from './errors.ts'
export * from './d1n.ts'
import { parseD1nBootstrap } from './d1n.ts'

export interface SocHttpOptions {
  /** Injectable fetch implementation (defaults to the global `fetch`). */
  fetchImpl?: typeof fetch | undefined
  /** Hook returning extra headers to merge into each request (e.g. Authorization). */
  authHeaders?: (() => Record<string, string>) | undefined
  /** WAF `D1N` cookie value; when set, attached as `Cookie: D1N=...`. */
  d1nCookie?: string | undefined
}

/**
 * Minimal fetch-based JSON HTTP client for SOC upstreams.
 *
 * Mirrors socp-mcp's client.py: always sends/expects JSON, merges auth headers,
 * attaches the WAF `D1N` cookie, and maps upstream status codes to the SocError
 * hierarchy. Network-level failures are wrapped as SocUpstreamError.
 */
export class SocHttp {
  /**
   * Resolved per request, not at construction: the deployment's endpoints can
   * be edited in Settings while the app runs, and a client that captured the
   * old value would keep talking to it.
   */
  private readonly resolveBaseUrl: () => string
  private readonly fetchImpl: typeof fetch
  private readonly authHeaders?: (() => Record<string, string>) | undefined
  /** Mutable: the WAF may hand it to us mid-flight, see `d1n.ts`. */
  private d1nCookie?: string | undefined

  constructor(baseUrl: string | (() => string), opts: SocHttpOptions = {}) {
    this.resolveBaseUrl = typeof baseUrl === 'function'
      ? () => baseUrl().replace(/\/+$/, '')
      : () => baseUrl.replace(/\/+$/, '')
    this.fetchImpl = opts.fetchImpl ?? fetch
    this.authHeaders = opts.authHeaders
    this.d1nCookie = opts.d1nCookie
  }

  async postJson<T = unknown>(path: string, body: unknown): Promise<T> {
    return this.request<T>('POST', path, body)
  }

  async getJson<T = unknown>(path: string): Promise<T> {
    return this.request<T>('GET', path)
  }

  private buildHeaders(hasBody: boolean): Record<string, string> {
    const headers: Record<string, string> = {
      accept: 'application/json',
    }
    if (hasBody) headers['content-type'] = 'application/json'
    if (this.authHeaders) Object.assign(headers, this.authHeaders())
    if (this.d1nCookie) {
      // The auth headers carry the session as `Cookie`; a second key differing
      // only in case reaches `fetch` as a comma-joined pair, which is not cookie
      // syntax and loses the session. Merge into the one header instead.
      const existingKey = Object.keys(headers).find(key => key.toLowerCase() === 'cookie')
      const existing = existingKey === undefined ? '' : headers[existingKey] ?? ''
      if (existingKey !== undefined) delete headers[existingKey]
      const pair = `D1N=${this.d1nCookie}`
      headers['cookie'] = existing === '' ? pair
        : /(^|;\s*)D1N=/.test(existing) ? existing
          : `${existing}; ${pair}`
    }
    return headers
  }

  private async request<T>(method: string, path: string, body?: unknown, afterBootstrap = false): Promise<T> {
    const url = `${this.resolveBaseUrl()}${path.startsWith('/') ? path : `/${path}`}`
    const hasBody = body !== undefined
    const init: RequestInit & { headers: Record<string, string>; body?: string } = {
      method,
      headers: this.buildHeaders(hasBody),
    }
    if (hasBody) init.body = JSON.stringify(body)

    let res: Response
    try {
      res = await this.fetchImpl(url, init)
    } catch (err) {
      throw new SocUpstreamError(`Network error reaching ${url}`, { cause: err })
    }

    const text = await res.text()

    // Not the response we asked for but the WAF's cookie bootstrap: adopt the
    // cookie and reissue, once. A second bootstrap means the cookie was refused.
    const d1n = parseD1nBootstrap(text)
    if (d1n !== undefined && !afterBootstrap) {
      this.d1nCookie = d1n
      return this.request<T>(method, path, body, true)
    }

    if (!res.ok) {
      const parsed = safeJson(text)
      const detail = `${method} ${path} failed with ${res.status}`
      if (res.status === 401 || res.status === 403) {
        throw new SocAuthError(detail, { status: res.status, body: parsed ?? text })
      }
      if (res.status === 404) {
        throw new SocNotFoundError(detail, { status: res.status, body: parsed ?? text })
      }
      if (res.status === 429) {
        throw new SocRateLimitedError(detail, { status: res.status, body: parsed ?? text })
      }
      if (res.status >= 500) {
        throw new SocUpstreamError(detail, { status: res.status, body: parsed ?? text })
      }
      throw new SocUpstreamError(detail, { status: res.status, body: parsed ?? text })
    }

    const parsed = safeJson(text)
    if (parsed === undefined) {
      throw new SocMalformedError(
        `${method} ${path} returned a non-JSON body`,
        { status: res.status, body: text },
      )
    }
    return parsed as T
  }
}

/** Parse JSON, returning `undefined` when the text is not valid JSON. */
function safeJson(text: string): unknown {
  if (text.trim() === '') return undefined
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}
