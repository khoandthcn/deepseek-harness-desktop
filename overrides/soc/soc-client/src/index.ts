import {
  SocAuthError,
  SocMalformedError,
  SocNotFoundError,
  SocRateLimitedError,
  SocUpstreamError,
} from './errors.ts'

export * from './errors.ts'

export interface SocHttpOptions {
  /** Injectable fetch implementation (defaults to the global `fetch`). */
  fetchImpl?: typeof fetch
  /** Hook returning extra headers to merge into each request (e.g. Authorization). */
  authHeaders?: () => Record<string, string>
  /** WAF `D1N` cookie value; when set, attached as `Cookie: D1N=...`. */
  d1nCookie?: string
}

/**
 * Minimal fetch-based JSON HTTP client for SOC upstreams.
 *
 * Mirrors socp-mcp's client.py: always sends/expects JSON, merges auth headers,
 * attaches the WAF `D1N` cookie, and maps upstream status codes to the SocError
 * hierarchy. Network-level failures are wrapped as SocUpstreamError.
 */
export class SocHttp {
  private readonly baseUrl: string
  private readonly fetchImpl: typeof fetch
  private readonly authHeaders?: () => Record<string, string>
  private readonly d1nCookie?: string

  constructor(baseUrl: string, opts: SocHttpOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, '')
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
    if (this.d1nCookie) headers['cookie'] = `D1N=${this.d1nCookie}`
    return headers
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = `${this.baseUrl}${path.startsWith('/') ? path : `/${path}`}`
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
