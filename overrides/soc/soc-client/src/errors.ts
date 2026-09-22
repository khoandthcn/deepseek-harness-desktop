/**
 * SOC HTTP client error hierarchy.
 * Mirrors the semantics of socp-mcp's errors.py.
 */
export class SocError extends Error {
  /** Optional HTTP status associated with the error. */
  readonly status?: number | undefined
  /** Optional parsed/raw response body for diagnostics. */
  readonly body?: unknown | undefined

  constructor(message: string, opts?: { status?: number; body?: unknown; cause?: unknown }) {
    super(message, opts?.cause !== undefined ? { cause: opts.cause } : undefined)
    this.name = new.target.name
    this.status = opts?.status
    this.body = opts?.body
    Object.setPrototypeOf(this, new.target.prototype)
  }
}

/**
 * 401 / 403 — authentication or authorization failure reported by an upstream
 * SOC API.
 *
 * NOTE: `@deepseek-ai/dsh-soc-auth` exports a different class of the same name
 * for failures of the login flow itself. They are unrelated types, so an
 * `instanceof` check catches only the one whose module it imported. Match on
 * both, or on `SocError`, when you mean "the session is the problem".
 */
export class SocAuthError extends SocError {}

/** 404 — resource not found. */
export class SocNotFoundError extends SocError {}

/** 429 — rate limited by the upstream. */
export class SocRateLimitedError extends SocError {}

/** >= 500 or a network-level failure reaching the upstream. */
export class SocUpstreamError extends SocError {}

/** A success response whose body could not be parsed as JSON (e.g. a WAF HTML page). */
export class SocMalformedError extends SocError {}
