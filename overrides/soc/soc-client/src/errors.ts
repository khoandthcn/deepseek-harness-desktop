/**
 * SOC HTTP client error hierarchy.
 * Mirrors the semantics of socp-mcp's errors.py.
 */
export class SocError extends Error {
  /** Optional HTTP status associated with the error. */
  readonly status?: number
  /** Optional parsed/raw response body for diagnostics. */
  readonly body?: unknown

  constructor(message: string, opts?: { status?: number; body?: unknown; cause?: unknown }) {
    super(message, opts?.cause !== undefined ? { cause: opts.cause } : undefined)
    this.name = new.target.name
    this.status = opts?.status
    this.body = opts?.body
    Object.setPrototypeOf(this, new.target.prototype)
  }
}

/** 401 / 403 — authentication or authorization failure. */
export class SocAuthError extends SocError {}

/** 404 — resource not found. */
export class SocNotFoundError extends SocError {}

/** 429 — rate limited by the upstream. */
export class SocRateLimitedError extends SocError {}

/** >= 500 or a network-level failure reaching the upstream. */
export class SocUpstreamError extends SocError {}

/** A success response whose body could not be parsed as JSON (e.g. a WAF HTML page). */
export class SocMalformedError extends SocError {}
