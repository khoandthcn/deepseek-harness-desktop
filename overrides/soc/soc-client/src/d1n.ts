/**
 * The WAF in front of the SOC hosts does not hand out its `D1N` cookie in a
 * `Set-Cookie` header. A client that lacks the cookie gets HTTP 200 and a
 * one-line page whose script writes the cookie and reloads:
 *
 *     <script>document.cookie="D1N=<hex>; expires=...; path=/";window.location.reload(true);</script>
 *
 * A browser never notices. A fetch client sees this page instead of the
 * response it asked for — for the WSO2 flow that means no `sessionDataKey`,
 * so a login fails at step 1 with credentials that were never even sent.
 * Recognize the page so a caller can adopt the cookie and reissue the request.
 */

export const D1N_COOKIE = 'D1N'

/** The bootstrap page is ~200 bytes; anything larger is a real response. */
const BOOTSTRAP_MAX_BYTES = 2048
const BOOTSTRAP = /document\.cookie\s*=\s*"D1N=([0-9A-Za-z]+)"[\s\S]{0,200}?window\.location\.reload/

/**
 * Extract the `D1N` value from a WAF bootstrap page.
 * @param body - a response body.
 * @returns the cookie value, or `undefined` when the body is anything else.
 */
export function parseD1nBootstrap(body: string): string | undefined {
  if (body.length > BOOTSTRAP_MAX_BYTES) return undefined
  return BOOTSTRAP.exec(body)?.[1]
}
