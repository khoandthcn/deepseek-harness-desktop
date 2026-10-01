/**
 * Why a request never got an answer, in words a user can act on.
 *
 * `fetch` reports every transport failure as "fetch failed" and keeps the
 * reason — no such host, no route, a certificate nobody vouches for — in a
 * nested `cause`. On a network that reaches the platform through a proxy, or
 * that inspects TLS with its own certificate authority, that reason is the
 * whole diagnosis, so it is dug out and named here rather than dropped.
 */

/** What kind of failure a transport error was. */
export type NetworkFailureKind = 'dns' | 'connect' | 'certificate' | 'proxy' | 'reset' | 'timeout' | 'unknown'

/** A transport failure, classified. */
export interface NetworkFailure {
  kind: NetworkFailureKind
  /** The system's own code for it, e.g. `ENOTFOUND`; empty when it gave none. */
  code: string
  /** What happened and what to do about it. Carries no URL and no credential. */
  message: string
}

const DNS_CODES = new Set(['ENOTFOUND', 'EAI_AGAIN', 'EAI_NODATA', 'EAI_NONAME'])
const CONNECT_CODES = new Set(['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'EHOSTDOWN', 'ENETDOWN', 'EACCES'])
const TIMEOUT_CODES = new Set(['ETIMEDOUT', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT', 'ABORT_ERR', 'TimeoutError'])
const RESET_CODES = new Set(['ECONNRESET', 'EPIPE', 'UND_ERR_SOCKET'])
const CERTIFICATE_CODES = new Set([
  'SELF_SIGNED_CERT_IN_CHAIN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_UNTRUSTED',
  'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_SIGNATURE_FAILURE',
])

/** Where the proxy and the trusted authorities are set, said once. */
const WHERE = 'in the environment the application starts with, or in the `.env` file of the Harness home (`~/.dsh/.env`)'

/**
 * Every error in a failure, outermost first: the `cause` chain, and the
 * members of an aggregate (a dual-stack connect reports one error per address).
 */
function chain(error: unknown): { code: string; message: string }[] {
  const out: { code: string; message: string }[] = []
  const seen = new Set<unknown>()
  const visit = (node: unknown): void => {
    if (node === null || typeof node !== 'object' || seen.has(node) || out.length > 12) return
    seen.add(node)
    const record = node as { code?: unknown; name?: unknown; message?: unknown; cause?: unknown; errors?: unknown }
    const code = typeof record.code === 'string' ? record.code
      : record.name === 'TimeoutError' ? 'TimeoutError' : ''
    out.push({ code, message: typeof record.message === 'string' ? record.message : '' })
    if (Array.isArray(record.errors)) for (const member of record.errors) visit(member)
    visit(record.cause)
  }
  visit(error)
  return out
}

/**
 * Whether this process sends its requests through a proxy. The launcher
 * publishes the policy it resolved through these variables, so they say what
 * is in effect whichever layer supplied it.
 * @param env - the process environment.
 * @returns true when a proxy is set for `https:` requests.
 */
export function proxyConfigured(env: Record<string, string | undefined> = process.env): boolean {
  return ['https_proxy', 'HTTPS_PROXY', 'http_proxy', 'HTTP_PROXY', 'all_proxy', 'ALL_PROXY']
    .some(name => (env[name] ?? '').trim() !== '')
}

/**
 * Classify a transport failure and say what to do about it.
 * @param error - what `fetch` threw.
 * @param env - the process environment, read for whether a proxy is set.
 * @returns the failure, with a message that names the cause and the remedy.
 */
export function diagnoseNetworkFailure(
  error: unknown,
  env: Record<string, string | undefined> = process.env,
): NetworkFailure {
  const errors = chain(error)
  const proxied = proxyConfigured(env)
  const find = (codes: Set<string>) => errors.find(entry => codes.has(entry.code))
  const viaProxy = proxied ? 'A proxy is configured, so the request went to it.' : 'No proxy is configured, so the request went direct.'

  // A proxy that answers the CONNECT with anything but 200 says so in words.
  const refused = errors.map(entry => /Proxy response \((\d{3})\)/.exec(entry.message)).find(Boolean)
  if (refused) {
    const status = refused[1]
    return {
      kind: 'proxy',
      code: `PROXY_${status}`,
      message: `the proxy refused the connection with status ${status}. `
        + (status === '407'
          ? `It wants credentials: write them into the proxy URL (http://user:password@host:port) ${WHERE}.`
          : 'It does not allow this destination; ask the network administrator to permit it, or use a network that reaches it.'),
    }
  }
  const certificate = find(CERTIFICATE_CODES)
  if (certificate) {
    return {
      kind: 'certificate',
      code: certificate.code,
      message: `the server's TLS certificate is not trusted (${certificate.code}). A network that inspects TLS re-signs `
        + 'traffic with its own certificate authority. Install that authority in the operating system\'s trust store — the '
        + `application trusts that store — or name its PEM file in NODE_EXTRA_CA_CERTS ${WHERE}, then restart the application.`,
    }
  }
  const dns = find(DNS_CODES)
  if (dns) {
    return {
      kind: 'dns',
      code: dns.code,
      message: `the host name did not resolve (${dns.code}). ${viaProxy} `
        + (proxied
          ? 'The name that failed is then the proxy\'s own, or the host is on the bypass list (NO_PROXY) and unknown to this network\'s DNS.'
          : 'A network that reaches outside hosts only through a proxy does not resolve their names itself: set HTTPS_PROXY '
            + `(http://host:port) ${WHERE}, and list internal domains in NO_PROXY. A browser may work regardless, because it `
            + 'reads the system\'s proxy auto-configuration and this application does not.'),
    }
  }
  const timeout = find(TIMEOUT_CODES)
  const connect = find(CONNECT_CODES)
  if (connect ?? timeout) {
    const entry = (connect ?? timeout)!
    return {
      kind: connect ? 'connect' : 'timeout',
      code: entry.code,
      message: `no connection could be made (${entry.code}). ${viaProxy} `
        + (proxied
          ? 'If the host is internal to this network, add its domain to NO_PROXY so it is reached direct; otherwise the proxy cannot reach it.'
          : `If this network reaches that host only through a proxy, set HTTPS_PROXY (http://host:port) ${WHERE}.`),
    }
  }
  const reset = find(RESET_CODES)
  if (reset) {
    return {
      kind: 'reset',
      code: reset.code,
      message: `the connection was closed before an answer arrived (${reset.code}). ${viaProxy} `
        + 'A filtering device on the path usually does this; ask whether the destination is allowed.',
    }
  }
  const innermost = [...errors].reverse().find(entry => entry.message !== '')
  return {
    kind: 'unknown',
    code: errors.find(entry => entry.code !== '')?.code ?? '',
    message: `${innermost?.message ?? 'the request failed without a reason'}. ${viaProxy}`,
  }
}

/**
 * The one-line form, for the tail of an error message.
 * @param error - what `fetch` threw.
 * @returns the cause and the remedy.
 */
export function describeNetworkFailure(error: unknown): string {
  return diagnoseNetworkFailure(error).message
}
