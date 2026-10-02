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

/** Where the proxy is set, said once. */
const WHERE = 'in the `.env` file of the Harness home (`~/.dsh/.env`), or in the environment the application starts with'

/** Where a certificate authority the machine should trust goes. */
const CA_WHERE = 'copy that authority\'s certificate (.pem, .crt or .cer) into the `certs` folder of the Harness home (`~/.dsh/certs`)'

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

/** How one request leaves this machine. */
export interface NetworkRoute {
  /** True when the request goes to the proxy. */
  proxied: boolean
  /** The proxy, without any credential in it; absent when direct. */
  proxy?: string
  /** The bypass entry that sent this host direct although a proxy is set. */
  bypassedBy?: string
}

const env = (values: Record<string, string | undefined>, ...names: string[]): string =>
  names.map(name => (values[name] ?? '').trim()).find(value => value !== '') ?? ''

/** A proxy URL fit to show: a proxy that needs a login carries it in the URL. */
export function withoutCredentials(value: string): string {
  try {
    const url = new URL(value)
    url.username = ''
    url.password = ''
    return url.toString().replace(/\/$/, '')
  } catch {
    return '(set, but not a URL)'
  }
}

/**
 * The bypass entry a host matches, read the way the launcher's proxy policy
 * reads it: an entry names a host and every subdomain under it, a leading `.`
 * or `*.` means the same, an entry may carry `:port`, and `*` matches all.
 * @returns the entry as written, or undefined when the host is not bypassed.
 */
export function bypassEntryFor(host: string, port: string, noProxy: string): string | undefined {
  const name = host.toLowerCase().replace(/^\[|\]$/g, '')
  for (const raw of noProxy.split(/[\s,]+/)) {
    const entry = raw.trim()
    if (entry === '') continue
    if (entry === '*') return entry
    const match = /^(?:\*?\.)?(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(entry.toLowerCase())
    if (!match) continue
    const [, entryHost, entryPort] = match
    const bare = entryHost!.replace(/^\[|\]$/g, '')
    if (entryPort !== undefined && entryPort !== port) continue
    if (name === bare || name.endsWith(`.${bare}`)) return entry
  }
  return undefined
}

/**
 * Whether a request to this URL goes through the proxy, as the policy the
 * launcher installed decides it. The launcher publishes the policy it resolved
 * through these variables, so they hold what is in effect.
 * @param url - the request URL.
 * @param values - the process environment.
 */
export function routeFor(url: string, values: Record<string, string | undefined> = process.env): NetworkRoute {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return { proxied: false }
  }
  const https = parsed.protocol === 'https:'
  const proxy = https
    ? env(values, 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY', 'http_proxy', 'HTTP_PROXY')
    : env(values, 'http_proxy', 'HTTP_PROXY', 'all_proxy', 'ALL_PROXY')
  if (proxy === '') return { proxied: false }
  const port = parsed.port || (https ? '443' : '80')
  const loopback = /^(localhost|127(\.\d+){3}|\[::1\]|0\.0\.0\.0)$/i.test(parsed.hostname)
  const bypassedBy = loopback ? 'localhost' : bypassEntryFor(parsed.hostname, port, env(values, 'no_proxy', 'NO_PROXY'))
  if (bypassedBy !== undefined) return { proxied: false, proxy: withoutCredentials(proxy), bypassedBy }
  return { proxied: true, proxy: withoutCredentials(proxy) }
}

/**
 * Classify a transport failure and say what to do about it.
 * @param error - what `fetch` threw.
 * @param env - the process environment, read for the proxy in effect.
 * @param url - the request URL, when known: it decides whether this host went
 *   to the proxy or was sent direct by the bypass list.
 * @returns the failure, with a message that names the cause and the remedy.
 */
export function diagnoseNetworkFailure(
  error: unknown,
  env: Record<string, string | undefined> = process.env,
  url?: string,
): NetworkFailure {
  const errors = chain(error)
  const route = url === undefined ? undefined : routeFor(url, env)
  const bypassed = route?.bypassedBy
  const proxied = route === undefined ? proxyConfigured(env) : route.proxied
  const find = (codes: Set<string>) => errors.find(entry => codes.has(entry.code))
  const viaProxy = bypassed !== undefined
    ? `A proxy is configured, but this host matches "${bypassed}" in NO_PROXY, so the request went direct.`
    : proxied ? 'A proxy is configured, so the request went to it.' : 'No proxy is configured, so the request went direct.'

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
  if (certificate?.code === 'ERR_TLS_CERT_ALTNAME_INVALID') {
    return {
      kind: 'certificate',
      code: certificate.code,
      message: 'the server presented a certificate for a different host name (ERR_TLS_CERT_ALTNAME_INVALID). '
        + 'The configured address does not match the server, or a device on the path answered in its place: '
        + 'check the platform domain, and open the address in a browser to see whose certificate it shows.',
    }
  }
  if (certificate) {
    return {
      kind: 'certificate',
      code: certificate.code,
      message: `the server's TLS certificate is not trusted (${certificate.code}). A network that inspects TLS re-signs `
        + 'traffic with its own certificate authority. The application trusts the operating system\'s store, so either '
        + `install that authority there or ${CA_WHERE}, then restart the application.`
        + (certificate.code === 'CERT_HAS_EXPIRED' ? ' An expired certificate can also be the server\'s own: check the date in a browser.' : ''),
    }
  }
  const dns = find(DNS_CODES)
  if (dns) {
    return {
      kind: 'dns',
      code: dns.code,
      message: `the host name did not resolve (${dns.code}). ${viaProxy} `
        + (bypassed !== undefined
          ? `This network's own DNS does not know the host: remove "${bypassed}" from NO_PROXY so it goes through the proxy, as a browser's does.`
          : proxied
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
        + (bypassed !== undefined
          ? `If the host is reached only through the proxy, remove "${bypassed}" from NO_PROXY.`
          : proxied
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
export function describeNetworkFailure(error: unknown, url?: string): string {
  return diagnoseNetworkFailure(error, process.env, url).message
}
