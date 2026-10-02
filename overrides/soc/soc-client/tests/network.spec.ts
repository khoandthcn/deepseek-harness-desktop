import { describe, expect, it } from 'vitest'
import { bypassEntryFor, diagnoseNetworkFailure, proxyConfigured, routeFor } from '../src/network.ts'

/** What `fetch` throws: a bare "fetch failed" whose reason is a nested cause. */
function fetchFailed(cause: unknown): TypeError {
  return Object.assign(new TypeError('fetch failed'), { cause })
}
const coded = (code: string, message = code) => Object.assign(new Error(message), { code })

describe('diagnoseNetworkFailure', () => {
  it('reads an unresolved name with no proxy as a missing proxy, and explains why a browser still works', () => {
    const out = diagnoseNetworkFailure(fetchFailed(coded('ENOTFOUND', 'getaddrinfo ENOTFOUND iam.soc.example')), {})
    expect(out).toMatchObject({ kind: 'dns', code: 'ENOTFOUND' })
    expect(out.message).toMatch(/No proxy is configured/)
    expect(out.message).toMatch(/set HTTPS_PROXY/)
    expect(out.message).toMatch(/browser/)
  })

  it('reads an unresolved name behind a proxy as the proxy or the bypass list, not as a missing proxy', () => {
    const out = diagnoseNetworkFailure(fetchFailed(coded('ENOTFOUND')), { HTTPS_PROXY: 'http://proxy.corp:3128' })
    expect(out.message).toMatch(/A proxy is configured/)
    expect(out.message).toMatch(/NO_PROXY/)
    expect(out.message).not.toMatch(/set HTTPS_PROXY/)
  })

  it('names an untrusted certificate and both ways to trust its authority', () => {
    for (const code of ['SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE']) {
      const out = diagnoseNetworkFailure(fetchFailed(coded(code)), {})
      expect(out).toMatchObject({ kind: 'certificate', code })
      expect(out.message).toMatch(/operating system's store/)
      expect(out.message).toMatch(/~\/\.dsh\/certs/)
      // Naming that variable for the home .env would stop the application from starting.
      expect(out.message).not.toMatch(/NODE_EXTRA_CA_CERTS/)
    }
  })

  it('reads a certificate for another host name as a wrong address, not as an authority to install', () => {
    const out = diagnoseNetworkFailure(fetchFailed(coded('ERR_TLS_CERT_ALTNAME_INVALID')), {})
    expect(out).toMatchObject({ kind: 'certificate', code: 'ERR_TLS_CERT_ALTNAME_INVALID' })
    expect(out.message).toMatch(/different host name/)
    expect(out.message).not.toMatch(/certs/)
  })

  it('finds the reason inside an aggregate, as a dual-stack connect reports it', () => {
    const aggregate = Object.assign(new AggregateError([coded('ECONNREFUSED'), coded('ENETUNREACH')], 'all failed'))
    expect(diagnoseNetworkFailure(fetchFailed(aggregate), {})).toMatchObject({ kind: 'connect', code: 'ECONNREFUSED' })
  })

  it('tells a connect timeout from a refusal, and advises by whether a proxy is set', () => {
    const direct = diagnoseNetworkFailure(fetchFailed(coded('UND_ERR_CONNECT_TIMEOUT')), {})
    expect(direct).toMatchObject({ kind: 'timeout', code: 'UND_ERR_CONNECT_TIMEOUT' })
    expect(direct.message).toMatch(/set HTTPS_PROXY/)
    const proxied = diagnoseNetworkFailure(fetchFailed(coded('UND_ERR_CONNECT_TIMEOUT')), { https_proxy: 'http://p:1' })
    expect(proxied.message).toMatch(/add its domain to NO_PROXY/)
  })

  it('reads a proxy that refuses the tunnel, and asks for credentials only on 407', () => {
    const denied = diagnoseNetworkFailure(fetchFailed(new Error('Proxy response (403) !== 200 when HTTP Tunneling')), { HTTPS_PROXY: 'http://p:1' })
    expect(denied).toMatchObject({ kind: 'proxy', code: 'PROXY_403' })
    expect(denied.message).toMatch(/does not allow this destination/)
    const login = diagnoseNetworkFailure(fetchFailed(new Error('Proxy response (407) !== 200 when HTTP Tunneling')), { HTTPS_PROXY: 'http://p:1' })
    expect(login.message).toMatch(/user:password@host:port/)
  })

  it('falls back to the innermost message when the failure is of no known kind', () => {
    expect(diagnoseNetworkFailure(fetchFailed(new Error('something odd')), {})).toMatchObject({ kind: 'unknown', code: '' })
    expect(diagnoseNetworkFailure(fetchFailed(new Error('something odd')), {}).message).toMatch(/something odd/)
    expect(diagnoseNetworkFailure('not even an error', {}).message).toMatch(/without a reason/)
  })

  it('never repeats a URL or a proxy credential', () => {
    const out = diagnoseNetworkFailure(fetchFailed(coded('ECONNREFUSED')), { HTTPS_PROXY: 'http://alice:s3cret@proxy.corp:3128' })
    expect(out.message).not.toContain('s3cret')
    expect(out.message).not.toContain('proxy.corp')
  })
})

describe('proxyConfigured', () => {
  it('reads either casing and ignores a blank value', () => {
    expect(proxyConfigured({})).toBe(false)
    expect(proxyConfigured({ HTTPS_PROXY: '  ' })).toBe(false)
    expect(proxyConfigured({ https_proxy: 'http://p:1' })).toBe(true)
    expect(proxyConfigured({ ALL_PROXY: 'http://p:1' })).toBe(true)
  })
})

describe('routeFor', () => {
  const PROXY = { HTTPS_PROXY: 'http://alice:s3cret@192.0.2.8:3128', NO_PROXY: 'corp.example,localhost,127.0.0.1' }

  it('sends a host to the proxy, and shows the proxy without its credentials', () => {
    expect(routeFor('https://iam.soc.example/oauth2', PROXY)).toEqual({ proxied: true, proxy: 'http://192.0.2.8:3128' })
  })

  it('sends a host and its subdomains direct when the bypass list names the domain', () => {
    expect(routeFor('https://iam.corp.example/', PROXY)).toMatchObject({ proxied: false, bypassedBy: 'corp.example' })
    expect(routeFor('https://corp.example/', PROXY)).toMatchObject({ proxied: false, bypassedBy: 'corp.example' })
    expect(routeFor('https://notcorp.example/', PROXY)).toMatchObject({ proxied: true })
  })

  it('goes direct with no proxy set, and keeps loopback direct', () => {
    expect(routeFor('https://iam.soc.example/', {})).toEqual({ proxied: false })
    expect(routeFor('http://127.0.0.1:8080/', { HTTP_PROXY: 'http://p:1' })).toMatchObject({ proxied: false })
  })
})

describe('bypassEntryFor', () => {
  it('reads leading dots, wildcards, ports and the catch-all as the launcher does', () => {
    expect(bypassEntryFor('a.b.example', '443', '.b.example')).toBe('.b.example')
    expect(bypassEntryFor('a.b.example', '443', '*.b.example')).toBe('*.b.example')
    expect(bypassEntryFor('a.b.example', '443', 'b.example:8443')).toBeUndefined()
    expect(bypassEntryFor('a.b.example', '8443', 'b.example:8443')).toBe('b.example:8443')
    expect(bypassEntryFor('anything', '443', 'x, *')).toBe('*')
  })
})

describe('diagnoseNetworkFailure with the request URL', () => {
  it('names the bypass entry that sent an unresolvable host direct, and says to remove it', () => {
    const env = { HTTPS_PROXY: 'http://192.0.2.8:3128', NO_PROXY: 'corp.example,soc.example' }
    const out = diagnoseNetworkFailure(fetchFailed(coded('ENOTFOUND')), env, 'https://iam.soc.example/oauth2/authorize')
    expect(out.kind).toBe('dns')
    expect(out.message).toMatch(/matches "soc.example" in NO_PROXY, so the request went direct/)
    expect(out.message).toMatch(/remove "soc.example" from NO_PROXY/)
  })

  it('keeps the proxied advice for a host the bypass list does not name', () => {
    const env = { HTTPS_PROXY: 'http://192.0.2.8:3128', NO_PROXY: 'corp.example' }
    const out = diagnoseNetworkFailure(fetchFailed(coded('ENOTFOUND')), env, 'https://iam.soc.example/')
    expect(out.message).toMatch(/A proxy is configured, so the request went to it/)
  })
})
