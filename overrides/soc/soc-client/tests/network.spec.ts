import { describe, expect, it } from 'vitest'
import { diagnoseNetworkFailure, proxyConfigured } from '../src/network.ts'

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
      expect(out.message).toMatch(/operating system's trust store/)
      expect(out.message).toMatch(/NODE_EXTRA_CA_CERTS/)
    }
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
