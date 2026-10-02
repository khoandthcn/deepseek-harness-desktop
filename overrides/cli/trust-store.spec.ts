import { X509Certificate } from 'node:crypto'
import { rootCertificates } from 'node:tls'
import { describe, expect, it, vi } from 'vitest'
import { certificatesIn, trustLocalAuthorities, type TrustEnvironment } from '../src/trust-store.ts'

const pem = (body: string) => `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`

/** An environment with values per layer, as the launcher's snapshot answers. */
function environment(layers: Partial<Record<'process' | 'project-env' | 'user-env', Record<string, string>>>): TrustEnvironment {
  return {
    getFrom(name, sources) {
      for (const source of sources) {
        const value = layers[source]?.[name]
        if (value !== undefined) return { value }
      }
      return undefined
    },
  }
}

function fakeTls(stores: { default: string[], system: string[] | Error }) {
  const set = vi.fn((_certificates: string[]) => {})
  return {
    set,
    api: {
      getCACertificates: (type: 'default' | 'system') => {
        const store = stores[type]
        if (store instanceof Error) throw store
        return store
      },
      setDefaultCACertificates: set,
    },
  }
}

/** A folder of files under `/home/certs`, as the options' seams read it. */
function folder(files: Record<string, string | Buffer>) {
  return {
    home: '/home',
    listDir: vi.fn((path: string) => {
      expect(path).toMatch(/[\\/]home[\\/]certs$/)
      return Object.keys(files)
    }),
    readFile: vi.fn((path: string) => {
      const name = path.split(/[\\/]/).pop()!
      const value = files[name]!
      return Buffer.isBuffer(value) ? value : Buffer.from(value)
    }),
  }
}

describe('trustLocalAuthorities', () => {
  it('adds the operating system store to what Node already trusts, without duplicates', () => {
    const { api, set } = fakeTls({ default: [pem('A'), pem('B')], system: [pem('B'), pem('CORP')] })
    const report = vi.fn()
    expect(trustLocalAuthorities(environment({}), report, { api })).toEqual({ system: 1, files: 0 })
    expect(set).toHaveBeenCalledWith([pem('A'), pem('B'), pem('CORP')])
    expect(report).not.toHaveBeenCalled()
  })

  it('leaves the default list alone when there is nothing to add', () => {
    const { api, set } = fakeTls({ default: [pem('A')], system: [pem('A')] })
    expect(trustLocalAuthorities(environment({}), vi.fn(), { api })).toEqual({ system: 0, files: 0 })
    expect(set).not.toHaveBeenCalled()
  })

  it('trusts the certificate files in the Harness home certs folder, and nothing else there', () => {
    const { api, set } = fakeTls({ default: [pem('A')], system: [] })
    const files = folder({ 'gateway.crt': `junk\n${pem('GW-ROOT')}\n${pem('GW-ISSUING')}\n`, 'notes.txt': pem('IGNORED') })
    expect(trustLocalAuthorities(environment({}), vi.fn(), { api, ...files })).toEqual({ system: 0, files: 2 })
    expect(set).toHaveBeenCalledWith([pem('A'), pem('GW-ROOT'), pem('GW-ISSUING')])
    expect(files.readFile).toHaveBeenCalledTimes(1)
  })

  it('treats a missing certs folder as nothing to add, without a warning', () => {
    const { api } = fakeTls({ default: [pem('A')], system: [] })
    const report = vi.fn()
    const listDir = () => { throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }) }
    expect(trustLocalAuthorities(environment({}), report, { api, home: '/home', listDir })).toEqual({ system: 0, files: 0 })
    expect(report).not.toHaveBeenCalled()
  })

  it('reports a file that holds no certificate and carries on with the others', () => {
    const { api } = fakeTls({ default: [pem('A')], system: [] })
    const report = vi.fn()
    const files = folder({ 'empty.pem': 'not a certificate', 'good.pem': pem('GOOD') })
    expect(trustLocalAuthorities(environment({}), report, { api, ...files })).toEqual({ system: 0, files: 1 })
    expect(report).toHaveBeenCalledWith(expect.stringMatching(/empty\.pem holds no certificate/))
  })

  it('leaves the system store out only when the launching environment says so, never a .env file', () => {
    const { api, set } = fakeTls({ default: [pem('A')], system: [pem('CORP')] })
    expect(trustLocalAuthorities(environment({ 'user-env': { DSH_TRUST_SYSTEM_CA: '0' } }), vi.fn(), { api })).toEqual({ system: 1, files: 0 })
    set.mockClear()
    expect(trustLocalAuthorities(environment({ process: { DSH_TRUST_SYSTEM_CA: '0' } }), vi.fn(), { api })).toEqual({ system: 0, files: 0 })
    expect(set).not.toHaveBeenCalled()
  })

  it('reports an unreadable system store and still trusts the folder', () => {
    const { api, set } = fakeTls({ default: [pem('A')], system: new Error('access denied') })
    const report = vi.fn()
    expect(trustLocalAuthorities(environment({}), report, { api, ...folder({ 'gw.pem': pem('GW') }) })).toEqual({ system: 0, files: 1 })
    expect(report).toHaveBeenCalledWith(expect.stringMatching(/certificate store could not be read \(access denied\)/))
    expect(set).toHaveBeenCalledWith([pem('A'), pem('GW')])
  })

  it('does nothing on a runtime that cannot change its default list', () => {
    expect(trustLocalAuthorities(environment({}), vi.fn(), { api: {} })).toEqual({ system: 0, files: 0 })
  })
})

describe('certificatesIn', () => {
  it('reads a DER certificate, the form Windows exports by default, as PEM', () => {
    const sample = new X509Certificate(rootCertificates[0]!)
    const out = certificatesIn(sample.raw)
    expect(out).toHaveLength(1)
    expect(new X509Certificate(out[0]!).fingerprint256).toBe(sample.fingerprint256)
  })

  it('reads every block of a PEM bundle and normalises Windows line endings', () => {
    expect(certificatesIn(Buffer.from(`${pem('A')}\r\n${pem('B')}`.replace(/\n/g, '\r\n')))).toEqual([pem('A'), pem('B')])
  })
})
