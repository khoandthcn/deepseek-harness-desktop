import { describe, expect, it, vi } from 'vitest'
import { trustLocalAuthorities, type TrustEnvironment } from '../src/trust-store.ts'

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

describe('trustLocalAuthorities', () => {
  it('adds the operating system store to what Node already trusts, without duplicates', () => {
    const { api, set } = fakeTls({ default: [pem('A'), pem('B')], system: [pem('B'), pem('CORP')] })
    const report = vi.fn()
    expect(trustLocalAuthorities(environment({}), report, api)).toEqual({ system: 1, extra: 0 })
    expect(set).toHaveBeenCalledWith([pem('A'), pem('B'), pem('CORP')])
    expect(report).not.toHaveBeenCalled()
  })

  it('leaves the default list alone when there is nothing to add', () => {
    const { api, set } = fakeTls({ default: [pem('A')], system: [pem('A')] })
    expect(trustLocalAuthorities(environment({}), vi.fn(), api)).toEqual({ system: 0, extra: 0 })
    expect(set).not.toHaveBeenCalled()
  })

  it('reads the file named in the Harness home .env, which Node itself never sees', () => {
    const { api, set } = fakeTls({ default: [pem('A')], system: [] })
    const readFile = vi.fn(() => `junk\n${pem('CORP-ROOT')}\n${pem('CORP-ISSUING')}\n`)
    const env = environment({ 'user-env': { NODE_EXTRA_CA_CERTS: ' /etc/corp/ca.pem ' } })
    expect(trustLocalAuthorities(env, vi.fn(), api, readFile)).toEqual({ system: 0, extra: 2 })
    expect(readFile).toHaveBeenCalledWith('/etc/corp/ca.pem')
    expect(set).toHaveBeenCalledWith([pem('A'), pem('CORP-ROOT'), pem('CORP-ISSUING')])
  })

  it('does not let a project .env choose whom to trust or switch the system store off', () => {
    const { api, set } = fakeTls({ default: [pem('A')], system: [pem('CORP')] })
    const readFile = vi.fn(() => pem('EVIL'))
    const env = environment({ 'project-env': { NODE_EXTRA_CA_CERTS: '/repo/evil.pem', DSH_TRUST_SYSTEM_CA: '0' } })
    expect(trustLocalAuthorities(env, vi.fn(), api, readFile)).toEqual({ system: 1, extra: 0 })
    expect(readFile).not.toHaveBeenCalled()
    expect(set).toHaveBeenCalledWith([pem('A'), pem('CORP')])
  })

  it('leaves the system store out when the user opts out', () => {
    const { api, set } = fakeTls({ default: [pem('A')], system: [pem('CORP')] })
    expect(trustLocalAuthorities(environment({ process: { DSH_TRUST_SYSTEM_CA: '0' } }), vi.fn(), api)).toEqual({ system: 0, extra: 0 })
    expect(set).not.toHaveBeenCalled()
  })

  it('reports an unreadable store or file and carries on with the rest', () => {
    const { api, set } = fakeTls({ default: [pem('A')], system: new Error('access denied') })
    const report = vi.fn()
    const env = environment({ process: { NODE_EXTRA_CA_CERTS: '/missing.pem' } })
    const readFile = () => { throw new Error('ENOENT: no such file') }
    expect(trustLocalAuthorities(env, report, api, readFile)).toEqual({ system: 0, extra: 0 })
    expect(report.mock.calls.map(call => call[0])).toEqual([
      expect.stringMatching(/certificate store could not be read \(access denied\)/),
      expect.stringMatching(/NODE_EXTRA_CA_CERTS could not be read \(ENOENT/),
    ])
    expect(set).not.toHaveBeenCalled()
  })

  it('says so when the named file holds no certificate', () => {
    const { api } = fakeTls({ default: [pem('A')], system: [] })
    const report = vi.fn()
    trustLocalAuthorities(environment({ process: { NODE_EXTRA_CA_CERTS: '/x.pem' } }), report, api, () => 'not a pem')
    expect(report).toHaveBeenCalledWith(expect.stringMatching(/holds no PEM certificate/))
  })

  it('does nothing on a runtime that cannot change its default list', () => {
    expect(trustLocalAuthorities(environment({}), vi.fn(), {})).toEqual({ system: 0, extra: 0 })
  })
})
