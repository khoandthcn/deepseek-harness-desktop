import { describe, expect, it } from 'vitest'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { deriveFromDomain, dshHome, ENDPOINTS_FILE, missingEndpointsMessage, resolveEndpoints } from '../src/endpoints.ts'

function homeWith(contents: string | undefined) {
  const home = mkdtempSync(join(tmpdir(), 'soc-endpoints-'))
  if (contents !== undefined) writeFileSync(join(home, ENDPOINTS_FILE), contents)
  return home
}

describe('deriveFromDomain', () => {
  it('gives every system its subdomain of the one platform domain', () => {
    expect(deriveFromDomain({ socDomain: 'example.com' })).toEqual({
      socDomain: 'example.com',
      iamUrl: 'https://iam.example.com',
      redirectUri: 'https://soc.example.com',
      soarBaseUrl: 'https://soar.example.com',
      edrBaseUrl: 'https://edr.example.com',
      siemBaseUrl: 'https://siem.example.com',
      nsmBaseUrl: 'https://nsm.example.com',
    })
  })

  it('leaves an explicitly configured URL alone', () => {
    const derived = deriveFromDomain({ socDomain: 'example.com', siemBaseUrl: 'https://siem-2.example.net' })
    expect(derived.siemBaseUrl).toBe('https://siem-2.example.net')
    expect(derived.edrBaseUrl).toBe('https://edr.example.com')
  })

  it('accepts a domain written as a URL, which is what people paste', () => {
    expect(deriveFromDomain({ socDomain: 'https://example.com/' }).iamUrl).toBe('https://iam.example.com')
  })

  it('derives nothing without a domain', () => {
    expect(deriveFromDomain({ clientId: 'CID' })).toEqual({ clientId: 'CID' })
  })
})

describe('resolveEndpoints', () => {
  it('asks for the platform domain when nothing is configured', () => {
    const resolved = resolveEndpoints({ env: {}, home: homeWith(undefined) })
    expect(resolved.missing).toEqual(['socDomain'])
    expect(resolved.values).toEqual({})
  })

  it('configures every system from the domain in the endpoints file', () => {
    const home = homeWith(JSON.stringify({ socDomain: 'example.com', clientId: 'CID' }))
    const resolved = resolveEndpoints({ env: {}, home })
    expect(resolved.missing).toEqual([])
    expect(resolved.values.iamUrl).toBe('https://iam.example.com')
    expect(resolved.values.nsmBaseUrl).toBe('https://nsm.example.com')
    expect(resolved.values.clientId).toBe('CID')
  })

  it('accepts a deployment that pins its URLs instead of naming a domain', () => {
    const home = homeWith(JSON.stringify({
      iamUrl: 'https://iam.example',
      redirectUri: 'https://portal.example',
      soarBaseUrl: 'https://soar.example',
    }))
    const resolved = resolveEndpoints({ env: {}, home })
    expect(resolved.missing).toEqual([])
    expect(resolved.values.redirectUri).toBe('https://portal.example')
  })

  it('lets the environment override the file, and the preset row override both', () => {
    const home = homeWith(JSON.stringify({ socDomain: 'file.example', clientId: 'FILE' }))
    const resolved = resolveEndpoints({
      home,
      env: { SOC_DOMAIN: 'env.example', SOC_CLIENT_ID: 'ENV' },
      config: { clientId: 'CONFIG' },
    })
    expect(resolved.values.iamUrl).toBe('https://iam.env.example')
    expect(resolved.values.clientId).toBe('CONFIG')
  })

  it('ignores blank and non-string entries rather than passing them on as URLs', () => {
    const home = homeWith(JSON.stringify({ socDomain: '   ', clientId: 42, redirectUri: null }))
    const resolved = resolveEndpoints({ env: {}, home })
    expect(resolved.values).toEqual({})
    expect(resolved.missing).toContain('socDomain')
  })

  it('trims what it keeps', () => {
    const home = homeWith(JSON.stringify({ soarBaseUrl: '  https://soar.example  ' }))
    expect(resolveEndpoints({ env: {}, home }).values.soarBaseUrl).toBe('https://soar.example')
  })

  it('says which file is malformed rather than looking unconfigured', () => {
    const home = homeWith('{ not json')
    expect(() => resolveEndpoints({ env: {}, home })).toThrow(/not valid JSON/)
    expect(() => resolveEndpoints({ env: {}, home: homeWith('[]') })).toThrow(/JSON object/)
  })

  it('names the file and the environment variables in its message', () => {
    const home = homeWith(undefined)
    const message = missingEndpointsMessage(resolveEndpoints({ env: {}, home }))
    expect(message).toContain(join(home, ENDPOINTS_FILE))
    expect(message).toContain('SOC_DOMAIN')
    expect(message).toContain('Settings')
  })
})

describe('dshHome', () => {
  it('defaults to .dsh under the home directory', () => {
    expect(dshHome({}, '/Users/someone')).toBe('/Users/someone/.dsh')
  })

  it('honours DSH_HOME', () => {
    expect(dshHome({ DSH_HOME: '/opt/dsh' }, '/Users/someone')).toBe('/opt/dsh')
  })
})
