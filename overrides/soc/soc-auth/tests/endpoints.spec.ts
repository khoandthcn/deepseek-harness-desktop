import { describe, expect, it } from 'vitest'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { dshHome, ENDPOINTS_FILE, missingEndpointsMessage, resolveEndpoints } from '../src/endpoints.ts'

function homeWith(contents: string | undefined) {
  const home = mkdtempSync(join(tmpdir(), 'soc-endpoints-'))
  if (contents !== undefined) writeFileSync(join(home, ENDPOINTS_FILE), contents)
  return home
}

describe('resolveEndpoints', () => {
  it('reports every required key when nothing is configured', () => {
    const resolved = resolveEndpoints({ env: {}, home: homeWith(undefined) })
    expect(resolved.missing).toEqual(['iamUrl', 'clientId', 'redirectUri', 'soarBaseUrl'])
    expect(resolved.values).toEqual({})
  })

  it('reads the endpoints file in the dsh home', () => {
    const home = homeWith(JSON.stringify({
      iamUrl: 'https://iam.example',
      clientId: 'CID',
      redirectUri: 'https://soc.example',
      soarBaseUrl: 'https://soar.example',
      nsmBaseUrl: 'https://nsm.example',
    }))
    const resolved = resolveEndpoints({ env: {}, home })
    expect(resolved.missing).toEqual([])
    expect(resolved.values.iamUrl).toBe('https://iam.example')
    expect(resolved.values.nsmBaseUrl).toBe('https://nsm.example')
  })

  it('lets the environment override the file, and the preset row override both', () => {
    const home = homeWith(JSON.stringify({ iamUrl: 'https://file.example', clientId: 'FILE' }))
    const resolved = resolveEndpoints({
      home,
      env: { SOC_IAM_URL: 'https://env.example', SOC_CLIENT_ID: 'ENV' },
      config: { clientId: 'CONFIG' },
    })
    expect(resolved.values.iamUrl).toBe('https://env.example')
    expect(resolved.values.clientId).toBe('CONFIG')
  })

  it('ignores blank and non-string entries rather than passing them on as URLs', () => {
    const home = homeWith(JSON.stringify({ iamUrl: '   ', clientId: 42, redirectUri: null }))
    const resolved = resolveEndpoints({ env: {}, home })
    expect(resolved.values).toEqual({})
    expect(resolved.missing).toContain('iamUrl')
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
    expect(message).toContain('SOC_IAM_URL')
    expect(message).toContain('soarBaseUrl')
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
