import { describe, expect, it } from 'vitest'
import { requireConfig } from '../src/config.ts'

const complete = {
  iamUrl: 'https://iam.example',
  clientId: 'CID',
  redirectUri: 'https://soc.example',
  soarBaseUrl: 'https://soar.example',
}

describe('requireConfig', () => {
  it('returns a complete config unchanged', () => {
    expect(requireConfig(complete)).toBe(complete)
  })

  it('names the block when a preset row carries no config at all', () => {
    expect(() => requireConfig(undefined)).toThrow(/needs a `config:` block/)
  })

  it('names every field that is missing', () => {
    const error = (() => {
      try {
        requireConfig({ iamUrl: 'https://iam.example', clientId: 'CID' })
        return undefined
      } catch (cause) {
        return cause as Error
      }
    })()
    expect(error?.message).toContain('redirectUri')
    expect(error?.message).toContain('soarBaseUrl')
    expect(error?.message).not.toContain('iamUrl')
  })

  it('treats a blank value as absent', () => {
    expect(() => requireConfig({ ...complete, clientId: '  ' })).toThrow(/clientId/)
  })
})
