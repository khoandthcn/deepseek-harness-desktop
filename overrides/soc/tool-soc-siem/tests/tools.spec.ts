import { describe, expect, it, vi } from 'vitest'
import { createSiemToolDefs, SIEM_PATHS, SIEM_TOKEN_FOR, type SiemHttpLike } from '../src/tools.ts'

/** vitest types `mock.calls` from the stub's own signature; these tests read
 * positional args the stubs do not declare, so narrow once here. */
const callsOf = (m: { mock: { calls: unknown[] } }): any[][] =>
  m.mock.calls as unknown as any[][]

/** A structural `SocHttp` double: SIEM carries its credential itself, so no scope. */
function stubHttp(responses: Record<string, unknown>) {
  const postJson = vi.fn(async (path: string) => {
    if (!(path in responses)) throw new Error(`unexpected POST ${path}`)
    return responses[path]
  })
  return { postJson }
}

/** Structural stand-in for soc-auth's `SocAuthService`. */
function fakeAuth(authenticated: boolean, siemMgmtClientId = 'cym_api') {
  return { isAuthenticated: vi.fn(() => authenticated), siemMgmtClientId }
}

function defs(authenticated: boolean, responses: Record<string, unknown> = {}) {
  const http = stubHttp(responses)
  const auth = fakeAuth(authenticated)
  const list = createSiemToolDefs({ http: http as unknown as SiemHttpLike, auth })
  const byName = (name: string) => {
    const def = list.find(d => d.name === name)
    if (!def) throw new Error(`no tool named ${name}`)
    return def
  }
  return { http, auth, list, byName }
}

describe('createSiemToolDefs', () => {
  it('defines exactly the single siem_check_access probe', () => {
    const { list } = defs(true)
    expect(list.map(d => d.name)).toEqual(['siem_check_access'])
  })

  it('does NOT define soc_login (that stays in tool-soc-soar)', () => {
    const { list } = defs(true)
    expect(list.map(d => d.name)).not.toContain('soc_login')
  })

  it('gives the tool a description and a parameters object', () => {
    const { byName } = defs(true)
    const def = byName('siem_check_access')
    expect(typeof def.description).toBe('string')
    expect(def.description.length).toBeGreaterThan(0)
    expect(def.parameters).toEqual({})
  })
})

describe('fail-closed when not logged in', () => {
  it('returns the not_authenticated value and never touches the http client', async () => {
    const { http, byName } = defs(false)
    const out = await byName('siem_check_access').execute({})
    expect(out).toMatchObject({ error: 'not_authenticated' })
    expect((out as { message: string }).message).toMatch(/soc_login/)
    expect(http.postJson).not.toHaveBeenCalled()
  })

  it('does not throw — the model gets a structured value it can act on', async () => {
    const { byName } = defs(false)
    await expect(byName('siem_check_access').execute({})).resolves.toBeDefined()
  })
})

describe('authenticated happy path', () => {
  it('posts the mgmt client_id and parses {count, data}', async () => {
    const { http, byName } = defs(true, {
      [SIEM_PATHS.userRolePerm]: { count: 2, data: ['view_dashboard', 'view_alert'] },
    })
    const out = await byName('siem_check_access').execute({})
    expect(out).toEqual({ count: 2, data: ['view_dashboard', 'view_alert'] })

    const [path, body] = callsOf(http.postJson)[0] as [string, Record<string, unknown>]
    expect(path).toBe('/oauth/management/get_user_role_perm')
    expect(body).toEqual({ client_id: 'cym_api' })
  })

  it('tolerates a missing count by falling back to the data length', async () => {
    const { byName } = defs(true, { [SIEM_PATHS.userRolePerm]: { data: ['a', 'b', 'c'] } })
    const out = await byName('siem_check_access').execute({})
    expect(out).toEqual({ count: 3, data: ['a', 'b', 'c'] })
  })

  it('rejects a non-object payload with a clear contract error', async () => {
    const { byName } = defs(true, { [SIEM_PATHS.userRolePerm]: 'nope' })
    await expect(byName('siem_check_access').execute({})).rejects.toThrow(/SIEM access/i)
  })
})

describe('SIEM_TOKEN_FOR', () => {
  it('routes every SIEM path to the audience/scope its SPA uses', () => {
    for (const path of Object.values(SIEM_PATHS)) {
      expect(SIEM_TOKEN_FOR[path], path).toBeDefined()
    }
    expect(SIEM_TOKEN_FOR[SIEM_PATHS.userRolePerm]).toEqual({ audience: 'gatekeeper', scope: 'login' })
  })
})
