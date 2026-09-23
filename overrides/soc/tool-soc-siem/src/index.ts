/**
 * `tool-soc-siem` — a thin Cordis plugin registering the SIEM access probe.
 *
 * All the behaviour lives in `tools.ts`, which is dependency-free and unit
 * tested; this file only wires it to the harness: build the HTTP client with the
 * SIEM auth headers seam, then push each definition through `defineTool` onto
 * `ctx.tools`.
 *
 * SIEM reuses the SOC session that `soc_login` (from `tool-soc-soar`)
 * establishes, so this plugin registers no login tool. The first request logs
 * in to SIEM, then each API group's token is acquired lazily (`SIEM_TOKEN_FOR`).
 *
 * @module @deepseek-ai/dsh-tool-soc-siem
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { SocHttp } from '@deepseek-ai/dsh-soc-client'
import type {} from '@deepseek-ai/dsh-soc-auth'
import { createSiemToolDefs, SIEM_TOKEN_FOR, type SiemHttpLike, type SiemToolDef } from './tools.ts'

export * from './tools.ts'

/**
 * The definitions are typed against a local structural mirror of the schema DSL
 * (`tools.ts` imports nothing from `dsh-tools`), so `defineTool`'s per-literal
 * generic inference cannot apply here. Aliasing the function to a concrete,
 * non-generic signature keeps the boundary explicit and stops the checker from
 * instantiating those generics against the mirror.
 */
const define = defineTool as unknown as (
  options: SiemToolDef,
) => Parameters<Context['tools']['register']>[0]

export const name = 'tool-soc-siem'

/** `socAuth` comes from the `soc-auth` plugin, which must be mounted first. */
export const inject = ['tools', 'socAuth']

export interface Config {
  /**
   * Override the SIEM base URL. Normally absent: the endpoint comes from the
   * `soc-auth` plugin, which is where the deployment is configured.
   */
  siemBaseUrl?: string | undefined
}

/**
 * Register the SIEM tool suite on `ctx.tools`.
 * @param ctx - registrant context carrying `tools` and `socAuth`.
 * @param config - optional overrides; a preset row for this plugin carries no
 *   config at all, so this arrives as `undefined`.
 */
export function apply(ctx: Context, config: Config = {}): void {
  const auth = ctx.socAuth
  // Configured once, on soc-auth.
  // Read per request: Settings can change the deployment while the app runs.
  const siemBaseUrl = () => config.siemBaseUrl ?? auth.siemBaseUrl

  // SIEM issues one token per API group (audience) and scope, so each request
  // is routed through a client carrying that path's token.
  const clients = new Map<string, SocHttp>()
  const clientFor = (audience: string, scope: string): SocHttp => {
    const key = `${audience}/${scope}`
    let client = clients.get(key)
    if (!client) {
      client = new SocHttp(siemBaseUrl, { authHeaders: () => auth.siemAuthHeaders(audience, scope) })
      clients.set(key, client)
    }
    return client
  }

  const siemHttp: SiemHttpLike = {
    async postJson<T>(path: string, body: unknown): Promise<T> {
      const route = SIEM_TOKEN_FOR[path]
      if (!route) throw new Error(`tool-soc-siem: no SIEM token route for ${path}`)
      await auth.siemToken(route.audience, route.scope)
      return clientFor(route.audience, route.scope).postJson<T>(path, body)
    },
  }

  for (const def of createSiemToolDefs({ http: siemHttp, auth })) {
    ctx.tools.register(define(def))
  }
}
