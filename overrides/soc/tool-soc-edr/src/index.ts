/**
 * `tool-soc-edr` — a thin Cordis plugin registering the read-only EDR tools.
 *
 * All the behaviour lives in `tools.ts`, which is dependency-free and unit
 * tested; this file only wires it to the harness: build the HTTP client and
 * adapter, then push each definition through `defineTool` onto `ctx.tools`.
 *
 * EDR reuses the SOC session that `soc_login` (from `tool-soc-soar`) establishes,
 * so this plugin registers no login tool. When both tool packages are mounted,
 * `soc_login` is registered exactly once, by `tool-soc-soar`.
 *
 * @module @deepseek-ai/dsh-tool-soc-edr
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { SocHttp } from '@deepseek-ai/dsh-soc-client'
import type {} from '@deepseek-ai/dsh-soc-auth'
import { EdrAdapter, type EdrHttp } from './adapter.ts'
import { createEdrToolDefs, type EdrToolDef } from './tools.ts'

export * from './contracts.ts'
export * from './adapter.ts'
export * from './tools.ts'

/**
 * The definitions are typed against a local structural mirror of the schema DSL
 * (`tools.ts` imports nothing from `dsh-tools`), so `defineTool`'s per-literal
 * generic inference cannot apply here. Aliasing the function to a concrete,
 * non-generic signature keeps the boundary explicit and stops the checker from
 * instantiating those generics against the mirror.
 */
const define = defineTool as unknown as (
  options: EdrToolDef,
) => Parameters<Context['tools']['register']>[0]

export const name = 'tool-soc-edr'

/** `socAuth` comes from the `soc-auth` plugin, which must be mounted first. */
export const inject = ['tools', 'socAuth']

export interface Config {
  /**
   * Override the EDR base URL. Normally absent: the endpoint comes from the
   * `soc-auth` plugin, which is where the deployment is configured.
   */
  edrBaseUrl?: string | undefined
}

/**
 * Register the EDR tool suite on `ctx.tools`.
 * @param ctx - registrant context carrying `tools` and `socAuth`.
 * @param config - optional overrides; a preset row for this plugin carries no
 *   config at all, so this arrives as `undefined`.
 */
export function apply(ctx: Context, config: Config = {}): void {
  const auth = ctx.socAuth
  // Configured once, on soc-auth.
  const edrBaseUrl = config.edrBaseUrl ?? auth.edrBaseUrl

  // One EDR token is global for every endpoint, so a single client carries the
  // credential; `edrAuthHeaders()` reads the current cookie on each request.
  const http = new SocHttp(edrBaseUrl, { authHeaders: () => auth.edrAuthHeaders() })

  const edrHttp: EdrHttp = {
    async postJson<T>(path: string, body: unknown): Promise<T> {
      await auth.edrToken()
      return http.postJson<T>(path, body)
    },
    async getJson<T>(path: string): Promise<T> {
      await auth.edrToken()
      return http.getJson<T>(path)
    },
  }

  const adapter = new EdrAdapter(edrHttp)

  for (const def of createEdrToolDefs({ adapter, auth })) {
    ctx.tools.register(define(def))
  }
}
