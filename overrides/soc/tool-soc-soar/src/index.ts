/**
 * `tool-soc-soar` — a thin Cordis plugin registering `soc_login` and the
 * read-only SOAR tools.
 *
 * All the behaviour lives in `tools.ts`, which is dependency-free and unit
 * tested; this file only wires it to the harness: build the HTTP client and
 * adapter, then push each definition through `defineTool` onto `ctx.tools`.
 *
 * @module @deepseek-ai/dsh-tool-soc-soar
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { SocHttp } from '@deepseek-ai/dsh-soc-client'
import type {} from '@deepseek-ai/dsh-soc-auth'
import { SoarAdapter, type SoarHttp } from './adapter.ts'
import { createSoarToolDefs, type SoarToolDef } from './tools.ts'

export * from './contracts.ts'
export * from './query.ts'
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
  options: SoarToolDef,
) => Parameters<Context['tools']['register']>[0]

export const name = 'tool-soc-soar'

/** `socAuth` comes from the `soc-auth` plugin, which must be mounted first. */
export const inject = ['tools', 'socAuth']

export interface Config {
  /**
   * Override the SOAR base URL. Normally absent: the endpoint comes from the
   * `soc-auth` plugin, which is where the deployment is configured.
   */
  soarBaseUrl?: string | undefined
  /** SOAR tenant; defaults to `MASTER`. */
  tenant?: string | undefined
}

/**
 * Register the SOAR tool suite on `ctx.tools`.
 * @param ctx - registrant context carrying `tools` and `socAuth`.
 * @param config - optional overrides; a preset row for this plugin carries no
 *   config at all, so this arrives as `undefined`.
 */
export function apply(ctx: Context, config: Config = {}): void {
  const auth = ctx.socAuth
  // Configured once, on soc-auth.
  // Read per request: Settings can change the deployment while the app runs.
  const soarBaseUrl = () => config.soarBaseUrl ?? auth.soarBaseUrl
  const tenant = config.tenant ?? auth.tenant

  // The SOAR Bearer is per-scope: await the (cached) exchange for this call's
  // scope, then send the Bearer and cookies that scope resolved to. A fresh
  // SocHttp per call is cheap and keeps the scoped auth header correct.
  const httpForScope = (scope: string): SocHttp =>
    new SocHttp(soarBaseUrl, { authHeaders: () => auth.authHeadersForSoar(scope) })

  const soarHttp: SoarHttp = {
    async postJson<T>(path: string, body: unknown, scope: string): Promise<T> {
      await auth.soarBearer(scope)
      return httpForScope(scope).postJson<T>(path, body)
    },
    async getJson<T>(path: string, scope: string): Promise<T> {
      await auth.soarBearer(scope)
      return httpForScope(scope).getJson<T>(path)
    },
  }

  const adapter = new SoarAdapter(soarHttp, tenant)

  for (const def of createSoarToolDefs({ adapter, auth })) {
    ctx.tools.register(define(def))
  }
}
