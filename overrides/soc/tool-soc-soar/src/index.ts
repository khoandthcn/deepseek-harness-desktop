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
import { createSoarToolDefs } from './tools.ts'

export * from './contracts.ts'
export * from './query.ts'
export * from './adapter.ts'
export * from './tools.ts'

export const name = 'tool-soc-soar'

/** `socAuth` comes from the `soc-auth` plugin, which must be mounted first. */
export const inject = ['tools', 'socAuth']

export interface Config {
  /** Base URL of the SOAR API, e.g. `https://soar.example`. */
  soarBaseUrl: string
  /** SOAR tenant; defaults to `MASTER`. */
  tenant?: string
}

/**
 * Register the SOAR tool suite on `ctx.tools`.
 * @param ctx - registrant context carrying `tools` and `socAuth`.
 * @param config - SOAR endpoint and tenant.
 */
export function apply(ctx: Context, config: Config): void {
  const auth = ctx.socAuth

  // The Bearer is re-read per request, so a refresh between calls is picked up
  // without rebuilding the client.
  const http = new SocHttp(config.soarBaseUrl, {
    authHeaders: () => auth.authHeadersForSoar(),
  })

  // `authHeadersForSoar()` is synchronous and only returns a Bearer once one has
  // been fetched, so every call first awaits the (cached) exchange.
  const soarHttp: SoarHttp = {
    async postJson<T>(path: string, body: unknown): Promise<T> {
      await auth.soarBearer()
      return http.postJson<T>(path, body)
    },
    async getJson<T>(path: string): Promise<T> {
      await auth.soarBearer()
      return http.getJson<T>(path)
    },
  }

  const adapter = new SoarAdapter(soarHttp, config.tenant ?? 'MASTER')

  for (const def of createSoarToolDefs({ adapter, auth })) {
    // The definitions are typed against a local structural mirror of the schema
    // DSL (tools.ts imports nothing from dsh-tools), so the precise generic
    // inference `defineTool` performs on a literal is not available here.
    ctx.tools.register(defineTool(def as Parameters<typeof defineTool>[0]))
  }
}
