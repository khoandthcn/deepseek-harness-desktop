/**
 * `tool-soc-nsm` — a thin Cordis plugin registering the NSM (NDR) tools.
 *
 * All the behaviour lives in `tools.ts`, which is dependency-free and unit
 * tested; this file only wires it to the harness: build the HTTP client with
 * the NSM auth headers seam, then push each definition through `defineTool`
 * onto `ctx.tools`.
 *
 * NSM reuses the SOC session that `soc_login` (from `tool-soc-soar`)
 * establishes, so this plugin registers no login tool. The first request signs
 * in to NSM, and the session cookies plus its CSRF header ride every call.
 *
 * @module @deepseek-ai/dsh-tool-soc-nsm
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { SocHttp } from '@deepseek-ai/dsh-soc-client'
import type {} from '@deepseek-ai/dsh-soc-auth'
import { createNsmToolDefs, type NsmHttpLike, type NsmToolDef } from './tools.ts'

export * from './tools.ts'

/**
 * The definitions are typed against a local structural mirror of the schema DSL
 * (`tools.ts` imports nothing from `dsh-tools`), so `defineTool`'s per-literal
 * generic inference cannot apply here. Aliasing the function to a concrete,
 * non-generic signature keeps the boundary explicit and stops the checker from
 * instantiating those generics against the mirror.
 */
const define = defineTool as unknown as (
  options: NsmToolDef,
) => Parameters<Context['tools']['register']>[0]

export const name = 'tool-soc-nsm'

/** `socAuth` comes from the `soc-auth` plugin, which must be mounted first. */
export const inject = ['tools', 'socAuth']

export interface Config {
  /**
   * Override the NSM base URL. Normally absent: the endpoint comes from the
   * `soc-auth` plugin, which is where the deployment is configured.
   */
  nsmBaseUrl?: string | undefined
}

/**
 * Register the NSM tool suite on `ctx.tools`.
 * @param ctx - registrant context carrying `tools` and `socAuth`.
 * @param config - optional overrides; a preset row for this plugin carries no
 *   config at all, so this arrives as `undefined`.
 */
export function apply(ctx: Context, config: Config = {}): void {
  const auth = ctx.socAuth
  // Configured once, on soc-auth.
  // Read per request: Settings can change the deployment while the app runs.
  const nsmBaseUrl = () => config.nsmBaseUrl ?? auth.nsmBaseUrl

  // One session serves every NSM endpoint, so a single client carries it;
  // `nsmAuthHeaders()` reads the current cookies and CSRF token per request.
  const client = new SocHttp(nsmBaseUrl, { authHeaders: () => auth.nsmAuthHeaders() })

  // Every call signs in first: the session is short-lived, and `nsmSession()`
  // renews it only when it has aged out.
  const http: NsmHttpLike = {
    async getJson<T>(path: string): Promise<T> {
      await auth.nsmSession()
      return client.getJson<T>(path)
    },
    async postJson<T>(path: string, body: unknown): Promise<T> {
      await auth.nsmSession()
      return client.postJson<T>(path, body)
    },
  }

  for (const def of createNsmToolDefs({ http, auth })) {
    ctx.tools.register(define(def))
  }
}
