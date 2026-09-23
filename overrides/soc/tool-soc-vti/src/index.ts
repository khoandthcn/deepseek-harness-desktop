/**
 * `tool-soc-vti` — a thin Cordis plugin registering the Threat Intelligence tools.
 *
 * All the behaviour lives in `tools.ts`, which is dependency-free and unit
 * tested; this file only wires it to the harness: resolve the account, build
 * the HTTP client with its Basic authorization, then push each definition
 * through `defineTool` onto `ctx.tools`.
 *
 * VTI is a separate platform from the SOC systems, with its own account, so
 * this slice needs no `soc_login` and no SOC session. The email and the API key
 * are read lazily, on the first request rather than at mount, and only from the
 * credentials store or the launch environment — never from settings, and never
 * shown to the model.
 *
 * @module @deepseek-ai/dsh-tool-soc-vti
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { SocHttp } from '@deepseek-ai/dsh-soc-client'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
import { launchEnvironmentOf } from '@deepseek-ai/dsh-launch-environment'
import { createVtiToolDefs, type VtiHttpLike, type VtiToolDef } from './tools.ts'

export * from './tools.ts'

/**
 * The definitions are typed against a local structural mirror of the schema DSL
 * (`tools.ts` imports nothing from `dsh-tools`), so `defineTool`'s per-literal
 * generic inference cannot apply here. Aliasing the function to a concrete,
 * non-generic signature keeps the boundary explicit.
 */
const define = defineTool as unknown as (
  options: VtiToolDef,
) => Parameters<Context['tools']['register']>[0]

export const name = 'tool-soc-vti'

export const inject = ['tools']

/** The credential references the account and the platform are stored under. */
export const VTI_USERNAME_REF = 'VTI_USERNAME'
export const VTI_API_KEY_REF = 'VTI_API_KEY'
export const VTI_DOMAIN_REF = 'VTI_DOMAIN'

/** The vendor's platform, whose API lives on the `api` subdomain of it. */
export const VTI_DEFAULT_DOMAIN = 'ti.example'

/**
 * The API base URL one platform domain implies. The vendor hosts the API on
 * `api.<domain>`, so a deployment names the domain and nothing else.
 * @param domain - the platform domain, with or without a scheme.
 * @returns the base URL to call.
 */
export function vtiBaseUrl(domain: string): string {
  const bare = domain.trim().replace(/^https?:\/\//, '').replace(/\/+$/, '')
  if (bare === '') return `https://api.${VTI_DEFAULT_DOMAIN}`
  return bare.startsWith('api.') ? `https://${bare}` : `https://api.${bare}`
}

export interface Config {
  /** Override the API base URL outright; normally the domain is enough. */
  baseUrl?: string | undefined
  /** The platform domain, e.g. `ti.example`; the API is `api.<domain>`. */
  domain?: string | undefined
  /** Credential reference holding the account email; defaults to `VTI_USERNAME`. */
  usernameRef?: string | undefined
  /** Credential reference holding the API key; defaults to `VTI_API_KEY`. */
  apiKeyRef?: string | undefined
}

/**
 * Read one credential: the credentials store when it is mounted, otherwise the
 * launch environment. Absent is not an error here — the tools report an
 * unconfigured account as a value the model can act on.
 * @param ctx - the plugin context.
 * @param ref - the reference to read.
 * @returns the value, or undefined when no layer holds one.
 */
async function readCredential(ctx: Context, ref: string): Promise<string | undefined> {
  const key = credentialRef(ref)
  const credentials = ctx.get('credentials')
  const value = credentials !== undefined
    ? (await credentials.resolve(key))?.value ?? launchEnvironmentOf(ctx).get(key)?.value
    : launchEnvironmentOf(ctx).get(key)?.value
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined
}

/**
 * Register the Threat Intelligence tool suite on `ctx.tools`.
 * @param ctx - registrant context carrying `tools`.
 * @param config - optional overrides; a preset row for this plugin carries no
 *   config at all, so this arrives as `undefined`.
 */
export function apply(ctx: Context, config: Config = {}): void {
  const usernameRef = config.usernameRef ?? VTI_USERNAME_REF
  const apiKeyRef = config.apiKeyRef ?? VTI_API_KEY_REF

  /**
   * The API host. A row may pin it, otherwise it follows the platform domain
   * this user configured, and failing that the vendor's own. Read per request,
   * like the credentials, so a correction takes effect without a restart.
   */
  let domain: string | undefined
  const baseUrl = (): string => config.baseUrl ?? vtiBaseUrl(domain ?? config.domain ?? '')

  /**
   * The Basic header, once an account is configured. Held here rather than
   * rebuilt per request, and re-read whenever it is missing, so a key typed
   * into Settings takes effect on the next call.
   */
  let authorization: string | undefined
  const ensureAuthorization = async (): Promise<boolean> => {
    if (authorization !== undefined) return true
    const [username, apiKey, configuredDomain] = await Promise.all([
      readCredential(ctx, usernameRef),
      readCredential(ctx, apiKeyRef),
      readCredential(ctx, VTI_DOMAIN_REF),
    ])
    domain = configuredDomain
    if (username === undefined || apiKey === undefined) return false
    authorization = `Basic ${Buffer.from(`${username}:${apiKey}`).toString('base64')}`
    return true
  }

  const client = new SocHttp(baseUrl, {
    authHeaders: () => (authorization === undefined ? {} : { Authorization: authorization }),
  })

  const http: VtiHttpLike = {
    getJson: <T>(path: string): Promise<T> => client.getJson<T>(path),
    postJson: <T>(path: string, body: unknown): Promise<T> => client.postJson<T>(path, body),
  }

  // Every tool asks this first, so the account is resolved before the request
  // that needs it, and a key typed into Settings takes effect on the next call.
  const auth = { ensureConfigured: ensureAuthorization }

  for (const def of createVtiToolDefs({ http, auth })) {
    ctx.tools.register(define(def))
  }
}
