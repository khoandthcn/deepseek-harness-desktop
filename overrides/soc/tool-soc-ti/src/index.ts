/**
 * `tool-soc-ti` — a thin Cordis plugin registering the Threat Intelligence tools.
 *
 * All the behaviour lives in `tools.ts`, which is dependency-free and unit
 * tested; this file only wires it to the harness: resolve the account, build
 * the HTTP client with its Basic authorization, then push each definition
 * through `defineTool` onto `ctx.tools`.
 *
 * TI is a separate platform from the SOC systems, with its own account, so
 * this slice needs no `soc_login` and no SOC session. The email and the API key
 * are read lazily, on the first request rather than at mount, and only from the
 * credentials store or the launch environment — never from settings, and never
 * shown to the model.
 *
 * @module @deepseek-ai/dsh-tool-soc-ti
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { SocHttp } from '@deepseek-ai/dsh-soc-client'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
import { launchEnvironmentOf } from '@deepseek-ai/dsh-launch-environment'
import { createTiToolDefs, type TiHttpLike, type TiToolDef } from './tools.ts'

export * from './tools.ts'

/**
 * The definitions are typed against a local structural mirror of the schema DSL
 * (`tools.ts` imports nothing from `dsh-tools`), so `defineTool`'s per-literal
 * generic inference cannot apply here. Aliasing the function to a concrete,
 * non-generic signature keeps the boundary explicit.
 */
const define = defineTool as unknown as (
  options: TiToolDef,
) => Parameters<Context['tools']['register']>[0]

export const name = 'tool-soc-ti'

export const inject = ['tools']

/** The credential references the account and the platform are stored under. */
export const TI_USERNAME_REF = 'TI_USERNAME'
export const TI_API_KEY_REF = 'TI_API_KEY'
export const TI_DOMAIN_REF = 'TI_DOMAIN'

/**
 * The API base URL one platform domain implies: the platform serves its API on
 * the `api` subdomain, so a deployment names the domain and nothing else. No
 * domain is built in — like the SOC side, this machine says where its platform
 * is, and an unconfigured one is told so rather than pointed somewhere.
 * @param domain - the platform domain, with or without a scheme.
 * @returns the base URL to call, or an empty string when nothing is configured.
 */
export function tiBaseUrl(domain: string): string {
  const bare = domain.trim().replace(/^https?:\/\//, '').replace(/\/+$/, '')
  if (bare === '') return ''
  return bare.startsWith('api.') ? `https://${bare}` : `https://api.${bare}`
}

export interface Config {
  /** Override the API base URL outright; normally the domain is enough. */
  baseUrl?: string | undefined
  /** The platform domain; its API is `api.<domain>`. */
  domain?: string | undefined
  /** Credential reference holding the account email; defaults to `TI_USERNAME`. */
  usernameRef?: string | undefined
  /** Credential reference holding the API key; defaults to `TI_API_KEY`. */
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
  const usernameRef = config.usernameRef ?? TI_USERNAME_REF
  const apiKeyRef = config.apiKeyRef ?? TI_API_KEY_REF

  /**
   * The API host. A row may pin it, otherwise it follows the platform domain
   * this user configured, and failing that the vendor's own. Read per request,
   * like the credentials, so a correction takes effect without a restart.
   */
  let domain: string | undefined
  const baseUrl = (): string => config.baseUrl ?? tiBaseUrl(domain ?? config.domain ?? '')

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
      readCredential(ctx, TI_DOMAIN_REF),
    ])
    domain = configuredDomain
    // Without a platform to reach, an account is not enough to call anything.
    if (username === undefined || apiKey === undefined) return false
    if (baseUrl() === '') return false
    authorization = `Basic ${Buffer.from(`${username}:${apiKey}`).toString('base64')}`
    return true
  }

  const client = new SocHttp(baseUrl, {
    authHeaders: () => (authorization === undefined ? {} : { Authorization: authorization }),
  })

  const http: TiHttpLike = {
    getJson: <T>(path: string): Promise<T> => client.getJson<T>(path),
    postJson: <T>(path: string, body: unknown): Promise<T> => client.postJson<T>(path, body),
  }

  // Every tool asks this first, so the account is resolved before the request
  // that needs it, and a key typed into Settings takes effect on the next call.
  const auth = { ensureConfigured: ensureAuthorization }

  for (const def of createTiToolDefs({ http, auth })) {
    ctx.tools.register(define(def))
  }
}
