/**
 * `soc-auth` — a thin Cordis plugin that exposes a {@link SocAuthService}
 * instance as `ctx.socAuth`.
 *
 * All cordis imports are **type-only**, so nothing from `@deepseek-ai/*` is
 * required at runtime and `service.ts` stays unit-testable on its own.
 */

import type { Context } from '@deepseek-ai/cordis'
import { SocAuthService } from './service.ts'

export * from './wso2.ts'
export * from './service.ts'

export const name = 'soc-auth'

/**
 * Nothing is strictly required: credentials come from `ctx.credentials` when
 * that service is present and from the environment otherwise, so the plugin must
 * be able to load without it.
 */
export const inject: string[] = []

export interface Config {
  /** Base URL of the WSO2 IAM server, e.g. `https://iam.example`. */
  iamUrl: string
  clientId: string
  redirectUri: string
  /** Base URL of the SOAR API, e.g. `https://soar.example`. */
  soarBaseUrl: string
  /** SOAR tenant; defaults to `MASTER`. */
  tenant?: string | undefined
  /** SOAR OAuth client id used by the access exchange; defaults to `SOAR_CLIENT`. */
  soarClientId?: string | undefined
  /**
   * Credential *references*, never the values themselves: the name of the entry
   * to read from `ctx.credentials`, falling back to the environment variable of
   * the same name. Default to `SOC_USERNAME` / `SOC_PASSWORD`.
   */
  usernameRef?: string | undefined
  passwordRef?: string | undefined
}

declare module '@deepseek-ai/cordis' {
  interface Context {
    socAuth: SocAuthService
  }
}

/** Minimal shape we rely on when the optional `credentials` service exists. */
interface CredentialsLike {
  get?: (ref: string) => string | undefined
}

/** `process` is typed locally so the package needs no `@types/node` dependency. */
declare const process: { env: Record<string, string | undefined> } | undefined

/**
 * Resolve a credential by reference: `ctx.credentials.get(ref)` when the
 * credentials service is installed, otherwise `process.env[ref]`. The value is
 * only ever handed to {@link SocAuthService}; it is never logged, never stored in
 * settings, and never shown to the model.
 */
export function resolveCredential(ctx: Context, ref: string): string {
  const credentials = (ctx as unknown as { credentials?: CredentialsLike }).credentials
  const fromService = typeof credentials?.get === 'function' ? credentials.get(ref) : undefined
  const value = fromService ?? (typeof process !== 'undefined' ? process?.env?.[ref] : undefined)
  if (!value) {
    throw new Error(
      `soc-auth: credential "${ref}" is not set — add it to the credentials store or export it in the environment.`,
    )
  }
  return value
}

export function apply(ctx: Context, config: Config): void {
  const usernameRef = config.usernameRef ?? 'SOC_USERNAME'
  const passwordRef = config.passwordRef ?? 'SOC_PASSWORD'

  const service = new SocAuthService({
    iamUrl: config.iamUrl,
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    soarBaseUrl: config.soarBaseUrl,
    tenant: config.tenant,
    soarClientId: config.soarClientId,
    username: resolveCredential(ctx, usernameRef),
    password: resolveCredential(ctx, passwordRef),
  })

  ctx.provide('socAuth', service)
}
