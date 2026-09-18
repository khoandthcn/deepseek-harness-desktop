/**
 * `soc-auth` — a thin Cordis plugin that exposes a {@link SocAuthService}
 * instance as `ctx.socAuth`.
 *
 * Credentials are read *lazily*, at login time rather than at mount time: the
 * credentials seam is asynchronous, and a plugin that reads a secret just to sit
 * idle has held it for no reason. `ctx.get('credentials')` is how a plugin may
 * consult an optional service — reading `ctx.credentials` directly throws unless
 * the service is declared in `inject`, which would make the whole plugin wait
 * for a store that need not exist.
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { credentialRef } from '@deepseek-ai/dsh-credentials'
import { launchEnvironmentOf } from '@deepseek-ai/dsh-launch-environment'
import type {} from '@deepseek-ai/dsh-settings'
import { requireConfig } from './config.ts'
import { SocAuthService } from './service.ts'

export * from './config.ts'
export * from './wso2.ts'
export * from './service.ts'

export const name = 'soc-auth'

/**
 * The settings namespace the SOC credentials card is keyed to. The card carries
 * no editable settings — the username and password go through the credentials
 * domain, not this section — but the Plugins configuration tab only dispatches a
 * card whose namespace the Host serves, so this section must exist for the card
 * to appear. Its schema is therefore empty.
 */
export const SOC_CREDENTIALS_NS = 'soc-credentials'
const SocCredentialsSection = z.object({})

/**
 * Nothing is strictly required: credentials come from `ctx.credentials` when
 * that service is present and from the launch environment otherwise, so the
 * plugin must be able to load without it.
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
  /** Base URL of the EDR API; defaults to `https://edr.example.com`. */
  edrBaseUrl?: string | undefined
  /** EDR OAuth client id used by its authorize; defaults to `EDR`. */
  edrClientId?: string | undefined
  /** EDR OIDC callback URL; defaults to `${edrBaseUrl}/v2/callback`. */
  edrRedirectUri?: string | undefined
  /** Base URL of the SIEM API; defaults to `https://siem.example.com`. */
  siemBaseUrl?: string | undefined
  /** SIEM OAuth client id used by its own authorize/token; defaults to `cym_portal`. */
  siemClientId?: string | undefined
  /** SIEM management client id sent by probe tools; defaults to `cym_api`. */
  siemMgmtClientId?: string | undefined
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

/**
 * Resolve one credential by reference: the credentials store when it is
 * mounted, otherwise the environment this run was launched with. The value goes
 * straight to {@link SocAuthService}; it is never logged, never written to
 * settings, and never shown to the model.
 *
 * @param ctx - the plugin context.
 * @param ref - the environment-variable-shaped reference to read.
 * @returns the secret.
 * @throws when neither layer holds a value.
 */
export async function resolveCredential(ctx: Context, ref: string): Promise<string> {
  const key = credentialRef(ref)
  const credentials = ctx.get('credentials')
  const value = credentials !== undefined
    ? (await credentials.resolve(key))?.value ?? launchEnvironmentOf(ctx).get(key)?.value
    : launchEnvironmentOf(ctx).get(key)?.value
  if (!value) {
    throw new Error(
      `soc-auth: credential "${ref}" is not set — add it to the credentials store or export it in the environment.`,
    )
  }
  return value
}

export function apply(ctx: Context, config: Config | undefined): void {
  // A row with no `config:` block arrives as undefined; say so plainly.
  const checked = requireConfig(config)
  const usernameRef = checked.usernameRef ?? 'SOC_USERNAME'
  const passwordRef = checked.passwordRef ?? 'SOC_PASSWORD'

  const service = new SocAuthService({
    iamUrl: checked.iamUrl,
    clientId: checked.clientId,
    redirectUri: checked.redirectUri,
    soarBaseUrl: checked.soarBaseUrl,
    tenant: checked.tenant,
    soarClientId: checked.soarClientId,
    edrBaseUrl: checked.edrBaseUrl,
    edrClientId: checked.edrClientId,
    edrRedirectUri: checked.edrRedirectUri,
    siemBaseUrl: checked.siemBaseUrl,
    siemClientId: checked.siemClientId,
    siemMgmtClientId: checked.siemMgmtClientId,
    credentials: async () => ({
      username: await resolveCredential(ctx, usernameRef),
      password: await resolveCredential(ctx, passwordRef),
    }),
  })

  ctx.provide('socAuth', service)

  // Publish the (empty) settings section the credentials card is keyed to, so
  // the Plugins configuration tab lists and renders the card. `settings` is a
  // Host service; if the deployment has none, the card simply does not appear.
  ctx.inject(['settings'], (settingsCtx) => {
    settingsCtx.settings.installSection(ctx, SOC_CREDENTIALS_NS, SocCredentialsSection, {}, {
      setSource: () => {},
      onChange: () => {},
    })
  })
}
