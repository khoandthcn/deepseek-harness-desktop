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
import { resolveEndpoints } from './endpoints.ts'
import { SocAuthService } from './service.ts'

export * from './endpoints.ts'
export * from './wso2.ts'
export * from './service.ts'

export const name = 'soc-auth'

/**
 * The settings namespace the SOC Cloud card is keyed to. The card's values do
 * not live here — the username, the password and the endpoints all go through
 * the credentials domain — but the Plugins configuration tab only dispatches a
 * card whose namespace the Host serves, so this section must exist for the card
 * to appear at all.
 */
export const SOC_CREDENTIALS_NS = 'soc-credentials'

/**
 * The settings namespace the Threat Intelligence card is keyed to. That
 * platform is a separate account on a separate host, so it gets a card of its
 * own rather than a second half of the SOC one. Published here, from the Host,
 * for the same reason the SOC section is: the plugin that uses it runs only
 * inside a session, and the card has to exist before the first sign-in.
 */
export const SOC_TI_NS = 'soc-threat-intel'
/**
 * The settings section behind the SOC Cloud card. The username and password are
 * NOT here — they go through the credentials domain, so their literals never
 * ride a response. The endpoints do: they are configuration, not secrets, and a
 * user who installed a public build has to be able to type them in.
 */
const SocCredentialsSection = z.object({
  socDomain: z.string().default(''),
  socClientId: z.string().default(''),
  socUsername: z.string().default(''),
})

/** The settings section behind the Threat Intelligence card. */
const SocThreatIntelSection = z.object({
  tiDomain: z.string().default(''),
  tiUsername: z.string().default(''),
})

/**
 * The endpoint fields the SOC Cloud card writes, in the order it renders them,
 * each stored under the credential reference of the same shape as the username
 * and password. They are configuration rather than secrets, but that store is
 * the one the card can write to, and it keeps every SOC setting in one place.
 *
 * Two fields, not one per system: the platform hosts each system on a
 * subdomain of one root, so the domain configures all of them (see
 * `deriveFromDomain`). The client id cannot be derived — it is the identifier
 * the platform issued for this app — and a public build carries no platform's,
 * so the card is where a user supplies it. A deployment that departs from the
 * subdomain convention pins the odd URL in `soc-endpoints.json` or in its
 * preset row instead.
 */
export const SOC_ENDPOINT_FIELDS = [
  'socDomain',
  'clientId',
] as const

/**
 * The credential reference one endpoint field is stored under, e.g.
 * `iamUrl` → `SOC_IAM_URL`.
 * @param field - the endpoint field name.
 * @returns the reference to read or write.
 */
export function endpointRef(field: string): string {
  return `SOC_${field.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase()}`
}

/**
 * Nothing is strictly required: credentials come from `ctx.credentials` when
 * that service is present and from the launch environment otherwise, so the
 * plugin must be able to load without it.
 */
export const inject: string[] = []

/**
 * A preset row's `config:` block. Every endpoint is optional here: a machine
 * normally supplies them through `soc-endpoints.json` or the environment (see
 * `endpoints.ts`), and a row only pins what a particular deployment must fix.
 */
export interface Config {
  /**
   * The platform's root domain, e.g. `soc.example.com`. Every system's URL is
   * derived from it; the per-system fields below only pin an exception.
   */
  socDomain?: string | undefined
  /**
   * The OAuth client the platform registered for its portal. IAM identifies the
   * application by it and refuses an authorize without one. It is fixed per
   * platform and nobody changes it per user, so it is configured in
   * `soc-endpoints.json` or the preset row rather than on a settings card.
   */
  /** Base URL of the WSO2 IAM server, e.g. `https://iam.example`. */
  iamUrl?: string | undefined
  clientId?: string | undefined
  redirectUri?: string | undefined
  /** Base URL of the SOAR API, e.g. `https://soar.example`. */
  soarBaseUrl?: string | undefined
  /**
   * Tenant the SOAR tools query. Defaults to `MASTER`, the account's own
   * top-level tenant, which already covers every tenant below it that the
   * account may see; a deployment scoped to one sub-tenant names it here.
   */
  tenant?: string | undefined
  /** SOAR OAuth client id used by its authorize; defaults to `clientId`. */
  soarClientId?: string | undefined
  /** Base URL of the EDR API, e.g. `https://edr.example`. */
  edrBaseUrl?: string | undefined
  /** EDR OAuth client id used by its authorize; defaults to `EDR`. */
  edrClientId?: string | undefined
  /** EDR OIDC callback URL; defaults to `${edrBaseUrl}/v2/callback`. */
  edrRedirectUri?: string | undefined
  /** Base URL of the SIEM API, e.g. `https://siem.example`. */
  siemBaseUrl?: string | undefined
  /** SIEM OAuth client id used by its own authorize/token; defaults to `cym_portal`. */
  siemClientId?: string | undefined
  /** SIEM management client id sent by probe tools; defaults to `cym_api`. */
  siemMgmtClientId?: string | undefined
  /** Base URL of the NSM (NDR) API, e.g. `https://nsm.example`. */
  nsmBaseUrl?: string | undefined
  /** NSM OIDC client id; defaults to `NSM`. */
  nsmClientId?: string | undefined
  /** NSM OIDC callback URL; defaults to `${nsmBaseUrl}/callback`. */
  nsmRedirectUri?: string | undefined
  /**
   * Credential *references*, never the values themselves: the name of the entry
   * to read from `ctx.credentials`, falling back to the environment variable of
   * the same name. Default to `SOC_USERNAME` / `SOC_PASSWORD`.
   */
  usernameRef?: string | undefined
  passwordRef?: string | undefined
  /**
   * Install the settings section and nothing else: no service, no session.
   *
   * The SOC Cloud card in Settings is dispatched by namespace, and the Host
   * lists a namespace only while something serves it. This plugin normally runs
   * inside the soc-cloud preset, i.e. only once a session mounts it — which
   * leaves a fresh install with nowhere to type the endpoints the first login
   * needs. Mounted this way at Host level, the card is there from the start.
   */
  settingsOnly?: boolean | undefined
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
  const row = config ?? {}
  // The card's namespace, served whether or not this row runs a session.
  installSocSection(ctx)
  if (row.settingsOnly === true) return
  const usernameRef = row.usernameRef ?? 'SOC_USERNAME'
  const passwordRef = row.passwordRef ?? 'SOC_PASSWORD'
  // The endpoints are not built in: this machine supplies them, from its own
  // file or environment, and a preset row may still pin them. Mounting must
  // succeed without them — `soc_login` is where an unconfigured machine is told
  // what to write, because that is when a user is present to act on it.
  const service = new SocAuthService({
    // Resolved per login: the machine's file and environment, what the user
    // typed in Settings, and finally anything this preset row pins.
    endpoints: () => resolveEndpoints({ config: row as Record<string, unknown> }),
    // What the user typed into Settings → Plugins → SOC Cloud. Read at login,
    // so a correction takes effect on the next sign-in without a restart.
    endpointOverrides: async () => {
      const credentials = ctx.get('credentials')
      const env = launchEnvironmentOf(ctx)
      const out: Record<string, string> = {}
      // The credentials store first: it is where earlier builds kept these,
      // and where a machine configured by its launch environment still keeps
      // them. What the user typed in Settings then wins over both.
      for (const field of SOC_ENDPOINT_FIELDS) {
        const key = credentialRef(endpointRef(field))
        const value = credentials !== undefined
          ? (await credentials.resolve(key))?.value ?? env.get(key)?.value
          : env.get(key)?.value
        if (typeof value === 'string' && value.trim() !== '') out[field] = value.trim()
      }
      return { ...out, ...socEndpointSettings(ctx) }
    },
    edrRedirectUri: row.edrRedirectUri,
    siemMgmtClientId: row.siemMgmtClientId,
    nsmRedirectUri: row.nsmRedirectUri,
    credentials: async () => ({
      // The name is configuration, so the card keeps it in the section; the
      // reference still answers for a machine configured the older way.
      username: readSection(ctx, SOC_CREDENTIALS_NS).socUsername ?? await resolveCredential(ctx, usernameRef),
      password: await resolveCredential(ctx, passwordRef),
    }),
  })

  // The Threat Intelligence tools read their own card's section through the
  // service, because the section is installed here — one plugin owns it, and
  // the card must exist even where no session mounted those tools.
  service.threatIntelSettings = () => {
    const section = readSection(ctx, SOC_TI_NS)
    return { tiDomain: section.tiDomain ?? '', tiUsername: section.tiUsername ?? '' }
  }
  ctx.provide('socAuth', service)
}

/**
 * Read one card's settings section, whichever row installed it.
 *
 * This plugin mounts twice: once on the Host, so the two cards exist before
 * any session, and once inside the preset that runs the tools. A namespace may
 * only be registered once, so the second mount cannot hold a source thunk of
 * its own — it reads the registry instead, which answers for whoever owns the
 * namespace and always with the current value.
 *
 * @param ctx - the mounting context.
 * @param ns - the card's namespace.
 * @returns the section's non-blank string fields, trimmed.
 */
export function readSection(ctx: Context, ns: string): Record<string, string> {
  const settings = ctx.get('settings')
  const section = settings?.get(ns as never)
  if (typeof section !== 'object' || section === null) return {}
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(section as Record<string, unknown>)) {
    // A blank control must fall through to whatever else supplies the field,
    // rather than masking the machine's file or environment with an empty
    // string.
    if (typeof value === 'string' && value.trim() !== '') out[key] = value.trim()
  }
  return out
}

/**
 * The SOC card's section as endpoint fields. The card names its controls after
 * the platform; sign-in knows one of them by another name.
 * @param ctx - the mounting context.
 * @returns the endpoint fields the user typed.
 */
export function socEndpointSettings(ctx: Context): Record<string, string> {
  const section = readSection(ctx, SOC_CREDENTIALS_NS)
  const out: Record<string, string> = {}
  if (section.socDomain !== undefined) out.socDomain = section.socDomain
  if (section.socClientId !== undefined) out.clientId = section.socClientId
  return out
}

/**
 * Publish the settings section the SOC Cloud card is keyed to. `settings` is a
 * Host service; where the deployment has none, the card simply does not appear.
 * Installing it twice throws, and this plugin does mount twice — on the Host
 * for the cards, and inside the preset for the tools — so the second mount
 * lets the first keep the namespace and reads it through {@link readSection}.
 * @param ctx - the mounting context.
 */
function installSocSection(ctx: Context): void {
  ctx.inject(['settings'], (settingsCtx) => {
    install(settingsCtx, SOC_CREDENTIALS_NS, SocCredentialsSection, {
      socDomain: '',
      socClientId: '',
      socUsername: '',
    })
    install(settingsCtx, SOC_TI_NS, SocThreatIntelSection, {
      tiDomain: '',
      tiUsername: '',
    })
  })

  /**
   * Install one section unless another mount of this plugin already holds the
   * namespace. The registry throws on a second registration, and the throw is
   * the whole failure mode worth guarding: it aborts this mount's remaining
   * setup, which is how the tools ended up unable to read their own settings.
   * @param settingsCtx - the context with `settings` resolved.
   * @param ns - the namespace to install.
   * @param schema - the section's schema.
   * @param entry - the composition entry, all fields blank.
   */
  function install<T>(
    settingsCtx: { settings: { installSection: (...args: never[]) => void, get: (ns: never) => unknown } },
    ns: string,
    schema: unknown,
    entry: T,
  ): void {
    if (settingsCtx.settings.get(ns as never) !== undefined) return
    settingsCtx.settings.installSection(
      ...([ctx, ns, schema, entry, { setSource: () => {}, onChange: () => {} }] as never[]),
    )
  }
}
