/**
 * Where the deployment's endpoints come from, and how they are merged.
 *
 * They are deliberately NOT baked into the build. An installer that carried
 * them would name the customer's internal systems to anyone who has the file,
 * and every deployment would need its own build. Instead each machine supplies
 * them, and one build serves every deployment.
 *
 * Four sources, later ones winning:
 *  1. `soc-endpoints.json` in the dsh home (`~/.dsh` unless `DSH_HOME` says
 *     otherwise) — the file an administrator hands out.
 *  2. Environment variables (`SOC_IAM_URL`, `SOC_SOAR_BASE_URL`, …) — for a
 *     machine that is configured by its launch environment.
 *  3. The SOC Cloud card in Settings — what this user typed, which is how
 *     someone who installed a public build configures their own deployment.
 *  4. The preset row's own `config:` block — for a deployment that does pin
 *     them, and for tests.
 *
 * Kept free of `@deepseek-ai/*` imports so it can be unit tested on its own.
 *
 * @module @deepseek-ai/dsh-soc-auth/endpoints
 */

import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/** One endpoint field: how it is named in the file, the environment, and here. */
interface EndpointField {
  readonly key: string
  readonly env: string
  /** False for a field a deployment may leave unset. */
  readonly required: boolean
}

/**
 * The platform hosts one system per subdomain of one root: `iam` signs in,
 * `soc` is the portal every system calls back to, and the rest are the systems
 * themselves. One domain therefore configures the whole deployment, and the
 * per-system URLs below exist only for a deployment that departs from it.
 */
export const SOC_SUBDOMAINS: Readonly<Record<string, string>> = {
  iamUrl: 'iam',
  redirectUri: 'soc',
  soarBaseUrl: 'soar',
  edrBaseUrl: 'edr',
  siemBaseUrl: 'siem',
  nsmBaseUrl: 'nsm',
}

/** Every endpoint field soc-auth understands, in the order errors list them. */
export const ENDPOINT_FIELDS: readonly EndpointField[] = [
  { key: 'socDomain', env: 'SOC_DOMAIN', required: true },
  { key: 'clientId', env: 'SOC_CLIENT_ID', required: false },
  { key: 'iamUrl', env: 'SOC_IAM_URL', required: false },
  { key: 'redirectUri', env: 'SOC_REDIRECT_URI', required: false },
  { key: 'soarBaseUrl', env: 'SOC_SOAR_BASE_URL', required: false },
  { key: 'tenant', env: 'SOC_TENANT', required: false },
  { key: 'soarClientId', env: 'SOC_SOAR_CLIENT_ID', required: false },
  { key: 'edrBaseUrl', env: 'SOC_EDR_BASE_URL', required: false },
  { key: 'edrClientId', env: 'SOC_EDR_CLIENT_ID', required: false },
  { key: 'siemBaseUrl', env: 'SOC_SIEM_BASE_URL', required: false },
  { key: 'siemClientId', env: 'SOC_SIEM_CLIENT_ID', required: false },
  { key: 'nsmBaseUrl', env: 'SOC_NSM_BASE_URL', required: false },
  { key: 'nsmClientId', env: 'SOC_NSM_CLIENT_ID', required: false },
]

/**
 * Fill in every per-system URL a domain implies, leaving anything already set
 * alone: an explicit URL always wins over the convention.
 * @param values - what the sources supplied.
 * @returns the same values with the derived URLs added.
 */
export function deriveFromDomain(values: Record<string, string>): Record<string, string> {
  const domain = values.socDomain?.replace(/^https?:\/\//, '').replace(/\/+$/, '')
  if (domain === undefined || domain === '') return values
  const derived: Record<string, string> = { ...values }
  for (const [key, subdomain] of Object.entries(SOC_SUBDOMAINS)) {
    if (derived[key] === undefined) derived[key] = `https://${subdomain}.${domain}`
  }
  return derived
}

/** The file an administrator drops next to the profile. */
export const ENDPOINTS_FILE = 'soc-endpoints.json'

/** A resolved endpoint set, plus what is still missing and where it came from. */
export interface ResolvedEndpoints {
  readonly values: Record<string, string>
  /** Required keys that no source supplied; empty when the deployment is usable. */
  readonly missing: string[]
  /** The file path consulted, named in the error so a user can act on it. */
  readonly filePath: string
}

/** The dsh home directory this machine uses. */
export function dshHome(env: NodeJS.ProcessEnv = process.env, home = homedir()): string {
  const configured = env.DSH_HOME?.trim()
  return configured !== undefined && configured !== '' ? configured : join(home, '.dsh')
}

/**
 * Read the endpoints file, if there is one.
 * @param path - the file to read.
 * @returns its string fields, or an empty object when it is absent.
 * @throws when the file exists but is not a JSON object, since a typo there
 *   would otherwise look like an unconfigured machine.
 */
function readFile(path: string): Record<string, string> {
  if (!existsSync(path)) return {}
  let parsed: unknown
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'))
  } catch (cause) {
    throw new Error(`soc-auth: ${path} is not valid JSON.`, { cause })
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`soc-auth: ${path} must hold a JSON object of endpoint settings.`)
  }
  return stringsOf(parsed as Record<string, unknown>)
}

/** Keep the non-blank string fields, so a null or a number cannot pass as a URL. */
function stringsOf(source: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const { key } of ENDPOINT_FIELDS) {
    const value = source[key]
    if (typeof value === 'string' && value.trim() !== '') out[key] = value.trim()
  }
  return out
}

/**
 * Merge the three sources and report what a deployment still owes.
 * @param opts - the preset row's config, the environment, and the home override.
 * @returns the merged values, the missing required keys, and the file consulted.
 */
export function resolveEndpoints(opts: {
  config?: Record<string, unknown> | undefined
  settings?: Record<string, unknown> | undefined
  env?: NodeJS.ProcessEnv | undefined
  home?: string | undefined
} = {}): ResolvedEndpoints {
  const env = opts.env ?? process.env
  const filePath = join(opts.home ?? dshHome(env), ENDPOINTS_FILE)
  const fromEnv: Record<string, string> = {}
  for (const { key, env: name } of ENDPOINT_FIELDS) {
    const value = env[name]?.trim()
    if (value !== undefined && value !== '') fromEnv[key] = value
  }
  const values = deriveFromDomain({
    ...readFile(filePath),
    ...fromEnv,
    ...stringsOf(opts.settings ?? {}),
    ...stringsOf(opts.config ?? {}),
  })
  // The domain is what a deployment normally sets, but one that pins every URL
  // by hand owes no domain: what must hold is that sign-in has somewhere to go.
  const SIGN_IN_KEYS = ['iamUrl', 'redirectUri', 'soarBaseUrl']
  const missing = SIGN_IN_KEYS.every(key => values[key] !== undefined)
    ? []
    : ENDPOINT_FIELDS.filter(field => field.required && values[field.key] === undefined).map(field => field.key)
  return { values, missing, filePath }
}

/**
 * The message a user can act on when endpoints are missing. Names the file to
 * write and the keys it needs, never a value.
 * @param resolved - the resolution that came up short.
 * @returns the sentence to throw.
 */
export function missingEndpointsMessage(resolved: ResolvedEndpoints): string {
  const envNames = ENDPOINT_FIELDS
    .filter(field => resolved.missing.includes(field.key))
    .map(field => field.env)
  return `SOC endpoints are not configured: ${resolved.missing.join(', ')} ${
    resolved.missing.length === 1 ? 'is' : 'are'} unset. `
    + 'Fill that in under Settings → Plugins → SOC Cloud — the platform domain alone configures every '
    + 'system, e.g. "soc.example.com" — '
    + `or write it into ${resolved.filePath} (a JSON object), `
    + `or set ${envNames.join(', ')} in the environment.`
}
