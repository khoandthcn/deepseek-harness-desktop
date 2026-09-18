/**
 * Model-facing SIEM tool definitions.
 *
 * Mirrors the EDR slice's `tools.ts`, and is likewise **dependency-free**: it
 * imports nothing from `@deepseek-ai/*`, so the whole tool surface is
 * unit-testable standalone. `index.ts` is the thin Cordis wrapper that feeds
 * each definition through `defineTool` and registers it.
 *
 * This slice is **best-effort and read-only**. SIEM's flow is only PARTIALLY
 * known: it has its own OAuth authorization server, and the one capture we have
 * of the token exchange 401'd, so neither the success response shape nor the API
 * credential carrier is confirmed. We therefore ship a single PROBE tool whose
 * job is to make a live run tell us exactly where SIEM auth breaks. SIEM reuses
 * the SOC session that `soc_login` (from `tool-soc-soar`) establishes, so no
 * login tool is defined here.
 *
 * NOTE: search tools are intentionally NOT defined — none of the SIEM search
 * shapes are known yet. They are pending a successful SIEM capture; once auth is
 * proven via `siem_check_access` and a search request is captured, add them here.
 */

/**
 * The auth surface the tools need: the session check plus the management client
 * id the probe sends. Declared structurally on purpose — the real implementation
 * is `SocAuthService` in the sibling `soc-auth` package, which this package must
 * not import.
 */
export interface SiemAuthLike {
  isAuthenticated(): boolean
  readonly siemMgmtClientId: string
}

/** The slice of soc-client's `SocHttp` this tool needs. */
export interface SiemHttpLike {
  postJson<T = unknown>(path: string, body: unknown): Promise<T>
}

/**
 * A local mirror of the harness's parameter-schema DSL, kept structural so this
 * module stays free of `@deepseek-ai/dsh-tools`.
 */
export interface ToolParamSpec {
  type: 'string' | 'number' | 'integer' | 'boolean' | 'array' | 'object' | 'json'
  required?: true | undefined
  description?: string | undefined
  enum?: readonly string[] | undefined
  items?: ToolParamSpec | undefined
  properties?: Record<string, ToolParamSpec> | undefined
  additionalProperties?: boolean | undefined
}

/** A plain tool definition, shaped for `defineTool` but independent of it. */
export interface SiemToolDef {
  name: string
  description: string
  parameters: Record<string, ToolParamSpec>
  output: {
    schema: { type: 'json' }
    render: (args: unknown, value: unknown) => { type: 'text'; text: string }[]
  }
  execute: (args: Record<string, any>, exec?: unknown) => Promise<unknown>
}

export interface CreateSiemToolDefsOptions {
  http: SiemHttpLike
  auth: SiemAuthLike
}

/**
 * Returned instead of throwing when no SOC session exists, so the model reads a
 * value it can act on (ask the user for an OTP) rather than an error trace. Same
 * shape as the EDR slice's.
 */
export const NOT_AUTHENTICATED = {
  error: 'not_authenticated',
  message:
    'Not logged in to the SOC platform. Ask the user for their current OTP, then call soc_login with it.',
} as const

/** SIEM API paths, read from the SIEM SPA. */
export const SIEM_PATHS = {
  userRolePerm: '/oauth/management/get_user_role_perm',
} as const

/**
 * The SIEM token each path needs. SIEM's OAuth server issues one token per API
 * group (audience) and scope; this mirrors its SPA's per-API TokenManager
 * configuration, where `/oauth/management/get_user_role_perm` sits under the
 * `gatekeeper` audience with scope `login`.
 */
export const SIEM_TOKEN_FOR: Readonly<Record<string, { audience: string, scope: string }>> = {
  [SIEM_PATHS.userRolePerm]: { audience: 'gatekeeper', scope: 'login' },
}

/** Raised when the SIEM permission payload does not match the expected shape. */
export class SiemContractError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SiemContractError'
  }
}

/** The parsed permission check: the count and the list of granted func names. */
export interface SiemAccessResult {
  count: number
  data: string[]
}

function describe(data: unknown): string {
  if (data === null) return 'null'
  return Array.isArray(data) ? 'an array' : typeof data
}

/**
 * Parse the `get_user_role_perm` response defensively. The observed shape is
 * `{ count, data: [<func>, ...] }`, but as SIEM's responses are only partially
 * known, tolerate a missing `count` (fall back to the array length) and coerce
 * each granted entry to a string.
 * @param payload - the raw upstream JSON.
 */
export function parseSiemAccess(payload: unknown): SiemAccessResult {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new SiemContractError(`Expected a SIEM access object, got ${describe(payload)}`)
  }
  const obj = payload as Record<string, unknown>
  const rawData = obj.data ?? []
  if (!Array.isArray(rawData)) {
    throw new SiemContractError('SIEM access `data` must be an array')
  }
  const data = rawData.map((entry) => String(entry))
  const count = typeof obj.count === 'number' ? obj.count : data.length
  return { count, data }
}

/** Render the JSON value as text; the harness shows this in the tool card. */
function renderJson(_args: unknown, value: unknown): { type: 'text'; text: string }[] {
  return [{ type: 'text', text: JSON.stringify(value) }]
}

/** The probe returns upstream JSON, so the output schema is open. */
const JSON_OUTPUT = {
  schema: { type: 'json' },
  render: renderJson,
} as const

/**
 * Build the SIEM tool definitions — currently a single access probe.
 * @param options - the SIEM HTTP client and the SOC auth service to drive.
 * @returns plain definitions, ready for `defineTool`.
 */
export function createSiemToolDefs({ http, auth }: CreateSiemToolDefsOptions): SiemToolDef[] {
  /**
   * Wrap a tool so it fails closed: with no SOC session it returns the structured
   * not-authenticated value and never touches the network.
   */
  function guarded(
    run: (args: Record<string, any>) => Promise<unknown>,
  ): (args: Record<string, any>) => Promise<unknown> {
    return async (args) => {
      if (!auth.isAuthenticated()) return { ...NOT_AUTHENTICATED }
      return run(args)
    }
  }

  return [
    {
      name: 'siem_check_access',
      description:
        'Probe SIEM authentication and report the account\'s SIEM permissions. It POSTs to the SIEM'
        + ' permission endpoint and returns the granted function names ({count, data}). Use it to'
        + ' confirm that SIEM auth works for the logged-in account and to see what it is allowed to do.'
        + ' This is the only SIEM tool for now: SIEM search tools are pending a successful SIEM capture.',
      parameters: {},
      output: JSON_OUTPUT,
      execute: guarded(async () => {
        const raw = await http.postJson(SIEM_PATHS.userRolePerm, { client_id: auth.siemMgmtClientId })
        return parseSiemAccess(raw)
      }),
    },
  ]
}
