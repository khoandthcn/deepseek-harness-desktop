/**
 * Model-facing Threat Intelligence (VTI) tool definitions.
 *
 * Mirrors the other SOC slices, and is likewise **dependency-free**: it imports
 * nothing from `@deepseek-ai/*`, so the whole tool surface is unit-testable
 * standalone. `index.ts` is the thin Cordis wrapper that feeds each definition
 * through `defineTool` and registers it.
 *
 * Every request and response shape here is from the vendor's published API
 * guide (version 1.8.1). The slice is **read-only**: it searches the customer's
 * alerts and looks indicators up, and never marks, exports or edits anything.
 *
 * Unlike the other slices, VTI is not reached through the SOC session: it is a
 * separate platform with its own account, authenticated with HTTP Basic (the
 * account email and an API key), so this slice carries its own credentials and
 * needs no `soc_login`.
 *
 * @module
 */

/**
 * The credential surface the tools need. Asynchronous because resolving the
 * account may have to ask the credentials store, and a tool that guessed while
 * that was in flight would report "not configured" for a configured account.
 */
export interface VtiAuthLike {
  ensureConfigured(): Promise<boolean>
}

/** The slice of soc-client's `SocHttp` these tools need. */
export interface VtiHttpLike {
  getJson<T = unknown>(path: string): Promise<T>
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
export interface VtiToolDef {
  name: string
  description: string
  parameters: Record<string, ToolParamSpec>
  output: {
    schema: { type: 'json' }
    render: (args: unknown, value: unknown) => { type: 'text'; text: string }[]
  }
  execute: (args: Record<string, any>, exec?: unknown) => Promise<unknown>
}

export interface CreateVtiToolDefsOptions {
  http: VtiHttpLike
  auth: VtiAuthLike
  /** Clock seam, so the default time window is testable. Defaults to `Date.now`. */
  now?: (() => number) | undefined
}

/**
 * Returned instead of throwing when no VTI account is configured, so the model
 * reads a value it can act on rather than an error trace.
 */
export const NOT_CONFIGURED = {
  error: 'not_configured',
  message:
    'No Threat Intelligence account is configured. Ask the user to fill in the VTI account email and '
    + 'API key under Settings → Plugins → SOC Cloud; the key comes from the platform\'s account page.',
} as const

/** VTI API paths, from the vendor's API guide. */
export const VTI_PATHS = {
  compromisedSystem: '/discovery-service/api/v1/compromised_system',
  portAnomaly: '/discovery-service/api/v1/port_anomaly',
  threatReport: '/discovery-service/api/v1/threat_report',
  cve: '/discovery-service/api/v1/cve',
  dataLeak: '/discovery-service/api/v1/data_leak',
  impersonate: '/discovery-service/api/v1/impersonate',
  phishing: '/discovery-service/api/v1/phishing',
  easmAsset: '/discovery-service/api/v1/easm_asset/asset',
  easmIssue: '/discovery-service/api/v1/easm_issue/issues',
  threatLookup: '/discovery-service/api/v1/threat_lookup',
  dataBreach: '/discovery-service/api/v1/data_breach',
  ccleak: '/discovery-service/api/v1/ccleak/search',
} as const

/** The detail endpoints, which take an id in the path. */
export const VTI_DETAIL_PATHS = {
  threatReport: (code: string) => `/discovery-service/api/v1/threat_report/${encodeURIComponent(code)}`,
  dataBreach: (code: string) => `/discovery-service/api/v1/data_breach/${encodeURIComponent(code)}`,
  ccleak: (id: string) => `/discovery-service/api/v1/ccleak/${encodeURIComponent(id)}`,
} as const

/** Page sizes the API accepts: 20 by default, 100 at most. */
export const VTI_DEFAULT_SIZE = 20
export const VTI_MAX_SIZE = 100
/** Default window when the caller gives no time range: 30 days. */
export const VTI_DEFAULT_WINDOW_SECONDS = 30 * 24 * 3600

/** Severity as the platform numbers it, for the tool descriptions. */
export const VTI_SEVERITY = '4 critical, 3 high, 2 medium, 1 low, 0 unknown'

/** Raised when a VTI payload does not match the documented shape. */
export class VtiContractError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VtiContractError'
  }
}

function describe(data: unknown): string {
  if (data === null) return 'null'
  return Array.isArray(data) ? 'an array' : typeof data
}

/** The window a search covers, in epoch milliseconds. */
export interface VtiWindow {
  from: number
  to: number
}

/**
 * Resolve the search window. Explicit epoch-millisecond bounds win; otherwise
 * the window ends now and runs back `last_seconds` (default 30 days, because
 * threat intelligence arrives far more slowly than telemetry).
 * @param args - the tool arguments.
 * @param now - current epoch milliseconds.
 */
export function resolveWindow(args: Record<string, any>, now: number): VtiWindow {
  const to = typeof args.time_to === 'number' ? args.time_to : now
  if (typeof args.time_from === 'number') return { from: args.time_from, to }
  const seconds = typeof args.last_seconds === 'number' && args.last_seconds > 0
    ? args.last_seconds
    : VTI_DEFAULT_WINDOW_SECONDS
  return { from: to - seconds * 1000, to }
}

/** Clamp a requested page size into what the API accepts. */
export function resolveSize(size: unknown): number {
  if (typeof size !== 'number' || !Number.isFinite(size) || size <= 0) return VTI_DEFAULT_SIZE
  return Math.min(Math.floor(size), VTI_MAX_SIZE)
}

/** The offset into a result set, for paging. */
export function resolveFrom(from: unknown): number {
  return typeof from === 'number' && from > 0 ? Math.floor(from) : 0
}

/** Integer severities the caller asked for, dropping anything out of range. */
export function resolveSeverity(severity: unknown): number[] | undefined {
  if (!Array.isArray(severity)) return undefined
  const levels = severity
    .map(level => Number(level))
    .filter(level => Number.isInteger(level) && level >= 0 && level <= 4)
  return levels.length > 0 ? levels : undefined
}

/** A parsed search: the rows and the total the platform reports. */
export interface VtiSearchResult {
  total: number
  returned: number
  rows: unknown[]
}

/**
 * Parse a search response. Most endpoints answer `{ message, data, total }`;
 * the document-breach one answers `{ alerts, total }`, so both keys are read.
 * @param payload - the raw upstream JSON.
 * @param what - what was searched, named in the error.
 */
export function parseVtiSearch(payload: unknown, what: string): VtiSearchResult {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new VtiContractError(`Expected a VTI ${what} object, got ${describe(payload)}`)
  }
  const obj = payload as Record<string, unknown>
  const rows = obj.data ?? obj.alerts
  if (!Array.isArray(rows)) {
    throw new VtiContractError(`VTI ${what} returned no \`data\` array (keys: ${Object.keys(obj).join(', ')})`)
  }
  const total = typeof obj.total === 'number' ? obj.total : rows.length
  return { total, returned: rows.length, rows }
}

/**
 * Parse an indicator lookup, whose answer is `{ success, message, detail }`.
 * @param payload - the raw upstream JSON.
 */
export function parseVtiLookup(payload: unknown): { value: unknown } {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new VtiContractError(`Expected a VTI lookup object, got ${describe(payload)}`)
  }
  const obj = payload as Record<string, unknown>
  if (obj.detail === undefined) {
    throw new VtiContractError(`VTI lookup returned no \`detail\` (keys: ${Object.keys(obj).join(', ')})`)
  }
  return { value: obj.detail }
}

/** Render the JSON value as text; the harness shows this in the tool card. */
function renderJson(_args: unknown, value: unknown): { type: 'text'; text: string }[] {
  return [{ type: 'text', text: JSON.stringify(value) }]
}

/** The tools return upstream JSON, so the output schema is open. */
const JSON_OUTPUT = {
  schema: { type: 'json' },
  render: renderJson,
} as const

/** The window and paging parameters every search shares. */
const SEARCH_PARAMS: Record<string, ToolParamSpec> = {
  keyword: { type: 'string', description: 'Free-text term, e.g. a domain, an IP address or an indicator.' },
  severity: {
    type: 'array',
    items: { type: 'integer' },
    description: `Severities to include (${VTI_SEVERITY}). Omit for every severity.`,
  },
  last_seconds: { type: 'integer', description: 'Window length back from now, in seconds (default 30 days).' },
  time_from: { type: 'integer', description: 'Window start, epoch milliseconds. Overrides last_seconds.' },
  time_to: { type: 'integer', description: 'Window end, epoch milliseconds. Defaults to now.' },
  size: { type: 'integer', description: `Rows to return, 1-${VTI_MAX_SIZE} (default ${VTI_DEFAULT_SIZE}).` },
  from: { type: 'integer', description: 'Offset into the result set, for paging (default 0).' },
}

/**
 * Build the VTI tool definitions: one search per alert family, the indicator
 * lookup, and the detail reads for the reports that have one.
 * @param options - the HTTP client, the credential check and the clock seam.
 * @returns plain definitions, ready for `defineTool`.
 */
export function createVtiToolDefs({ http, auth, now }: CreateVtiToolDefsOptions): VtiToolDef[] {
  const clock = now ?? (() => Date.now())

  /** Fail closed: with no account configured, no request is made. */
  function guarded(
    run: (args: Record<string, any>) => Promise<unknown>,
  ): (args: Record<string, any>) => Promise<unknown> {
    return async (args) => {
      if (!await auth.ensureConfigured()) return { ...NOT_CONFIGURED }
      return run(args)
    }
  }

  /** The body the alert searches share, as the API spells its fields. */
  const searchBody = (args: Record<string, any>): Record<string, unknown> => {
    const window = resolveWindow(args, clock())
    const severity = resolveSeverity(args.severity)
    return {
      from: resolveFrom(args.from),
      size: resolveSize(args.size),
      time_from: window.from,
      time_to: window.to,
      ...typeof args.keyword === 'string' && args.keyword !== '' ? { keyword: args.keyword } : {},
      ...severity === undefined ? {} : { severity },
    }
  }

  /** One alert search, since eight of them differ only in path and wording. */
  const search = (name: string, path: string, what: string, description: string): VtiToolDef => ({
    name,
    description,
    parameters: SEARCH_PARAMS,
    output: JSON_OUTPUT,
    execute: guarded(async args => parseVtiSearch(await http.postJson(path, searchBody(args)), what)),
  })

  return [
    search(
      'vti_search_compromised_systems',
      VTI_PATHS.compromisedSystem,
      'compromised system',
      'Search Threat Intelligence alerts about the organisation\'s own hosts talking to known malware'
      + ' infrastructure. Each alert names the internal IP address, the indicator it reached and the'
      + ' malware family. Use it to find machines that are already compromised.',
    ),
    search(
      'vti_search_port_anomalies',
      VTI_PATHS.portAnomaly,
      'port anomaly',
      'Search Threat Intelligence alerts about unexpected open ports on the organisation\'s'
      + ' internet-facing addresses. Use it to find services exposed by mistake.',
    ),
    search(
      'vti_search_data_leaks',
      VTI_PATHS.dataLeak,
      'data leak',
      'Search Threat Intelligence alerts about the organisation\'s credentials or data appearing in'
      + ' leaks. Use it when asked what of ours has leaked, or to check one account or domain.',
    ),
    search(
      'vti_search_impersonations',
      VTI_PATHS.impersonate,
      'impersonation',
      'Search Threat Intelligence alerts about domains, accounts or apps impersonating the'
      + ' organisation. Use it for brand-abuse questions.',
    ),
    search(
      'vti_search_phishing',
      VTI_PATHS.phishing,
      'phishing',
      'Search Threat Intelligence alerts about phishing sites and campaigns aimed at the'
      + ' organisation or its customers.',
    ),
    search(
      'vti_search_credit_card_leaks',
      VTI_PATHS.ccleak,
      'credit-card leak',
      'Search Threat Intelligence alerts about the organisation\'s payment cards offered on criminal'
      + ' markets. Card numbers arrive masked by the platform.',
    ),
    {
      name: 'vti_search_cves',
      description:
        'Search the vulnerability feed: CVEs the platform tracks, with its own scoring and the'
        + ' affected products. Use it to check whether a CVE is known, or to list recent critical ones.'
        + ` Severities are ${VTI_SEVERITY}.`,
      parameters: {
        ...SEARCH_PARAMS,
        keyword: { type: 'string', description: 'CVE id or product name, e.g. "CVE-2025-49619" or "redhat".' },
        cvss_level: {
          type: 'array',
          items: { type: 'string', enum: ['unknow', 'low', 'medium', 'high', 'critical'] },
          description: 'CVSS levels to include, as the platform spells them (note "unknow").',
        },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        const levels = Array.isArray(args.cvss_level)
          ? args.cvss_level.map((level: unknown) => String(level))
          : undefined
        const body = {
          ...searchBody(args),
          ...levels === undefined || levels.length === 0 ? {} : { cvss_level: levels },
        }
        return parseVtiSearch(await http.postJson(VTI_PATHS.cve, body), 'CVE')
      }),
    },
    {
      name: 'vti_search_threat_reports',
      description:
        'Search the platform\'s in-depth threat reports: campaigns, actors, malware families and'
        + ' intrusion write-ups. Returns each report\'s code, title and tags; read one in full with'
        + ' vti_get_threat_report.',
      parameters: {
        ...SEARCH_PARAMS,
        severity: { type: 'array', items: { type: 'integer' }, description: 'Severities to include.' },
        tlp: {
          type: 'array',
          items: { type: 'integer' },
          description: 'Sharing levels to include: 0 red, 1 amber, 2 green, 3 white.',
        },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        const tlp = Array.isArray(args.tlp)
          ? args.tlp.map((level: unknown) => Number(level)).filter(Number.isInteger)
          : undefined
        const body = { ...searchBody(args), ...tlp === undefined || tlp.length === 0 ? {} : { tlp } }
        return parseVtiSearch(await http.postJson(VTI_PATHS.threatReport, body), 'threat report')
      }),
    },
    {
      name: 'vti_get_threat_report',
      description:
        'Read one in-depth threat report in full, by the code vti_search_threat_reports returned'
        + ' (e.g. "VTI_2025_0123").',
      parameters: {
        code_report: { type: 'string', required: true, description: 'The report code.' },
      },
      output: JSON_OUTPUT,
      execute: guarded(async args => http.getJson(VTI_DETAIL_PATHS.threatReport(String(args.code_report ?? '')))),
    },
    {
      name: 'vti_search_document_breaches',
      description:
        'Search Threat Intelligence alerts about the organisation\'s internal documents or source'
        + ' code appearing publicly. Read one in full with vti_get_document_breach.',
      parameters: {
        ...SEARCH_PARAMS,
        status: {
          type: 'array',
          items: { type: 'integer' },
          description: 'Handling states to include, as the platform numbers them.',
        },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        // This endpoint names its paging `offset`/`limit` rather than `from`/`size`.
        const window = resolveWindow(args, clock())
        const severity = resolveSeverity(args.severity)
        const status = Array.isArray(args.status)
          ? args.status.map((value: unknown) => Number(value)).filter(Number.isInteger)
          : undefined
        const body = {
          offset: resolveFrom(args.from),
          limit: resolveSize(args.size),
          time_from: window.from,
          time_to: window.to,
          ...typeof args.keyword === 'string' && args.keyword !== '' ? { keyword: args.keyword } : {},
          ...severity === undefined ? {} : { severity },
          ...status === undefined || status.length === 0 ? {} : { status },
        }
        return parseVtiSearch(await http.postJson(VTI_PATHS.dataBreach, body), 'document breach')
      }),
    },
    {
      name: 'vti_get_document_breach',
      description: 'Read one document-breach alert in full, by the code vti_search_document_breaches returned.',
      parameters: {
        code_report: { type: 'string', required: true, description: 'The alert code.' },
      },
      output: JSON_OUTPUT,
      execute: guarded(async args => http.getJson(VTI_DETAIL_PATHS.dataBreach(String(args.code_report ?? '')))),
    },
    {
      name: 'vti_get_credit_card_leak',
      description: 'Read one payment-card leak alert in full, by the id vti_search_credit_card_leaks returned.',
      parameters: {
        ccleak_id: { type: 'string', required: true, description: 'The alert id.' },
      },
      output: JSON_OUTPUT,
      execute: guarded(async args => http.getJson(VTI_DETAIL_PATHS.ccleak(String(args.ccleak_id ?? '')))),
    },
    {
      name: 'vti_search_easm_assets',
      description:
        'Search the attack-surface inventory: the organisation\'s internet-facing assets the platform'
        + ' discovered, with their addresses, hosting and issue counts.',
      parameters: {
        ...SEARCH_PARAMS,
        type: { type: 'string', description: 'Asset type to list, e.g. "domain" or "ip".' },
        status: { type: 'array', items: { type: 'integer' }, description: 'Asset states to include.' },
        status_code: {
          type: 'array',
          items: { type: 'integer' },
          description: 'HTTP status codes to include, e.g. [200, 403].',
        },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        return parseVtiSearch(await http.postJson(VTI_PATHS.easmAsset, easmBody(args, clock())), 'EASM asset')
      }),
    },
    {
      name: 'vti_search_easm_issues',
      description:
        'Search the issues found on the organisation\'s internet-facing assets: the affected asset,'
        + ' what was found and when. Use it to see what is exposed and needs fixing.',
      parameters: {
        ...SEARCH_PARAMS,
        customer_status: {
          type: 'array',
          items: { type: 'integer' },
          description: 'Handling states to include, as the platform numbers them.',
        },
        data_type: { type: 'string', description: 'Which timestamp the window applies to, e.g. "alert_time".' },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        const body = easmBody(args, clock())
        if (typeof args.data_type === 'string' && args.data_type !== '') body.data_type = args.data_type
        const states = Array.isArray(args.customer_status)
          ? args.customer_status.map((value: unknown) => Number(value)).filter(Number.isInteger)
          : undefined
        if (states !== undefined && states.length > 0) body.customer_status = states
        return parseVtiSearch(await http.postJson(VTI_PATHS.easmIssue, body), 'EASM issue')
      }),
    },
    {
      name: 'vti_lookup_indicator',
      description:
        'Look one indicator up in the Threat Intelligence platform: a domain, an IP address, a URL or'
        + ' a file hash. Returns the platform\'s verdict and severity, plus enrichment such as passive'
        + ' DNS, subdomains, WHOIS and recent DNS records. Use it to judge whether an indicator seen'
        + ' in SIEM, EDR or NSM is known-bad.',
      parameters: {
        value: { type: 'string', required: true, description: 'The indicator, e.g. "example.com" or "8.8.8.8".' },
        entity_type: {
          type: 'string',
          required: true,
          enum: ['domain', 'ip', 'url', 'file'],
          description: 'What the value is.',
        },
        sections: {
          type: 'array',
          items: { type: 'string' },
          description: 'Extra sections to include; "enrichment" adds passive DNS, subdomains and WHOIS.',
        },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        const sections = Array.isArray(args.sections) && args.sections.length > 0
          ? args.sections.map((section: unknown) => String(section))
          : ['enrichment']
        const body = {
          value: String(args.value ?? ''),
          entity_type: String(args.entity_type ?? ''),
          sections,
        }
        return parseVtiLookup(await http.postJson(VTI_PATHS.threatLookup, body))
      }),
    },
  ]
}

/**
 * The body the two attack-surface searches share. They name their window
 * `from_time`/`to_time`, unlike every other endpoint.
 * @param args - the tool arguments.
 * @param now - current epoch milliseconds.
 * @returns the request body, ready for the endpoint's own fields.
 */
function easmBody(args: Record<string, any>, now: number): Record<string, unknown> {
  const window = resolveWindow(args, now)
  const severity = resolveSeverity(args.severity)
  const status = Array.isArray(args.status)
    ? args.status.map((value: unknown) => Number(value)).filter(Number.isInteger)
    : undefined
  const statusCode = Array.isArray(args.status_code)
    ? args.status_code.map((value: unknown) => Number(value)).filter(Number.isInteger)
    : undefined
  const body: Record<string, unknown> = {
    from: resolveFrom(args.from),
    size: resolveSize(args.size),
    from_time: window.from,
    to_time: window.to,
  }
  if (typeof args.keyword === 'string' && args.keyword !== '') body.keyword = args.keyword
  if (typeof args.type === 'string' && args.type !== '') body.type = args.type
  if (severity !== undefined) body.severity = severity
  if (status !== undefined && status.length > 0) body.status = status
  if (statusCode !== undefined && statusCode.length > 0) body.status_code = statusCode
  return body
}
