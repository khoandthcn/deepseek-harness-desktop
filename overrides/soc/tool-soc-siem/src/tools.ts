/**
 * Model-facing SIEM tool definitions.
 *
 * Mirrors the EDR slice's `tools.ts`, and is likewise **dependency-free**: it
 * imports nothing from `@deepseek-ai/*`, so the whole tool surface is
 * unit-testable standalone. `index.ts` is the thin Cordis wrapper that feeds
 * each definition through `defineTool` and registers it.
 *
 * This slice is **read-only**. Every request shape here was read from a capture
 * of the SIEM web application, including its per-API token routing: SIEM's own
 * OAuth server issues one token per API group (audience) and scope, which
 * `SIEM_TOKEN_FOR` records. SIEM reuses the SOC session that `soc_login` (from
 * `tool-soc-soar`) establishes, so no login tool is defined here.
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
  /** Clock seam, so the default time window is testable. Defaults to `Date.now`. */
  now?: (() => number) | undefined
  /** Query id seam; SIEM tags each search with one. Defaults to a random UUID. */
  newQueryId?: (() => string) | undefined
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
  tenantSearch: '/cymtenantapi/api/v1/tenant/socp_search',
  eventSearch: '/adaptereventapi/v1/search',
  eventStatistic: '/adaptereventapi/api/v1/statistic/',
  agentSearch: '/cymagentapi/CyMAgentManagement/Search',
} as const

/**
 * The SIEM token each path needs. SIEM's OAuth server issues one token per API
 * group (audience) and scope; this mirrors its SPA's per-API TokenManager
 * configuration, where `/oauth/management/get_user_role_perm` sits under the
 * `gatekeeper` audience with scope `login`.
 */
export const SIEM_TOKEN_FOR: Readonly<Record<string, { audience: string, scope: string }>> = {
  [SIEM_PATHS.userRolePerm]: { audience: 'gatekeeper', scope: 'login' },
  [SIEM_PATHS.tenantSearch]: { audience: 'cym_tenant_api', scope: 'read:te_tenant' },
  [SIEM_PATHS.eventSearch]: { audience: 'cym_event_alert_api', scope: 'read:eventapi' },
  [SIEM_PATHS.eventStatistic]: { audience: 'cym_dashboard_api', scope: 'read:db_statistic' },
  [SIEM_PATHS.agentSearch]: { audience: 'cym_agent_api', scope: 'read:agent' },
}

/** Default and maximum page sizes for the search tools. */
export const SIEM_DEFAULT_SIZE = 20
export const SIEM_MAX_SIZE = 200
/** Default search window when the caller gives no time range: one hour. */
export const SIEM_DEFAULT_WINDOW_SECONDS = 3600
/** Event rows are raw log documents; these fields are dropped as bulk. */
export const SIEM_BULKY_EVENT_FIELDS = ['_raw_event', 'raw_event'] as const

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

/** The time window a search covers, in epoch milliseconds. */
export interface SiemWindow {
  time_from: number
  time_to: number
}

/**
 * Resolve the search window. Explicit epoch-millisecond bounds win; otherwise
 * the window ends now and runs back `last_seconds` (default one hour), which is
 * what keeps an unbounded query from scanning the whole retention period.
 * @param args - the tool arguments.
 * @param now - current epoch milliseconds.
 */
export function resolveWindow(args: Record<string, any>, now: number): SiemWindow {
  const to = typeof args.time_to === 'number' ? args.time_to : now
  if (typeof args.time_from === 'number') return { time_from: args.time_from, time_to: to }
  const seconds = typeof args.last_seconds === 'number' && args.last_seconds > 0
    ? args.last_seconds
    : SIEM_DEFAULT_WINDOW_SECONDS
  return { time_from: to - seconds * 1000, time_to: to }
}

/** Clamp a requested page size into the tool's range. */
export function resolveSize(size: unknown): number {
  if (typeof size !== 'number' || !Number.isFinite(size) || size <= 0) return SIEM_DEFAULT_SIZE
  return Math.min(Math.floor(size), SIEM_MAX_SIZE)
}

/** The parsed event search: the hits, the matching total and the window used. */
export interface SiemEventSearchResult {
  count: number
  returned: number
  window: SiemWindow
  events: Record<string, unknown>[]
}

/**
 * Parse an event search response. The observed shape is
 * `{ code, count, data: [...], fields, aggs, raw_aggs }`; `count` is the total
 * match count only on a counting request, so `returned` reports what came back.
 * The raw log line is dropped from each row: it repeats the parsed fields and
 * would dominate the tool's output.
 * @param payload - the raw upstream JSON.
 * @param window - the window the search ran over, echoed back for the model.
 */
export function parseSiemEventSearch(payload: unknown, window: SiemWindow): SiemEventSearchResult {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new SiemContractError(`Expected a SIEM search object, got ${describe(payload)}`)
  }
  const obj = payload as Record<string, unknown>
  const rows = obj.data ?? []
  if (!Array.isArray(rows)) throw new SiemContractError('SIEM search `data` must be an array')
  const events = rows.map((row) => {
    if (typeof row !== 'object' || row === null) return { value: row } as Record<string, unknown>
    const copy = { ...(row as Record<string, unknown>) }
    for (const field of SIEM_BULKY_EVENT_FIELDS) delete copy[field]
    return copy
  })
  const count = typeof obj.count === 'number' ? obj.count : events.length
  return { count, returned: events.length, window, events }
}

/** One tenant the account may search. */
export interface SiemTenant {
  tenantId: string
  fullName: string
}

/**
 * Parse the tenant list. The observed shape is
 * `{ status, data: { items: [{ tenantId, fullName }], count } }`.
 * @param payload - the raw upstream JSON.
 */
export function parseSiemTenants(payload: unknown): { count: number, tenants: SiemTenant[] } {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new SiemContractError(`Expected a SIEM tenant object, got ${describe(payload)}`)
  }
  const data = (payload as Record<string, unknown>).data
  const items = typeof data === 'object' && data !== null ? (data as Record<string, unknown>).items : undefined
  if (!Array.isArray(items)) throw new SiemContractError('SIEM tenants `data.items` must be an array')
  const tenants = items.map((item) => {
    const row = (typeof item === 'object' && item !== null ? item : {}) as Record<string, unknown>
    return { tenantId: String(row.tenantId ?? ''), fullName: String(row.fullName ?? '') }
  })
  return { count: tenants.length, tenants }
}

/**
 * Parse the searchable-field map out of the event statistics response, whose
 * `fields` is `{ <field>: <type> }`.
 * @param payload - the raw upstream JSON.
 */
export function parseSiemEventFields(payload: unknown): { count: number, fields: Record<string, string> } {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new SiemContractError(`Expected a SIEM statistics object, got ${describe(payload)}`)
  }
  const raw = (payload as Record<string, unknown>).fields
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new SiemContractError('SIEM statistics `fields` must be an object')
  }
  const fields: Record<string, string> = {}
  for (const [name, type] of Object.entries(raw as Record<string, unknown>)) fields[name] = String(type)
  return { count: Object.keys(fields).length, fields }
}

/** One agent, reduced to the fields worth showing a model. */
export interface SiemAgent {
  agentId: string
  computerName: string
  os: string
  platform: string
  platformVersion: string
  architecture: string
}

/**
 * Parse an agent search. The upstream row carries a whole host inventory
 * (installed files, interfaces, configuration), so only the identifying fields
 * are kept.
 * @param payload - the raw upstream JSON.
 */
export function parseSiemAgents(payload: unknown): { total: number, returned: number, agents: SiemAgent[] } {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new SiemContractError(`Expected a SIEM agent object, got ${describe(payload)}`)
  }
  const obj = payload as Record<string, unknown>
  const rows = obj.agent_infos ?? []
  if (!Array.isArray(rows)) throw new SiemContractError('SIEM agents `agent_infos` must be an array')
  const agents = rows.map((row) => {
    const agent = (typeof row === 'object' && row !== null ? row : {}) as Record<string, unknown>
    const host = (typeof agent.hostInfo === 'object' && agent.hostInfo !== null
      ? agent.hostInfo
      : {}) as Record<string, unknown>
    return {
      agentId: String(agent.agentId ?? ''),
      computerName: String(host.computerName ?? ''),
      os: String(host.os ?? ''),
      platform: String(host.platform ?? ''),
      platformVersion: String(host.platformVersion ?? ''),
      architecture: String(host.architecture ?? ''),
    }
  })
  const total = typeof obj.total === 'number' ? obj.total : agents.length
  return { total, returned: agents.length, agents }
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

/** The query-language hint repeated in the search tool descriptions. */
const QUERY_HINT =
  'The query uses SIEM\'s own event language, e.g. `log_parser ~ "win"` (`~` matches, `=` equals,'
  + ' and terms combine with `and`/`or`); an empty query matches everything in the window.'
  + ' Call siem_list_event_fields for the searchable field names.'

/**
 * Build the SIEM tool definitions: the access probe, the tenant list, the
 * searchable-field list, event search and count, and agent search.
 * @param options - the SIEM HTTP client, the SOC auth service, and the clock
 *   and query-id seams.
 * @returns plain definitions, ready for `defineTool`.
 */
export function createSiemToolDefs({ http, auth, now, newQueryId }: CreateSiemToolDefsOptions): SiemToolDef[] {
  const clock = now ?? (() => Date.now())
  const queryId = newQueryId ?? (() => globalThis.crypto.randomUUID())

  /** The body SIEM's event search expects; `_counting` picks count vs. hits. */
  const searchBody = (args: Record<string, any>, window: SiemWindow, counting: boolean) => ({
    query: typeof args.query === 'string' ? args.query : '',
    time_from: window.time_from,
    time_to: window.time_to,
    tenants: typeof args.tenants === 'string' ? args.tenants : '',
    _sort: typeof args.sort === 'string' ? args.sort : '-timestamp',
    _size: counting ? 0 : resolveSize(args.size),
    _from: typeof args.from === 'number' && args.from > 0 ? Math.floor(args.from) : 0,
    _counting: counting,
    query_id: queryId(),
  })

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
        + ' A permission a search needs but the account lacks is why that search is refused.',
      parameters: {},
      output: JSON_OUTPUT,
      execute: guarded(async () => {
        const raw = await http.postJson(SIEM_PATHS.userRolePerm, { client_id: auth.siemMgmtClientId })
        return parseSiemAccess(raw)
      }),
    },
    {
      name: 'siem_list_tenants',
      description:
        'List the SIEM tenants (customers) this account may search, as {tenantId, fullName}. A SIEM'
        + ' event search runs against one tenant, named by its tenantId, so call this first when the'
        + ' user names a customer rather than a tenant id.',
      parameters: {},
      output: JSON_OUTPUT,
      execute: guarded(async () => parseSiemTenants(await http.postJson(SIEM_PATHS.tenantSearch, {}))),
    },
    {
      name: 'siem_list_event_fields',
      description:
        'List the searchable event fields and their types ({field: type}). Use it before writing a'
        + ' siem_search_events query, so the query names fields SIEM actually indexes.',
      parameters: {
        last_seconds: {
          type: 'integer',
          description:
            'How far back to sample the field map, in seconds. Defaults to 30 days, because a short'
            + ' window can miss fields no recent event carries.',
        },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        const to = clock()
        const seconds = typeof args.last_seconds === 'number' && args.last_seconds > 0
          ? args.last_seconds
          : 30 * 24 * 3600
        const raw = await http.postJson(SIEM_PATHS.eventStatistic, {
          time_from: to - seconds * 1000,
          time_to: to,
          type: 'event',
          query: '',
          aggs: '',
          getting_fields: true,
        })
        return parseSiemEventFields(raw)
      }),
    },
    {
      name: 'siem_search_events',
      description:
        'Search SIEM log events and return the matching events, newest first. ' + QUERY_HINT
        + ' The window defaults to the last hour; widen it with last_seconds or give explicit'
        + ' time_from/time_to. Each event is the parsed log document; the raw log line is omitted.',
      parameters: {
        query: { type: 'string', description: 'SIEM event query; empty matches every event in the window.' },
        tenants: {
          type: 'string',
          description: 'Tenant id to search, from siem_list_tenants. Empty searches the default scope.',
        },
        last_seconds: { type: 'integer', description: 'Window length back from now, in seconds (default 3600).' },
        time_from: { type: 'integer', description: 'Window start, epoch milliseconds. Overrides last_seconds.' },
        time_to: { type: 'integer', description: 'Window end, epoch milliseconds. Defaults to now.' },
        size: { type: 'integer', description: `Events to return, 1-${SIEM_MAX_SIZE} (default ${SIEM_DEFAULT_SIZE}).` },
        from: { type: 'integer', description: 'Offset into the result set, for paging (default 0).' },
        sort: { type: 'string', description: 'Sort expression, e.g. `-timestamp` (default) or `timestamp`.' },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        const window = resolveWindow(args, clock())
        const raw = await http.postJson(SIEM_PATHS.eventSearch, searchBody(args, window, false))
        return parseSiemEventSearch(raw, window)
      }),
    },
    {
      name: 'siem_count_events',
      description:
        'Count SIEM log events matching a query in a time window, without returning them. ' + QUERY_HINT
        + ' Use it to size a search before running it, or to compare volumes across windows.',
      parameters: {
        query: { type: 'string', description: 'SIEM event query; empty counts every event in the window.' },
        tenants: { type: 'string', description: 'Tenant id to count in, from siem_list_tenants.' },
        last_seconds: { type: 'integer', description: 'Window length back from now, in seconds (default 3600).' },
        time_from: { type: 'integer', description: 'Window start, epoch milliseconds. Overrides last_seconds.' },
        time_to: { type: 'integer', description: 'Window end, epoch milliseconds. Defaults to now.' },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        const window = resolveWindow(args, clock())
        const raw = await http.postJson(SIEM_PATHS.eventSearch, searchBody(args, window, true))
        // A counting request returns no rows, so the row-count fallback in the
        // shared parser would report 0 for a malformed response. For a tool whose
        // whole output is the number, that is indistinguishable from "no matches".
        const count = (raw as { count?: unknown } | null)?.count
        if (typeof count !== 'number') {
          throw new SiemContractError(
            `SIEM returned no count for the counting search (response keys: ${
              raw !== null && typeof raw === 'object' ? Object.keys(raw).join(', ') : typeof raw})`,
          )
        }
        return { count, window }
      }),
    },
    {
      name: 'siem_search_agents',
      description:
        'Search the SIEM agents (endpoints reporting logs) and return their identity and platform.'
        + ' Use it to find which machine a hostname belongs to, or to list the agents of a tenant.',
      parameters: {
        active: {
          type: 'string',
          description: 'Agent state filter as SIEM spells it: "1" for active, "0" for inactive. Omit for both.',
        },
        size: { type: 'integer', description: `Agents to return, 1-${SIEM_MAX_SIZE} (default ${SIEM_DEFAULT_SIZE}).` },
        from: { type: 'integer', description: 'Offset into the result set, for paging (default 0).' },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        const query: Record<string, unknown> = {}
        if (typeof args.active === 'string' && args.active.length > 0) query.active = args.active
        const raw = await http.postJson(SIEM_PATHS.agentSearch, {
          limit: resolveSize(args.size),
          since: typeof args.from === 'number' && args.from > 0 ? Math.floor(args.from) : 0,
          query,
          sort: [{ field: 'hostInfo.computerName', direction: 'asc' }],
        })
        return parseSiemAgents(raw)
      }),
    },
  ]
}
