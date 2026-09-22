/**
 * Model-facing NSM (network detection and response) tool definitions.
 *
 * Mirrors the SIEM and EDR slices, and is likewise **dependency-free**: it
 * imports nothing from `@deepseek-ai/*`, so the whole tool surface is
 * unit-testable standalone. `index.ts` is the thin Cordis wrapper that feeds
 * each definition through `defineTool` and registers it.
 *
 * Every request shape here was read from a capture of the NSM web application.
 * The slice is **read-only**: it searches alerts, groups them, and lists the
 * sensors and tenants a search names. NSM reuses the SOC session that
 * `soc_login` (from `tool-soc-soar`) establishes, so no login tool is defined
 * here.
 *
 * @module
 */

/**
 * The auth surface the tools need — only the session check. Declared
 * structurally on purpose: the real implementation is `SocAuthService` in the
 * `soc-auth` package, which this package must not import.
 */
export interface NsmAuthLike {
  isAuthenticated(): boolean
}

/** The slice of soc-client's `SocHttp` these tools need. */
export interface NsmHttpLike {
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
export interface NsmToolDef {
  name: string
  description: string
  parameters: Record<string, ToolParamSpec>
  output: {
    schema: { type: 'json' }
    render: (args: unknown, value: unknown) => { type: 'text'; text: string }[]
  }
  execute: (args: Record<string, any>, exec?: unknown) => Promise<unknown>
}

export interface CreateNsmToolDefsOptions {
  http: NsmHttpLike
  auth: NsmAuthLike
  /** Clock seam, so the default time window is testable. Defaults to `Date.now`. */
  now?: (() => number) | undefined
}

/**
 * Returned instead of throwing when no SOC session exists, so the model reads a
 * value it can act on (ask the user for an OTP) rather than an error trace.
 */
export const NOT_AUTHENTICATED = {
  error: 'not_authenticated',
  message:
    'Not logged in to the SOC platform. Ask the user for their current OTP, then call soc_login with it.',
} as const

/** NSM API paths, read from the NSM web application. */
export const NSM_PATHS = {
  perm: '/api/v1/perm',
  sensors: '/api/v1/sensor/',
  tenants: '/api/v1/tenant/',
  searchEvent: '/api/v1/custom_search_event',
  groupBy: '/api/v1/group_by',
  modelMap: '/api/v1/config/model_map/',
} as const

/** Default and maximum page sizes for the search tools. */
export const NSM_DEFAULT_SIZE = 20
export const NSM_MAX_SIZE = 200
/** Default search window when the caller gives no time range: one hour. */
export const NSM_DEFAULT_WINDOW_SECONDS = 3600
/**
 * Alert fields dropped from each row: NSM repeats the whole raw event and its
 * packet payload inside the alert, which would dominate a tool result.
 */
export const NSM_BULKY_ALERT_FIELDS = ['alert_events', 'alert_raw', 'alert_payload', 'alert_packet'] as const

/** Raised when an NSM payload does not match the expected shape. */
export class NsmContractError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NsmContractError'
  }
}

function describe(data: unknown): string {
  if (data === null) return 'null'
  return Array.isArray(data) ? 'an array' : typeof data
}

/**
 * Every NSM response is `{ code, status, message, data, count }`. Unwrap it,
 * reporting the upstream message when the call did not succeed.
 * @param payload - the raw upstream JSON.
 * @param what - what was being fetched, named in the error.
 */
export function unwrapNsm(payload: unknown, what: string): { data: unknown, count: number } {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new NsmContractError(`Expected an NSM ${what} object, got ${describe(payload)}`)
  }
  const obj = payload as Record<string, unknown>
  const code = typeof obj.code === 'number' ? obj.code : 200
  if (code !== 200) {
    const message = typeof obj.message === 'string' ? obj.message : 'no message'
    throw new NsmContractError(`NSM refused the ${what} request (code ${code}): ${message}`)
  }
  return { data: obj.data, count: typeof obj.count === 'number' ? obj.count : 0 }
}

/** The time window a search covers, in epoch milliseconds. */
export interface NsmWindow {
  from: number
  to: number
}

/**
 * Resolve the search window. Explicit epoch-millisecond bounds win; otherwise
 * the window ends now and runs back `last_seconds` (default one hour).
 * @param args - the tool arguments.
 * @param now - current epoch milliseconds.
 */
export function resolveWindow(args: Record<string, any>, now: number): NsmWindow {
  const to = typeof args.time_to === 'number' ? args.time_to : now
  if (typeof args.time_from === 'number') return { from: args.time_from, to }
  const seconds = typeof args.last_seconds === 'number' && args.last_seconds > 0
    ? args.last_seconds
    : NSM_DEFAULT_WINDOW_SECONDS
  return { from: to - seconds * 1000, to }
}

/** Clamp a requested page size into the tool's range. */
export function resolveSize(size: unknown): number {
  if (typeof size !== 'number' || !Number.isFinite(size) || size <= 0) return NSM_DEFAULT_SIZE
  return Math.min(Math.floor(size), NSM_MAX_SIZE)
}

/** The parsed alert search: the hits, the total match count and the window. */
export interface NsmAlertSearchResult {
  count: number
  returned: number
  window: NsmWindow
  alerts: Record<string, unknown>[]
}

/**
 * Parse an alert search response. Its `data` is `{ data: [...], aggr: {...} }`;
 * `count` on the envelope is the total number of matches, while `returned`
 * reports how many rows came back. The bulky nested event copies are dropped.
 * @param payload - the raw upstream JSON.
 * @param window - the window the search ran over, echoed back for the model.
 */
export function parseNsmAlertSearch(payload: unknown, window: NsmWindow): NsmAlertSearchResult {
  const { data, count } = unwrapNsm(payload, 'alert search')
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new NsmContractError(`Expected an NSM alert search result, got ${describe(data)}`)
  }
  const rows = (data as Record<string, unknown>).data ?? []
  if (!Array.isArray(rows)) throw new NsmContractError('NSM alert search `data.data` must be an array')
  const alerts = rows.map((row) => {
    if (typeof row !== 'object' || row === null) return { value: row } as Record<string, unknown>
    const copy = { ...(row as Record<string, unknown>) }
    for (const field of NSM_BULKY_ALERT_FIELDS) delete copy[field]
    return copy
  })
  return { count, returned: alerts.length, window, alerts }
}

/** One bucket of a group-by: the value and how many alerts carry it. */
export interface NsmBucket {
  key: string
  count: number
}

/**
 * Parse a group-by response, whose buckets live at
 * `data.aggr.group_by_data.buckets` as `{ key, doc_count }`.
 * @param payload - the raw upstream JSON.
 * @param field - the field grouped on, echoed back for the model.
 */
export function parseNsmGroupBy(
  payload: unknown,
  field: string,
): { field: string, count: number, buckets: NsmBucket[] } {
  const { data, count } = unwrapNsm(payload, 'group-by')
  const aggr = typeof data === 'object' && data !== null ? (data as Record<string, unknown>).aggr : undefined
  const group = typeof aggr === 'object' && aggr !== null
    ? (aggr as Record<string, unknown>).group_by_data
    : undefined
  const buckets = typeof group === 'object' && group !== null
    ? (group as Record<string, unknown>).buckets
    : undefined
  if (!Array.isArray(buckets)) {
    throw new NsmContractError('NSM group-by `data.aggr.group_by_data.buckets` must be an array')
  }
  return {
    field,
    count,
    buckets: buckets.map((bucket) => {
      const row = (typeof bucket === 'object' && bucket !== null ? bucket : {}) as Record<string, unknown>
      return { key: String(row.key ?? ''), count: typeof row.doc_count === 'number' ? row.doc_count : 0 }
    }),
  }
}

/** One sensor: the probe that produced an alert. */
export interface NsmSensor {
  sensorId: string
  tenant: string
  ip: string
  active: boolean
  lastPing: string
  eventsPerSecond: string
}

/**
 * Parse the sensor inventory, keeping identity and health only.
 * @param payload - the raw upstream JSON.
 */
export function parseNsmSensors(payload: unknown): { count: number, sensors: NsmSensor[] } {
  const { data, count } = unwrapNsm(payload, 'sensor list')
  if (!Array.isArray(data)) throw new NsmContractError('NSM sensor list `data` must be an array')
  const sensors = data.map((entry) => {
    const row = (typeof entry === 'object' && entry !== null ? entry : {}) as Record<string, unknown>
    return {
      sensorId: String(row.sensor_id ?? row._id ?? ''),
      tenant: String(row._tenant ?? ''),
      ip: String(row.sensor_ip ?? ''),
      active: row.sensor_active === true,
      lastPing: String(row.sensor_last_ping ?? ''),
      eventsPerSecond: String(row.sensor_eps ?? ''),
    }
  })
  return { count: count || sensors.length, sensors }
}

/**
 * Parse the tenant list down to the ids a search names.
 * @param payload - the raw upstream JSON.
 */
export function parseNsmTenants(payload: unknown): { count: number, tenants: string[] } {
  const { data, count } = unwrapNsm(payload, 'tenant list')
  if (!Array.isArray(data)) throw new NsmContractError('NSM tenant list `data` must be an array')
  const tenants = data.map((entry) => {
    const row = (typeof entry === 'object' && entry !== null ? entry : {}) as Record<string, unknown>
    return String(row.tenant_id ?? row._id ?? '')
  })
  return { count: count || tenants.length, tenants }
}

/** The account's NSM identity and what it may do. */
export interface NsmAccess {
  fullname: string
  level: string
  serverType: string
  permissions: string[]
}

/**
 * Parse `perm`, whose `data.current_user` carries the identity and permission
 * list NSM grants this session.
 * @param payload - the raw upstream JSON.
 */
export function parseNsmAccess(payload: unknown): NsmAccess {
  const { data } = unwrapNsm(payload, 'permission')
  const user = typeof data === 'object' && data !== null
    ? (data as Record<string, unknown>).current_user
    : undefined
  if (typeof user !== 'object' || user === null) {
    throw new NsmContractError(`Expected NSM \`data.current_user\`, got ${describe(user)}`)
  }
  const row = user as Record<string, unknown>
  const perms = Array.isArray(row.perms) ? row.perms.map((perm) => String(perm)) : []
  return {
    fullname: String(row.fullname ?? ''),
    level: String(row._level ?? ''),
    serverType: String(row.server_type ?? ''),
    permissions: perms,
  }
}

/**
 * Parse the searchable fields of one document type out of the model map, whose
 * `data.<doc_type>.properties` maps each field to its definition.
 * @param payload - the raw upstream JSON.
 * @param docType - the document type to read, e.g. `alert`.
 */
export function parseNsmFields(payload: unknown, docType: string): { docType: string, count: number, fields: string[] } {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new NsmContractError(`Expected an NSM model map object, got ${describe(payload)}`)
  }
  const data = (payload as Record<string, unknown>).data
  const model = typeof data === 'object' && data !== null
    ? (data as Record<string, unknown>)[docType]
    : undefined
  const properties = typeof model === 'object' && model !== null
    ? (model as Record<string, unknown>).properties
    : undefined
  if (typeof properties !== 'object' || properties === null) {
    const known = typeof data === 'object' && data !== null ? Object.keys(data as object).join(', ') : 'none'
    throw new NsmContractError(`NSM model map has no properties for "${docType}" (known types: ${known})`)
  }
  const fields = Object.keys(properties as object).sort()
  return { docType, count: fields.length, fields }
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

/** The query-language hint repeated in the search tool descriptions. */
const QUERY_HINT =
  'The query uses NSM\'s own search language, e.g. `alert_attacker="1.2.3.4"` or `src="22"`, with'
  + ' terms combined by `and`/`or`; an empty query matches every alert in the window.'
  + ' Call nsm_list_alert_fields for the field names.'

/**
 * Build the NSM tool definitions: the access probe, the sensor and tenant
 * inventories, the field list, alert search and group-by.
 * @param options - the NSM HTTP client, the SOC auth service and the clock seam.
 * @returns plain definitions, ready for `defineTool`.
 */
export function createNsmToolDefs({ http, auth, now }: CreateNsmToolDefsOptions): NsmToolDef[] {
  const clock = now ?? (() => Date.now())

  /**
   * Wrap a tool so it fails closed: with no SOC session it returns the
   * structured not-authenticated value and never touches the network.
   */
  function guarded(
    run: (args: Record<string, any>) => Promise<unknown>,
  ): (args: Record<string, any>) => Promise<unknown> {
    return async (args) => {
      if (!auth.isAuthenticated()) return { ...NOT_AUTHENTICATED }
      return run(args)
    }
  }

  /** The body NSM's alert search and group-by share. */
  const searchBody = (args: Record<string, any>, window: NsmWindow) => ({
    search_type: 'advance_search',
    data: {
      time: { from: window.from, to: window.to },
      query: typeof args.query === 'string' ? args.query : '',
      groupby: { field: '' },
    },
    doc_type: 'alert',
    request_cache: true,
  })

  return [
    {
      name: 'nsm_check_access',
      description:
        'Report the account\'s NSM (network detection) identity and permissions. Use it to confirm'
        + ' that NSM auth works for the logged-in account and to see what it is allowed to do.',
      parameters: {},
      output: JSON_OUTPUT,
      execute: guarded(async () => parseNsmAccess(await http.getJson(NSM_PATHS.perm))),
    },
    {
      name: 'nsm_list_tenants',
      description:
        'List the NSM tenant ids this account may search. An alert search can be narrowed to one'
        + ' tenant, so call this when the user names a customer rather than a tenant id.',
      parameters: {},
      output: JSON_OUTPUT,
      execute: guarded(async () => parseNsmTenants(await http.getJson(NSM_PATHS.tenants))),
    },
    {
      name: 'nsm_list_sensors',
      description:
        'List the NSM sensors (network probes) with their tenant, address, health and event rate.'
        + ' Use it to see which probes are reporting, or to find the sensor behind an alert.',
      parameters: {},
      output: JSON_OUTPUT,
      execute: guarded(async () => parseNsmSensors(await http.getJson(NSM_PATHS.sensors))),
    },
    {
      name: 'nsm_list_alert_fields',
      description:
        'List the searchable NSM alert fields. Use it before writing an nsm_search_alerts query, so'
        + ' the query names fields NSM actually indexes.',
      parameters: {},
      output: JSON_OUTPUT,
      execute: guarded(async () => parseNsmFields(await http.getJson(NSM_PATHS.modelMap), 'alert')),
    },
    {
      name: 'nsm_search_alerts',
      description:
        'Search NSM network alerts and return the matching alerts, newest first. ' + QUERY_HINT
        + ' The window defaults to the last hour; widen it with last_seconds or give explicit'
        + ' time_from/time_to. The nested copies of the raw events are omitted from each alert.',
      parameters: {
        query: { type: 'string', description: 'NSM alert query; empty matches every alert in the window.' },
        last_seconds: { type: 'integer', description: 'Window length back from now, in seconds (default 3600).' },
        time_from: { type: 'integer', description: 'Window start, epoch milliseconds. Overrides last_seconds.' },
        time_to: { type: 'integer', description: 'Window end, epoch milliseconds. Defaults to now.' },
        size: { type: 'integer', description: `Alerts to return, 1-${NSM_MAX_SIZE} (default ${NSM_DEFAULT_SIZE}).` },
        from: { type: 'integer', description: 'Offset into the result set, for paging (default 0).' },
        sort_field: { type: 'string', description: 'Field to sort on (default `_create_time`).' },
        sort_type: { type: 'string', enum: ['desc', 'asc'], description: 'Sort direction (default `desc`).' },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        const window = resolveWindow(args, clock())
        const raw = await http.postJson(NSM_PATHS.searchEvent, {
          ...searchBody(args, window),
          size: resolveSize(args.size),
          from: typeof args.from === 'number' && args.from > 0 ? Math.floor(args.from) : 0,
          sort_field: typeof args.sort_field === 'string' ? args.sort_field : '_create_time',
          sort_type: args.sort_type === 'asc' ? 'asc' : 'desc',
        })
        return parseNsmAlertSearch(raw, window)
      }),
    },
    {
      name: 'nsm_group_alerts',
      description:
        'Count NSM alerts by one field, newest window first: the top attackers, targets, categories'
        + ' or severities behind a query. ' + QUERY_HINT
        + ' Use it to see the shape of an incident before pulling individual alerts.',
      parameters: {
        group_by_field: {
          type: 'string',
          required: true,
          description: 'Field to group on, e.g. `alert_attacker`, `alert_victim`, `alert_category` or `alert_severity`.',
        },
        query: { type: 'string', description: 'NSM alert query; empty groups every alert in the window.' },
        last_seconds: { type: 'integer', description: 'Window length back from now, in seconds (default 3600).' },
        time_from: { type: 'integer', description: 'Window start, epoch milliseconds. Overrides last_seconds.' },
        time_to: { type: 'integer', description: 'Window end, epoch milliseconds. Defaults to now.' },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        const field = String(args.group_by_field ?? '')
        const window = resolveWindow(args, clock())
        const raw = await http.postJson(NSM_PATHS.groupBy, {
          ...searchBody(args, window),
          size: 0,
          from: 0,
          group_by_field: field,
        })
        return parseNsmGroupBy(raw, field)
      }),
    },
  ]
}
