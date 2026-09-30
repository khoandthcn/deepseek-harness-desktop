/**
 * Model-facing EDR tool definitions.
 *
 * Mirrors the SOAR slice's `tools.ts`, and is likewise **dependency-free**: it
 * imports nothing from `@deepseek-ai/*`, so the whole tool surface is
 * unit-testable standalone. `index.ts` is the thin Cordis wrapper that feeds
 * each definition through `defineTool` and registers it.
 *
 * This slice is **read-only**: every tool only searches or lists. EDR reuses
 * the SOC session that `soc_login` (from `tool-soc-soar`) establishes, so no
 * login tool is defined here — a duplicate `soc_login` would collide when both
 * tool packages are mounted.
 */

import type {
  HuntingHistoryOptions,
  SearchAgentsOptions,
  SearchAlertsOptions,
  SearchEventsOptions,
} from './adapter.ts'

/** The adapter surface the tools drive; `EdrAdapter` satisfies it structurally. */
export interface EdrAdapterLike {
  searchEvents(options: SearchEventsOptions): Promise<unknown>
  searchAlerts(options: SearchAlertsOptions): Promise<unknown>
  searchAgents(options: SearchAgentsOptions): Promise<unknown>
  getAgents(agentIds: string[], infos?: string[] | undefined): Promise<unknown>
  getAlertEvents(alertIds: string[], direction: 'asc' | 'desc'): Promise<unknown>
  threatHuntingHistory(options: HuntingHistoryOptions): Promise<unknown>
  listEventFields(): Promise<unknown>
  listAlertFields(): Promise<unknown>
}

/**
 * The auth surface the tools need — only the session check. Declared structurally
 * on purpose: the real implementation is `SocAuthService` in the sibling
 * `soc-auth` package, which this package must not import.
 */
export interface SocAuthLike {
  isAuthenticated(): boolean
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
export interface EdrToolDef {
  name: string
  description: string
  parameters: Record<string, ToolParamSpec>
  output: {
    schema: { type: 'json' }
    render: (args: unknown, value: unknown) => { type: 'text'; text: string }[]
  }
  execute: (args: Record<string, any>, exec?: unknown) => Promise<unknown>
}

export interface CreateEdrToolDefsOptions {
  adapter: EdrAdapterLike
  auth: SocAuthLike
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

/**
 * Shared guidance appended to every EDR read tool. EDR timestamps are epoch
 * seconds, and a relative window (`last_seconds`) is often easier than an
 * absolute one.
 */
const EDR_NOTES =
  ' Notes: EDR timestamps are epoch SECONDS (a millisecond value is accepted and converted). For a'
  + ' recent window prefer `last_seconds` (e.g. 3600 for the last hour); otherwise give'
  + ' `from_timestamp`/`to_timestamp`. `query` is an EDR search expression, e.g.'
  + ' `severity = "High" OR severity = "Low"` — `=`, `AND`, `OR`, double-quoted values. `since` is'
  + ' the zero-based offset of the first record and `since + limit` must stay below 10000: narrow'
  + ' the window rather than paging past that. The total is in `total`; to count, ask for `limit: 1`.'

/**
 * A required, non-empty list of strings. A `json` parameter arrives as whatever
 * the model wrote, and one bare id is the usual slip.
 * @param value - the parameter as received.
 * @param name - its name, for the error.
 * @returns the strings.
 * @throws when there is no usable id.
 */
function stringList(value: unknown, name: string): string[] {
  const list = (Array.isArray(value) ? value : typeof value === 'string' ? [value] : [])
    .filter((item): item is string => typeof item === 'string' && item.trim() !== '')
    .map(item => item.trim())
  if (list.length === 0) throw new Error(`${name} must be a non-empty array of strings.`)
  return list
}

/** The optional counterpart of {@link stringList}: absent stays absent. */
function optionalStringList(value: unknown, name: string): string[] | undefined {
  return value === undefined || value === null ? undefined : stringList(value, name)
}

/** Render the JSON value as text; the harness shows this in the tool card. */
function renderJson(_args: unknown, value: unknown): { type: 'text'; text: string }[] {
  return [{ type: 'text', text: JSON.stringify(value) }]
}

/** Every tool returns upstream JSON, so the output schema is open. */
const JSON_OUTPUT = {
  schema: { type: 'json' },
  render: renderJson,
} as const

/**
 * Build the read-only EDR tool definitions.
 * @param options - the EDR adapter and the SOC auth service to drive.
 * @returns plain definitions, ready for `defineTool`.
 */
export function createEdrToolDefs({ adapter, auth }: CreateEdrToolDefsOptions): EdrToolDef[] {
  /**
   * Wrap a read tool so it fails closed: with no SOC session it returns the
   * structured not-authenticated value and never touches the adapter.
   */
  function guarded(
    run: (args: Record<string, any>) => Promise<unknown>,
  ): (args: Record<string, any>) => Promise<unknown> {
    return async (args) => {
      if (!auth.isAuthenticated()) return { ...NOT_AUTHENTICATED }
      return run(args)
    }
  }

  /**
   * Sort is declared as a string because that is what a model writes, while the
   * API wants `{ field, direction }`. Translate here rather than shipping the
   * string, which the API would ignore.
   * @param sort - `field` or `-field`, or nothing.
   * @returns the sort object, or undefined so the caller's default applies.
   */
  const parseSort = (sort: unknown): { field: string, direction: 'asc' | 'desc' } | undefined => {
    if (typeof sort !== 'string' || sort.trim() === '') return undefined
    const trimmed = sort.trim()
    return trimmed.startsWith('-')
      ? { field: trimmed.slice(1), direction: 'desc' }
      : { field: trimmed, direction: 'asc' }
  }

  const SORT_PARAM: ToolParamSpec = {
    type: 'string',
    description: 'Sort field; prefix with "-" for descending, e.g. "-TimeStamp".',
  }

  const timeWindow: Record<string, ToolParamSpec> = {
    last_seconds: {
      type: 'integer',
      description: 'Relative window: only results within this many seconds of now.',
    },
    from_timestamp: {
      type: 'integer',
      description: 'Absolute window start, in epoch SECONDS.',
    },
    to_timestamp: {
      type: 'integer',
      description: 'Absolute window end, in epoch SECONDS.',
    },
    limit: { type: 'integer', description: 'Maximum results to return. Defaults to 50.' },
    since: { type: 'integer', description: 'Zero-based offset of the first result, for paging. Defaults to 0.' },
  }

  return [
    {
      name: 'edr_search_events',
      description:
        'Search raw EDR endpoint telemetry (process, file, network, and other events collected from'
        + ' agents). Use it to answer questions about what happened on a host: which processes ran,'
        + ' what connected out, what touched a file.'
        + EDR_NOTES,
      parameters: {
        query: {
          type: 'string',
          description: 'Raw EDR search expression, sent as search_query_str.',
        },
        key_quick_search: {
          type: 'string',
          description: 'A quick free-text keyword to match across common event fields.',
        },
        ...timeWindow,
        sort: SORT_PARAM,
      },
      output: JSON_OUTPUT,
      execute: guarded(args => adapter.searchEvents({
        searchQuery: args.query,
        keyQuickSearch: args.key_quick_search,
        lastSeconds: args.last_seconds,
        fromTimestamp: args.from_timestamp,
        toTimestamp: args.to_timestamp,
        limit: args.limit,
        since: args.since,
        sort: parseSort(args.sort),
      })),
    },
    {
      name: 'edr_search_alerts',
      description:
        'Search EDR alerts (detections raised on endpoints). Use it for questions about what fired:'
        + ' how many high-severity alerts, what triggered on a host, what arrived in a time window.'
        + EDR_NOTES,
      parameters: {
        query: {
          type: 'string',
          description: 'Raw EDR search expression, sent as search_query_str.',
        },
        ...timeWindow,
        sort: SORT_PARAM,
      },
      output: JSON_OUTPUT,
      execute: guarded(args => adapter.searchAlerts({
        searchQuery: args.query,
        lastSeconds: args.last_seconds,
        fromTimestamp: args.from_timestamp,
        toTimestamp: args.to_timestamp,
        limit: args.limit,
        since: args.since,
        sort: parseSort(args.sort),
      })),
    },
    {
      name: 'edr_search_agents',
      description:
        'Search the EDR agents (managed endpoints): their hostname, OS, and status. Use it to find a'
        + ' host\'s agent, list which endpoints are enrolled, or check which agents are offline.'
        + EDR_NOTES,
      parameters: {
        query: {
          type: 'json',
          description:
            'Agent filter object, as EDR spells it. One condition is {"compare": {"field": "online",'
            + ' "operator": "=", "value": "false"}} — that one lists offline agents. Omit to list every agent.',
        },
        since: { type: 'integer', description: 'Zero-based offset of the first agent to return. Defaults to 0.' },
        limit: { type: 'integer', description: 'Maximum agents to return. Defaults to 50.' },
      },
      output: JSON_OUTPUT,
      execute: guarded(args => adapter.searchAgents({
        query: args.query,
        since: args.since,
        limit: args.limit,
      })),
    },
    {
      name: 'edr_get_agents',
      description:
        'Get detailed information for specific EDR agents by agent id: host, network interfaces,'
        + ' configuration, policy, update group, first and last ping. Use it after a search gave you'
        + ' agent ids — from an alert\'s `agent_id`, or from edr_search_agents.',
      parameters: {
        agent_ids: { type: 'json', description: 'Array of agent ids, e.g. ["0662DA39…"].' },
        infos: {
          type: 'json',
          description:
            'Optional array naming the blocks to return, from: hostInfo, netInterfaces, cfgInfos,'
            + ' first_ping, last_ping, group_id, update_group, policy, ip. Omit for EDR\'s default set.',
        },
      },
      output: JSON_OUTPUT,
      execute: guarded(args => adapter.getAgents(stringList(args.agent_ids, 'agent_ids'), optionalStringList(args.infos, 'infos'))),
    },
    {
      name: 'edr_get_alert_events',
      description:
        'Get the raw events behind one or more EDR alerts, grouped by alert id. Use it to see what'
        + ' actually happened on the host for an alert: the processes, command lines, files and'
        + ' connections the detection fired on. Take `alert_id` from edr_search_alerts.',
      parameters: {
        alert_ids: { type: 'json', description: 'Array of alert ids, e.g. ["20211011_8483_971179602_261577"].' },
        direction: {
          type: 'string',
          description: 'Order of each alert\'s events by creation time: "asc" or "desc" (default "desc").',
        },
      },
      output: JSON_OUTPUT,
      execute: guarded(args => adapter.getAlertEvents(
        stringList(args.alert_ids, 'alert_ids'),
        args.direction === 'asc' ? 'asc' : 'desc',
      )),
    },
    {
      name: 'edr_threat_hunting_history',
      description:
        'List the history of threat-hunting searches previously run in EDR, newest first. Use it to'
        + ' review what hunts have been performed and their outcomes.'
        + EDR_NOTES,
      parameters: {
        from: { type: 'integer', description: 'Zero-based offset into the history. Defaults to 0.' },
        size: { type: 'integer', description: 'How many entries to return. Defaults to 50.' },
      },
      output: JSON_OUTPUT,
      execute: guarded(args => adapter.threatHuntingHistory({ from: args.from, size: args.size })),
    },
    {
      name: 'edr_list_event_fields',
      description:
        'List the EDR event field definitions (field name → metadata). Use it to find the exact field'
        + ' name and type before you put a field in an `edr_search_events` query — guessing a field'
        + ' name is the usual cause of an empty result.'
        + EDR_NOTES,
      parameters: {},
      output: JSON_OUTPUT,
      execute: guarded(() => adapter.listEventFields()),
    },
    {
      name: 'edr_list_alert_fields',
      description:
        'List the EDR alert field definitions (field name → metadata). Use it to find the exact field'
        + ' name and type before you put a field in an `edr_search_alerts` query.'
        + EDR_NOTES,
      parameters: {},
      output: JSON_OUTPUT,
      execute: guarded(() => adapter.listAlertFields()),
    },
  ]
}
