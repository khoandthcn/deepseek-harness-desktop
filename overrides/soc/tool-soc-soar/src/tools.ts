/**
 * Model-facing SOAR tool definitions.
 *
 * This module is deliberately **dependency-free**: it imports nothing from
 * `@deepseek-ai/*`, so the whole tool surface (descriptions, parameter specs and
 * `execute` bodies) is unit-testable standalone. `index.ts` is the thin Cordis
 * wrapper that feeds each definition through `defineTool` and registers it.
 *
 * Slice 1 is **read-only**: every tool here only searches or lists. When SOAR
 * mutations arrive (assign an alert, change a ticket status, run a playbook)
 * they must NOT simply be added alongside these — a write tool needs an explicit
 * approval gate so the user confirms the change before it reaches the platform.
 * Nothing below is such a gate, because nothing below writes.
 */

import type {
  GroupAlertsOptions,
  ListNotificationsOptions,
  PageOptions,
  SearchAlertsOptions,
  SearchCasesOptions,
  SearchTicketsOptions,
} from './adapter.ts'

/** The adapter surface the tools drive; `SoarAdapter` satisfies it structurally. */
export interface SoarAdapterLike {
  searchAlerts(options: SearchAlertsOptions): Promise<unknown>
  groupAlerts(options: GroupAlertsOptions): Promise<unknown>
  getAlertEvents(alertInternalId: number): Promise<{ count: number, data: Record<string, unknown>[] }>
  listAlertTypes(options: PageOptions): Promise<unknown>
  listAlertFields(options: PageOptions): Promise<unknown>
  searchCases(options: SearchCasesOptions): Promise<unknown>
  searchTickets(options: SearchTicketsOptions): Promise<unknown>
  listNotifications(options: ListNotificationsOptions): Promise<unknown>
}

/**
 * The auth surface the tools need. Declared structurally on purpose: the real
 * implementation is `SocAuthService` in the sibling `soc-auth` package, which
 * this package must not import (separate workspace package, and importing it
 * would drag WSO2/fetch machinery into these unit tests).
 */
export interface SocAuthLike {
  isAuthenticated(): boolean
  login(otp: string): Promise<void>
  soarBearer(scope: string): Promise<string>
  authHeadersForSoar(scope: string): Record<string, string>
  invalidate(): void
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
export interface SoarToolDef {
  name: string
  description: string
  parameters: Record<string, ToolParamSpec>
  output: {
    schema: { type: 'json' }
    render: (args: unknown, value: unknown) => { type: 'text'; text: string }[]
  }
  execute: (args: Record<string, any>, exec?: unknown) => Promise<unknown>
}

export interface CreateSoarToolDefsOptions {
  adapter: SoarAdapterLike
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
 * Shared guidance appended to every SOAR read tool, so the model gets the three
 * rules that otherwise cause silently wrong queries. From the SOAR API map.
 */
const SOAR_NOTES =
  ' Notes: all SOAR timestamps are epoch MILLISECONDS (not seconds) — 1780718815823, never 1780718815.'
  + ' A deployment serves many tenants (customers): pass `tenant` to keep to one, and leave it out'
  + ' only when every tenant the account can see is wanted.'
  + ' `query` is SOAR\'s own language: `field = "value"`, `field >= number`, `AND`/`OR` with'
  + ' parentheses, and `field = IN(["a", "b"])` for several values; it is ANDed with the other'
  + ' filters. Status values include "open", "in progress" and "close"; severities are "low",'
  + ' "medium", "high", "critical". A page holds at most 500 records; the total matching the'
  + ' filters is `count`, so to count, ask for `size: 1` and read it.'
  + ' Two different ids exist: `case_id` is the human-readable per-tenant id a user will quote'
  + ' (e.g. "260608_0001"), while `_id` is the globally unique internal id — match whichever the'
  + ' user gave you, and quote `case_id` back to them.'

/** Render the JSON value as text; the harness shows this in the tool card. */
function renderJson(_args: unknown, value: unknown): { type: 'text'; text: string }[] {
  return [{ type: 'text', text: JSON.stringify(value) }]
}

/** Every tool returns upstream JSON verbatim, so the output schema is open. */
const JSON_OUTPUT = {
  schema: { type: 'json' },
  render: renderJson,
} as const

/**
 * Build the Slice 1 SOAR tool definitions.
 * @param options - the SOAR adapter and the SOC auth service to drive.
 * @returns plain definitions, ready for `defineTool`.
 */
export function createSoarToolDefs({ adapter, auth }: CreateSoarToolDefsOptions): SoarToolDef[] {
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

  const paging: Record<string, ToolParamSpec> = {
    page: { type: 'integer', description: 'Zero-based page number. Defaults to 0.' },
    size: { type: 'integer', description: 'Results per page.' },
  }

  return [
    {
      name: 'soc_login',
      description:
        'Log in to the SOC platform. Login needs a one-time password: ask the user for the current'
        + ' 6-digit OTP shown in their authenticator app, then call this tool with it immediately'
        + ' (the code rotates every 30 seconds, so do not reuse an old one). The username and'
        + ' password are already configured — you never need to ask for them. Call this when a SOAR'
        + ' tool reports `not_authenticated`, and never echo the OTP back to the user.',
      parameters: {
        otp: {
          type: 'string',
          required: true,
          description: 'The current 6-digit OTP from the user\'s authenticator app.',
        },
      },
      output: JSON_OUTPUT,
      // No `isAuthenticated()` guard here: this tool is what establishes the session.
      execute: async (args) => {
        await auth.login(String(args.otp))
        // Deliberately returns no echo of the OTP.
        return { status: 'logged_in' }
      },
    },
    {
      name: 'soar_search_alerts',
      description:
        'Search SOAR alerts. Give a period (`created_from`/`created_to`) and a `tenant` whenever you'
        + ' can: the platform keeps millions of alerts and an unbounded search is slow. Use it to'
        + ' answer questions about detections: how many high-severity'
        + ' alerts are open, what fired on a host, what arrived in a time window. Filters combine'
        + ' with AND; `query` is a raw xtext expression for anything the named filters cannot'
        + ' express.'
        + SOAR_NOTES,
      parameters: {
        severity: { type: 'string', description: 'Alert severity, e.g. "high".' },
        status: { type: 'string', description: 'Alert status, e.g. "NEW".' },
        created_from: {
          type: 'integer',
          description: 'Only alerts created at or after this time, in epoch MILLISECONDS.',
        },
        created_to: {
          type: 'integer',
          description: 'Only alerts created at or before this time, in epoch MILLISECONDS.',
        },
        tenant: {
          type: 'string',
          description: 'Only records of this tenant (customer), e.g. "acme". Omit for every tenant visible to the account.',
        },
        query: {
          type: 'string',
          description:
            'Raw SOAR xtext query, ANDed with the other filters, e.g. \'hostname = "srv1"\'.',
        },
        ...paging,
        sort: { type: 'string', description: 'Sort field; prefix with "-" for descending. Defaults to "-created".' },
      },
      output: JSON_OUTPUT,
      execute: guarded(args => adapter.searchAlerts({
        severity: args.severity,
        status: args.status,
        createdFrom: args.created_from,
        createdTo: args.created_to,
        tenant: args.tenant,
        rawQuery: args.query,
        page: args.page,
        size: args.size,
        sort: args.sort ?? '-created',
      })),
    },
    {
      name: 'soar_group_alerts',
      description:
        'Count SOAR alerts by the value of one field, over EVERY alert the filters match — the way to'
        + ' get a ranking or a breakdown: alerts per rule (`rule_id`), per host (`hostname`), per'
        + ' source solution (`source`), per category, per severity. Never rank from the rows of'
        + ' soar_search_alerts: a page is a sample, not the period. The result gives `total`,'
        + ' `groups` (largest first) and `missing` (alerts without the field); if `truncated` is'
        + ' true the scan stopped at `scanned` alerts and the counts are incomplete — narrow the'
        + ' filters and say so. `created_from` and `created_to` are required, and a `tenant` makes it'
        + ' far faster: it reads 500 alerts per request, so keep the period as short as the question allows.'
        + SOAR_NOTES,
      parameters: {
        field: { type: 'string', description: 'The alert field to group by, e.g. "rule_id". Check names with soar_list_alert_fields.' },
        top: { type: 'integer', description: 'How many of the largest groups to return, 1-100. Defaults to 10.' },
        severity: { type: 'string', description: 'Alert severity, e.g. "high".' },
        status: { type: 'string', description: 'Alert status, e.g. "open".' },
        created_from: {
          type: 'integer',
          description: 'Only alerts created at or after this time, in epoch MILLISECONDS.',
        },
        created_to: {
          type: 'integer',
          description: 'Only alerts created at or before this time, in epoch MILLISECONDS.',
        },
        tenant: {
          type: 'string',
          description: 'Only records of this tenant (customer), e.g. "acme". Omit for every tenant visible to the account.',
        },
        query: { type: 'string', description: 'Raw SOAR xtext query, ANDed with the other filters.' },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        if (typeof args.field !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.]*$/.test(args.field)) {
          throw new Error('field must be the name of one alert field, e.g. "rule_id".')
        }
        // Without a period this reads every alert the platform has ever kept —
        // millions — and the first request alone times out at the gateway.
        if (typeof args.created_from !== 'number' || typeof args.created_to !== 'number') {
          throw new Error(
            'soar_group_alerts needs a period: give created_from and created_to in epoch milliseconds'
            + ' (and a tenant where you can). It reads every matching alert, so an open-ended grouping'
            + ' would read millions and time out.',
          )
        }
        return adapter.groupAlerts({
          field: args.field,
          top: args.top,
          severity: args.severity,
          status: args.status,
          createdFrom: args.created_from,
          createdTo: args.created_to,
          tenant: args.tenant,
          rawQuery: args.query,
        })
      }),
    },
    {
      name: 'soar_get_alert_events',
      description:
        'Get the events a SOAR alert was raised on: the underlying log or telemetry records with'
        + ' their process, network, user and file fields. Use it to see what actually happened behind'
        + ' an alert. It takes the alert\'s internal `_id` (a number, from soar_search_alerts), not'
        + ' its `alert_id`.',
      parameters: {
        alert_internal_id: { type: 'integer', description: 'The alert\'s `_id`, e.g. 206899862.' },
        limit: { type: 'integer', description: 'Events to return, 1-200. Defaults to 20; `count` is always the full number.' },
      },
      output: JSON_OUTPUT,
      execute: guarded(async (args) => {
        const id = Number(args.alert_internal_id)
        if (!Number.isInteger(id) || id <= 0) {
          throw new Error('alert_internal_id must be the alert\'s numeric `_id`, not its `alert_id`.')
        }
        const events = await adapter.getAlertEvents(id)
        const limit = Math.min(Math.max(1, Math.floor(Number(args.limit) || 20)), 200)
        return { count: events.count, returned: Math.min(limit, events.count), data: events.data.slice(0, limit) }
      }),
    },
    {
      name: 'soar_list_alert_types',
      description:
        'List the alert types defined in SOAR (the detection categories, with the alert fields each'
        + ' one carries). Use it to discover what kinds of alert exist before writing a query.'
        + SOAR_NOTES,
      parameters: { ...paging },
      output: JSON_OUTPUT,
      execute: guarded(args => adapter.listAlertTypes({ page: args.page, size: args.size })),
    },
    {
      name: 'soar_list_alert_fields',
      description:
        'List the alert field definitions in SOAR (field name, data type, description). Use it to'
        + ' find the exact field name and type before you put a field in a `query` — guessing a'
        + ' field name is the usual cause of an empty result.'
        + SOAR_NOTES,
      parameters: { ...paging },
      output: JSON_OUTPUT,
      execute: guarded(args => adapter.listAlertFields({ page: args.page, size: args.size })),
    },
    {
      name: 'soar_search_cases',
      description:
        'Search SOAR cases: what an investigation is filed under. A case is not a ticket — it owns'
        + ' tickets (`total_ticket`, `open_ticket`, `done_ticket`) and alerts link to it. Use it'
        + ' for which cases are open, what a case is about, the case a user quotes by its'
        + ' `case_id`, and how many cases a period had (read `count` with `size: 1`). Filters'
        + ' combine with AND. Fields `query` can filter on include `tenant`, `type`, `owner`,'
        + ' `closed_time`, `sla_expired` (true once the case missed its SLA) and `incident_tag`'
        + ' ("incident" on a case confirmed as an incident).'
        + SOAR_NOTES,
      parameters: {
        severity: { type: 'string', description: 'Case severity, e.g. "high".' },
        status: { type: 'string', description: 'Case status, as the platform spells it.' },
        created_from: {
          type: 'integer',
          description: 'Only cases created at or after this time, in epoch MILLISECONDS.',
        },
        created_to: {
          type: 'integer',
          description: 'Only cases created at or before this time, in epoch MILLISECONDS.',
        },
        tenant: {
          type: 'string',
          description: 'Only records of this tenant (customer), e.g. "acme". Omit for every tenant visible to the account.',
        },
        query: {
          type: 'string',
          description: 'Raw SOAR xtext query, ANDed with the other filters, e.g. \'type = "incident"\'.',
        },
        ...paging,
        sort: { type: 'string', description: 'Sort field; prefix with "-" for descending. Defaults to "-created".' },
      },
      output: JSON_OUTPUT,
      execute: guarded(args => adapter.searchCases({
        severity: args.severity,
        status: args.status,
        createdFrom: args.created_from,
        createdTo: args.created_to,
        tenant: args.tenant,
        rawQuery: args.query,
        page: args.page,
        size: args.size,
        sort: args.sort ?? '-created',
      })),
    },
    {
      name: 'soar_search_tickets',
      description:
        'Search SOAR tickets: units of work assigned to a handling group. A ticket is not a case —'
        + ' for cases use soar_search_cases. Use this for what a group has to do or did: open'
        + ' tickets, tickets by tier, tickets that missed their SLA; and for counts, by reading'
        + ' `count` with `size: 1`. Fields a query can filter on include `created`, `tenant`,'
        + ' `status`, `severity`, `type`, `assigned_group` (the handling tier, e.g. "tier2",'
        + ' "tier3") and `sla_expired` (true once the ticket missed its SLA).'
        + SOAR_NOTES,
      parameters: {
        severity: { type: 'string', description: 'Ticket severity, e.g. "high".' },
        status: { type: 'string', description: 'Ticket status, e.g. "open".' },
        created_from: {
          type: 'integer',
          description: 'Only tickets created at or after this time, in epoch MILLISECONDS.',
        },
        created_to: {
          type: 'integer',
          description: 'Only tickets created at or before this time, in epoch MILLISECONDS.',
        },
        tenant: {
          type: 'string',
          description: 'Only records of this tenant (customer), e.g. "acme". Omit for every tenant visible to the account.',
        },
        query: {
          type: 'string',
          description: 'Raw SOAR xtext query, ANDed with the other filters, e.g. \'assigned_group = "tier2"\'.',
        },
        ...paging,
        sort: { type: 'string', description: 'Sort field; prefix with "-" for descending. Defaults to "-created".' },
      },
      output: JSON_OUTPUT,
      execute: guarded(args => adapter.searchTickets({
        severity: args.severity,
        status: args.status,
        createdFrom: args.created_from,
        createdTo: args.created_to,
        tenant: args.tenant,
        rawQuery: args.query,
        page: args.page,
        size: args.size,
        sort: args.sort ?? '-created',
      })),
    },
    {
      name: 'soar_list_notifications',
      description:
        'List the current user\'s SOAR notifications (assignments, status changes, comments), newest'
        + ' first. Each notification names the object it concerns and that object\'s id.'
        + SOAR_NOTES,
      parameters: {
        size: { type: 'integer', description: 'How many notifications to return.' },
        only_unread: { type: 'boolean', description: 'Return only unread notifications.' },
      },
      output: JSON_OUTPUT,
      execute: guarded(args => adapter.listNotifications({
        size: args.size,
        onlyUnread: args.only_unread,
      })),
    },
  ]
}
