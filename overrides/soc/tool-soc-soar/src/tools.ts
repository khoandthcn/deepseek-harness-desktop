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
  ListNotificationsOptions,
  PageOptions,
  SearchAlertsOptions,
  SearchTicketsOptions,
} from './adapter.ts'

/** The adapter surface the tools drive; `SoarAdapter` satisfies it structurally. */
export interface SoarAdapterLike {
  searchAlerts(options: SearchAlertsOptions): Promise<unknown>
  listAlertTypes(options: PageOptions): Promise<unknown>
  listAlertFields(options: PageOptions): Promise<unknown>
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
  soarBearer(): Promise<string>
  authHeadersForSoar(): Record<string, string>
  invalidate(): void
}

/**
 * A local mirror of the harness's parameter-schema DSL, kept structural so this
 * module stays free of `@deepseek-ai/dsh-tools`.
 */
export interface ToolParamSpec {
  type: 'string' | 'number' | 'integer' | 'boolean' | 'array' | 'object' | 'json'
  required?: true
  description?: string
  enum?: readonly string[]
  items?: ToolParamSpec
  properties?: Record<string, ToolParamSpec>
  additionalProperties?: boolean
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
  + ' Results are scoped to one tenant, so include the tenant in any query you write when the'
  + ' deployment serves more than one.'
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
        'Search SOAR alerts. Use it to answer questions about detections: how many high-severity'
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
        rawQuery: args.query,
        page: args.page,
        size: args.size,
        sort: args.sort ?? '-created',
      })),
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
      name: 'soar_search_tickets',
      description:
        'Search SOAR tickets (cases/incidents). Use it for investigation-level questions: which'
        + ' cases are open, what a case contains, the case a user quotes by its `case_id`.'
        + SOAR_NOTES,
      parameters: {
        query: {
          type: 'string',
          description: 'Raw SOAR xtext query, e.g. \'status = "OPEN"\'.',
        },
        ...paging,
        sort: { type: 'string', description: 'Sort field; prefix with "-" for descending. Defaults to "-created".' },
      },
      output: JSON_OUTPUT,
      execute: guarded(args => adapter.searchTickets({
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
