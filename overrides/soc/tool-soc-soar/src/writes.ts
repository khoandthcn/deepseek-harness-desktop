/**
 * The SOAR tools that change the platform: comment on a case or a ticket,
 * close a case, open a ticket. Each one is gated by an approval the user gives
 * in the application before it runs (see {@link WRITE_TOOL_NAMES} and the
 * plugin's `tools/pre-execute` listener), and each one says exactly what it is
 * about to do so that approval is an informed one.
 *
 * Routes and scopes are the ones the SOAR web application itself uses; the
 * close-case payloads are those of the platform's API reference.
 */

import type { SoarToolDef, ToolParamSpec } from './tools.ts'

/** The slice of the HTTP client the write tools need. */
export interface SoarWriteHttp {
  postJson<T = unknown>(path: string, body: unknown, scope: string): Promise<T>
  putJson<T = unknown>(path: string, body: unknown, scope: string): Promise<T>
  getJson<T = unknown>(path: string, scope: string): Promise<T>
}

/** The scope each write route requires, from the SOAR route map. */
export const SOAR_WRITE_SCOPES = {
  caseEdit: 'edit:case',
  caseComment: 'create:case_comment',
  caseActivity: 'read:case',
  ticketCreate: 'create:ticket',
  ticketComment: 'create:ticket_comment',
  ticketType: 'read:ticket_type',
  ticketSeverity: 'read:ticket_severity',
  ticketStatus: 'read:ticket_status',
  resolution: 'read:resolution',
} as const

/** The tools that change something on the platform. Every call needs the user's approval. */
export const WRITE_TOOL_NAMES = new Set([
  'soar_close_case',
  'soar_add_case_comment',
  'soar_add_ticket_comment',
  'soar_create_ticket',
])

/** How a case may be closed, and the payload the platform expects for each. */
export const CLOSE_RESOLUTIONS = {
  true_positive: { resolution: 'True positive', details: ['Action of admin', 'System business', 'No impact'] },
  false_positive: { resolution: 'False positive', details: ['FALSEPOSITIVE'] },
  duplicate: { resolution: 'Duplicate', details: [] as string[] },
} as const

export type CloseKind = keyof typeof CLOSE_RESOLUTIONS

const pathPart = (value: unknown): string => encodeURIComponent(String(value))

/** A non-empty trimmed string, or an error naming the parameter. */
function required(args: Record<string, unknown>, name: string): string {
  const value = args[name]
  if (typeof value !== 'string' && typeof value !== 'number') throw new Error(`\`${name}\` is required`)
  const text = String(value).trim()
  if (text === '') throw new Error(`\`${name}\` is required`)
  return text
}

/** An internal record id (`_id`): a positive integer, never the human-readable id. */
function internalId(args: Record<string, unknown>, name: string): number {
  const value = Number(args[name])
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`\`${name}\` must be the record's internal \`_id\` (an integer from a search result), not its human-readable id`)
  }
  return value
}

/** The `data` of a platform envelope, or the payload itself. */
function dataOf(payload: unknown): unknown {
  return payload !== null && typeof payload === 'object' && 'data' in payload ? (payload as { data: unknown }).data : payload
}

function rowsOf(payload: unknown): Record<string, unknown>[] {
  const data = dataOf(payload)
  return Array.isArray(data) ? data as Record<string, unknown>[] : []
}

/** Match a row by `_id` or, case-insensitively, by `name`. */
function pick(rows: Record<string, unknown>[], wanted: string, what: string): Record<string, unknown> {
  const lower = wanted.toLowerCase()
  const found = rows.find(row => String(row._id) === wanted)
    ?? rows.find(row => String(row.name ?? '').toLowerCase() === lower)
  if (!found) {
    const names = rows.map(row => `${String(row.name)} (${String(row._id)})`).join(', ')
    throw new Error(`no ${what} "${wanted}"; the platform has: ${names || 'none'}`)
  }
  return found
}

export interface SoarWriteOptions {
  http: SoarWriteHttp
  /** The tenant used when a call names none. */
  defaultTenant: string
}

/** The calls behind the write tools and their lookups. */
export class SoarWriter {
  constructor(private readonly options: SoarWriteOptions) {}

  private tenant(value: unknown): string {
    const text = typeof value === 'string' ? value.trim() : ''
    return text === '' ? this.options.defaultTenant : text
  }

  async closeCase(args: { id: number, kind: CloseKind, comment: string, detail?: string, duplicateOf?: string, tenant?: string | undefined }) {
    const spec = CLOSE_RESOLUTIONS[args.kind]
    let body: Record<string, unknown>
    if (args.kind === 'duplicate') {
      if (!args.duplicateOf) throw new Error('closing as duplicate needs `duplicate_of`: the case_id of the case this one duplicates')
      body = { resolution_detail: null, comment_close: args.comment || args.duplicateOf, duplicate_case_id: args.duplicateOf, resolution: spec.resolution, status: 'close' }
    } else {
      const detail = args.detail ?? spec.details[spec.details.length - 1]!
      if (!(spec.details as readonly string[]).includes(detail)) {
        throw new Error(`\`resolution_detail\` for ${args.kind} must be one of: ${spec.details.join(', ')}`)
      }
      body = { resolution_detail: detail, comment_close: args.comment, resolution: spec.resolution, status: 'close' }
    }
    const tenant = this.tenant(args.tenant)
    return dataOf(await this.options.http.putJson(`/soarapi/v1/${pathPart(tenant)}/case/${pathPart(args.id)}`, body, SOAR_WRITE_SCOPES.caseEdit))
  }

  async addCaseComment(args: { id: number, comment: string, tenant?: string | undefined }) {
    const tenant = this.tenant(args.tenant)
    return dataOf(await this.options.http.postJson(
      `/soarapi/v1/${pathPart(tenant)}/case/${pathPart(args.id)}/comment`, { comment: args.comment }, SOAR_WRITE_SCOPES.caseComment))
  }

  async addTicketComment(args: { id: number, comment: string, tenant?: string | undefined }) {
    const tenant = this.tenant(args.tenant)
    return dataOf(await this.options.http.postJson(
      `/ticketapi/v1/${pathPart(tenant)}/ticket/${pathPart(args.id)}/comment`, { comment: args.comment }, SOAR_WRITE_SCOPES.ticketComment))
  }

  async caseActivity(args: { id: number, tenant?: string | undefined }) {
    const tenant = this.tenant(args.tenant)
    return dataOf(await this.options.http.getJson(`/soarapi/v1/${pathPart(tenant)}/case/${pathPart(args.id)}/event`, SOAR_WRITE_SCOPES.caseActivity))
  }

  private async ticketTypes(tenant: string) {
    return rowsOf(await this.options.http.postJson(`/ticketapi/v1/${pathPart(tenant)}/ticket_type/_search`,
      { _from: 0, _size: 200, _counting: true, _fields: '', query: '' }, SOAR_WRITE_SCOPES.ticketType))
  }

  private async severitiesOf(tenant: string, typeId: unknown) {
    return rowsOf(await this.options.http.getJson(`/ticketapi/v1/${pathPart(tenant)}/ticket_severity_type/${pathPart(typeId)}`, SOAR_WRITE_SCOPES.ticketSeverity))
  }

  private async statuses(tenant: string) {
    return rowsOf(await this.options.http.postJson(`/ticketapi/v1/${pathPart(tenant)}/ticket_status/_search`,
      { _from: 0, _size: 300, _counting: false, _fields: '', _sort: '', query: '' }, SOAR_WRITE_SCOPES.ticketStatus))
  }

  /** The ticket types, each with the severities it accepts, for choosing before a ticket is opened. */
  async ticketOptions(args: { tenant?: string | undefined }) {
    const tenant = this.tenant(args.tenant)
    const types = await this.ticketTypes(tenant)
    return Promise.all(types.map(async type => ({
      _id: type._id,
      name: type.name,
      severities: (await this.severitiesOf(tenant, type._id).catch(() => [])).map(row => ({ _id: row._id, name: row.name })),
    })))
  }

  async createTicket(args: {
    title: string, description: string, type: string, severity: string, tenant?: string | undefined,
    assignedGroup?: string, linkedCase?: string, tags?: string[],
  }) {
    const tenant = this.tenant(args.tenant)
    const type = pick(await this.ticketTypes(tenant), args.type, 'ticket type')
    const severity = pick(await this.severitiesOf(tenant, type._id), args.severity, `severity for ticket type "${String(type.name)}"`)
    // A new ticket opens in the "open" status, and its resolution is whatever
    // the type's workflow assigns to that first transition — as the web form does.
    const status = pick(await this.statuses(tenant), 'open', 'ticket status')
    const resolution = dataOf(await this.options.http.getJson(
      `/ticketapi/v1/${pathPart(tenant)}/resolution/${pathPart(type._id)}/${pathPart(status._id)}`, SOAR_WRITE_SCOPES.resolution)) as { name?: unknown } | null
    const body: Record<string, unknown> = {
      title: args.title,
      description: args.description,
      tags: args.tags ?? [],
      ticket_type_id: type._id,
      ticket_severity_id: severity._id,
      ticket_status_id: status._id,
      resolution: resolution?.name ?? null,
    }
    if (args.assignedGroup) body.assigned_group = args.assignedGroup
    if (args.linkedCase) body.linked_case = args.linkedCase
    return dataOf(await this.options.http.postJson(`/ticketapi/v1/${pathPart(tenant)}/ticket`, body, SOAR_WRITE_SCOPES.ticketCreate))
  }
}

/**
 * What a write call is about to do, in one sentence: the text of the approval
 * the user is asked for. Built from the arguments only, so it states what will
 * be sent, not what the model meant.
 */
export function describeWrite(name: string, args: Record<string, unknown>): string {
  const tenant = typeof args.tenant === 'string' && args.tenant.trim() !== '' ? ` (tenant ${args.tenant})` : ''
  const quote = (value: unknown) => {
    const text = String(value ?? '').replace(/\s+/g, ' ').trim()
    return `"${text.length > 200 ? `${text.slice(0, 200)}…` : text}"`
  }
  switch (name) {
    case 'soar_close_case': {
      const kind = String(args.resolution ?? '')
      const why = kind === 'duplicate' ? `duplicate of ${String(args.duplicate_of ?? '?')}` : `${kind}${args.resolution_detail ? ` / ${String(args.resolution_detail)}` : ''}`
      return `Close SOAR case _id ${String(args.case_id)}${tenant} as ${why}, with the comment ${quote(args.comment)}.`
    }
    case 'soar_add_case_comment':
      return `Add a comment to SOAR case _id ${String(args.case_id)}${tenant}: ${quote(args.comment)}.`
    case 'soar_add_ticket_comment':
      return `Add a comment to SOAR ticket _id ${String(args.ticket_id)}${tenant}: ${quote(args.comment)}.`
    case 'soar_create_ticket':
      return `Open a SOAR ticket${tenant} of type ${quote(args.ticket_type)}, severity ${quote(args.severity)}`
        + `${args.linked_case ? `, linked to case ${String(args.linked_case)}` : ''}, titled ${quote(args.title)}.`
    default:
      return `Run ${name}.`
  }
}

const TENANT: ToolParamSpec = {
  type: 'string',
  description: 'The tenant the record belongs to: the `tenant` field of the search result. Required unless the deployment has a single tenant.',
}

const WRITE_NOTE = ' This changes the SOC platform: the user is asked to approve the exact action before it runs.'
  + ' Never call it on your own initiative; only when the user asked for this action on this record.'

/**
 * Build the write tools, and the two reads that let the model fill them in.
 * @param options - the writer and the not-authenticated value to return without a session.
 */
export function createSoarWriteToolDefs(options: {
  writer: Pick<SoarWriter, 'closeCase' | 'addCaseComment' | 'addTicketComment' | 'createTicket' | 'caseActivity' | 'ticketOptions'>
  isAuthenticated: () => boolean
  notAuthenticated: unknown
  output: SoarToolDef['output']
}): SoarToolDef[] {
  const { writer, isAuthenticated, notAuthenticated, output } = options
  const guarded = (run: (args: Record<string, unknown>) => Promise<unknown>) =>
    async (args: Record<string, unknown>) => (isAuthenticated() ? run(args) : notAuthenticated)
  return [
    {
      name: 'soar_get_case_activity',
      description: 'Read the activity log of one SOAR case: comments, status changes, assignments, playbook results, in order.'
        + ' Pass the case\'s internal `_id` from soar_search_cases. Read before commenting or closing, to see what was already done.',
      parameters: { case_id: { type: 'integer', required: true, description: 'The case\'s internal `_id`.' }, tenant: TENANT },
      output,
      execute: guarded(args => writer.caseActivity({ id: internalId(args, 'case_id'), tenant: args.tenant as string | undefined })),
    },
    {
      name: 'soar_list_ticket_options',
      description: 'List the SOAR ticket types and, for each, the severities it accepts. Call before soar_create_ticket to pick a valid type and severity.',
      parameters: { tenant: TENANT },
      output,
      execute: guarded(args => writer.ticketOptions({ tenant: args.tenant as string | undefined })),
    },
    {
      name: 'soar_add_case_comment',
      description: 'Add a comment to a SOAR case: an investigation note, a finding, a handover.' + WRITE_NOTE,
      parameters: {
        case_id: { type: 'integer', required: true, description: 'The case\'s internal `_id` from soar_search_cases (not its case_id).' },
        comment: { type: 'string', required: true, description: 'The comment text, as it should appear on the case.' },
        tenant: TENANT,
      },
      output,
      execute: guarded(args => writer.addCaseComment({ id: internalId(args, 'case_id'), comment: required(args, 'comment'), tenant: args.tenant as string | undefined })),
    },
    {
      name: 'soar_add_ticket_comment',
      description: 'Add a comment to a SOAR ticket.' + WRITE_NOTE,
      parameters: {
        ticket_id: { type: 'integer', required: true, description: 'The ticket\'s internal `_id` from soar_search_tickets.' },
        comment: { type: 'string', required: true, description: 'The comment text.' },
        tenant: TENANT,
      },
      output,
      execute: guarded(args => writer.addTicketComment({ id: internalId(args, 'ticket_id'), comment: required(args, 'comment'), tenant: args.tenant as string | undefined })),
    },
    {
      name: 'soar_close_case',
      description: 'Close a SOAR case with a resolution. `resolution`: "true_positive" (with `resolution_detail` one of'
        + ' "Action of admin", "System business", "No impact"), "false_positive", or "duplicate" (with `duplicate_of`, the'
        + ' case_id it duplicates). `comment` is the closing comment the platform records.' + WRITE_NOTE,
      parameters: {
        case_id: { type: 'integer', required: true, description: 'The case\'s internal `_id` from soar_search_cases (not its case_id).' },
        resolution: { type: 'string', required: true, enum: ['true_positive', 'false_positive', 'duplicate'], description: 'How the case ends.' },
        resolution_detail: { type: 'string', enum: ['Action of admin', 'System business', 'No impact'], description: 'For true_positive only.' },
        comment: { type: 'string', required: true, description: 'The closing comment: what was found and why it is closed.' },
        duplicate_of: { type: 'string', description: 'For duplicate only: the case_id of the original case.' },
        tenant: TENANT,
      },
      output,
      execute: guarded(args => {
        const kind = required(args, 'resolution') as CloseKind
        if (!(kind in CLOSE_RESOLUTIONS)) throw new Error('`resolution` must be true_positive, false_positive or duplicate')
        return writer.closeCase({
          id: internalId(args, 'case_id'),
          kind,
          comment: required(args, 'comment'),
          ...(typeof args.resolution_detail === 'string' ? { detail: args.resolution_detail } : {}),
          ...(typeof args.duplicate_of === 'string' ? { duplicateOf: args.duplicate_of.trim() } : {}),
          tenant: args.tenant as string | undefined,
        })
      }),
    },
    {
      name: 'soar_create_ticket',
      description: 'Open a SOAR ticket, for example to hand a finding to the customer or another team. Pick `ticket_type` and'
        + ' `severity` from soar_list_ticket_options (name or _id); the ticket opens in the "open" status.' + WRITE_NOTE,
      parameters: {
        title: { type: 'string', required: true, description: 'The ticket title.' },
        description: { type: 'string', required: true, description: 'The ticket body: what happened, what is asked of the recipient.' },
        ticket_type: { type: 'string', required: true, description: 'Ticket type name or _id.' },
        severity: { type: 'string', required: true, description: 'Severity name or _id, one the type accepts.' },
        linked_case: { type: 'string', description: 'The case_id this ticket follows from, if any.' },
        assigned_group: { type: 'string', description: 'The group to assign, if the user named one.' },
        tags: { type: 'array', items: { type: 'string' }, description: 'Tags to set.' },
        tenant: TENANT,
      },
      output,
      execute: guarded(args => writer.createTicket({
        title: required(args, 'title'),
        description: required(args, 'description'),
        type: required(args, 'ticket_type'),
        severity: required(args, 'severity'),
        tenant: args.tenant as string | undefined,
        ...(typeof args.assigned_group === 'string' && args.assigned_group.trim() ? { assignedGroup: args.assigned_group.trim() } : {}),
        ...(typeof args.linked_case === 'string' && args.linked_case.trim() ? { linkedCase: args.linked_case.trim() } : {}),
        ...(Array.isArray(args.tags) ? { tags: args.tags.map(String) } : {}),
      })),
    },
  ]
}
