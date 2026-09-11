/**
 * SOAR response shapes.
 *
 * Ported from socp-mcp `contracts/soar.py`. The pydantic models there use
 * `extra="allow"`, so every interface here carries an index signature: the core
 * fields are named, the remaining ones (63 on an alert) pass through untouched.
 * Validation is deliberately hand-rolled — no runtime schema library.
 */

export interface Extra {
  [key: string]: unknown
}

/** Standard envelope of `{entity}/_search`. */
export interface SearchEnvelope<T> {
  count: number
  data: T[]
}

export interface Alert extends Extra {
  _id?: number | null | undefined
  alert_id?: string | null | undefined
  severity?: string | null | undefined
  status?: string | null | undefined
  cycir_base_status?: string | null | undefined
  assignee?: string | null | undefined
  category?: string | null | undefined
  attack_tactic?: string | null | undefined
  attack_technique?: string | null | undefined
  created?: number | null | undefined
  last_updated?: number | null | undefined
  sla?: number | null | undefined
  sla_expired?: boolean | null | undefined
  description?: string | null | undefined
  message?: string | null | undefined
  hostname?: string | null | undefined
  source?: string | null | undefined
  rule_id?: string | null | undefined
  tenant?: string | null | undefined
  type?: string | null | undefined
  unread?: boolean | null | undefined
}

export interface AlertType extends Extra {
  _id?: number | null | undefined
  name?: string | null | undefined
  description?: string | null | undefined
  alert_field_ids?: number[] | undefined
  alert_fields?: string[] | undefined
  tenant?: string | null | undefined
}

export interface AlertField extends Extra {
  _id?: number | null | undefined
  name?: string | null | undefined
  data_type?: string | null | undefined
  mean_type?: string | null | undefined
  is_built_in?: boolean | null | undefined
  description?: string | null | undefined
}

/** Ticket/case — shape provisional (api-map §7); unknown fields pass through. */
export interface Ticket extends Extra {
  _id?: number | null | undefined
  object_id?: string | null | undefined
  status?: string | null | undefined
  severity?: string | null | undefined
  created?: number | null | undefined
}

export interface Notification extends Extra {
  notification_id?: string | null | undefined
  object?: string | null | undefined
  object_id?: string | null | undefined
  action_type?: string | null | undefined
  message?: string | null | undefined
  actor?: string | null | undefined
  username?: string | null | undefined
  created_time?: number | null | undefined
  unread?: boolean | null | undefined
  tenant?: string | null | undefined
}

export interface NotificationList extends Extra {
  notifications: Notification[]
  counting_all: number
  counting_unread: number
}

/** Raised when an upstream payload does not match the expected shape. */
export class SoarContractError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SoarContractError'
  }
}

function asRecord(data: unknown, what: string): Record<string, unknown> {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new SoarContractError(`Expected a ${what} object, got ${describe(data)}`)
  }
  return data as Record<string, unknown>
}

function describe(data: unknown): string {
  if (data === null) return 'null'
  return Array.isArray(data) ? 'an array' : typeof data
}

/** Validate a `{entity}/_search` envelope; missing count/data default to 0/[]. */
export function parseSearchEnvelope<T>(data: unknown): SearchEnvelope<T> {
  const obj = asRecord(data, 'search envelope')
  const rawData = obj.data ?? []
  if (!Array.isArray(rawData)) {
    throw new SoarContractError('Search envelope `data` must be an array')
  }
  const count = obj.count ?? 0
  if (typeof count !== 'number') {
    throw new SoarContractError('Search envelope `count` must be a number')
  }
  return { count, data: rawData as T[] }
}

/** Validate the `/notification/v1/notification` payload. */
export function parseNotificationList(data: unknown): NotificationList {
  const obj = asRecord(data, 'notification list')
  const notifications = obj.notifications ?? []
  if (!Array.isArray(notifications)) {
    throw new SoarContractError('Notification list `notifications` must be an array')
  }
  return {
    ...obj,
    notifications: notifications as Notification[],
    counting_all: typeof obj.counting_all === 'number' ? obj.counting_all : 0,
    counting_unread: typeof obj.counting_unread === 'number' ? obj.counting_unread : 0,
  }
}
