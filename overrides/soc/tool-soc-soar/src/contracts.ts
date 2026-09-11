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
  _id?: number | null
  alert_id?: string | null
  severity?: string | null
  status?: string | null
  cycir_base_status?: string | null
  assignee?: string | null
  category?: string | null
  attack_tactic?: string | null
  attack_technique?: string | null
  created?: number | null
  last_updated?: number | null
  sla?: number | null
  sla_expired?: boolean | null
  description?: string | null
  message?: string | null
  hostname?: string | null
  source?: string | null
  rule_id?: string | null
  tenant?: string | null
  type?: string | null
  unread?: boolean | null
}

export interface AlertType extends Extra {
  _id?: number | null
  name?: string | null
  description?: string | null
  alert_field_ids?: number[]
  alert_fields?: string[]
  tenant?: string | null
}

export interface AlertField extends Extra {
  _id?: number | null
  name?: string | null
  data_type?: string | null
  mean_type?: string | null
  is_built_in?: boolean | null
  description?: string | null
}

/** Ticket/case — shape provisional (api-map §7); unknown fields pass through. */
export interface Ticket extends Extra {
  _id?: number | null
  object_id?: string | null
  status?: string | null
  severity?: string | null
  created?: number | null
}

export interface Notification extends Extra {
  notification_id?: string | null
  object?: string | null
  object_id?: string | null
  action_type?: string | null
  message?: string | null
  actor?: string | null
  username?: string | null
  created_time?: number | null
  unread?: boolean | null
  tenant?: string | null
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
