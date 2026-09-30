/**
 * SoarAdapter — turns the raw SOAR API into clean models.
 *
 * Ported from socp-mcp `modules/soar.py`. Every HTTP call goes through the
 * injected client (structurally compatible with soc-client's `SocHttp`);
 * this module never touches `fetch` directly.
 */

import {
  type Alert,
  type AlertField,
  type AlertType,
  type Case,
  type NotificationList,
  type SearchEnvelope,
  type Ticket,
  parseNotificationList,
  parseSearchEnvelope,
} from './contracts.ts'
import { buildAlertQuery } from './query.ts'

/** The slice of soc-client's `SocHttp` this adapter needs. */
export interface SoarHttp {
  /** @param scope - the SOAR scope this endpoint requires; the client mints a Bearer for it. */
  postJson<T = unknown>(path: string, body: unknown, scope: string): Promise<T>
  getJson<T = unknown>(path: string, scope: string): Promise<T>
}

/** SOAR scope required by each endpoint, read from the SOAR SPA's route map. */
export const SOAR_SCOPES = {
  alertSearch: 'read:alert',
  alertTypes: 'read:alert_types',
  alertFields: 'read:alert_field',
  alertEvents: 'read:artifact_event',
  caseSearch: 'read:case',
  ticketSearch: 'read:ticket',
  notifications: 'read:notification',
} as const

/** The most records one search request may return. */
export const SOAR_MAX_SIZE = 500

/** How many alerts a grouping reads before it stops and says it stopped. */
export const SOAR_GROUP_SCAN_LIMIT = 100_000

/**
 * A page size SOAR will accept. It rejects more than {@link SOAR_MAX_SIZE}, so
 * a larger request is served as the largest page rather than as an error.
 */
function pageSize(size: number): number {
  return Math.min(Math.max(1, Math.floor(size)), SOAR_MAX_SIZE)
}

export interface SearchAlertsOptions {
  severity?: string | null | undefined
  status?: string | null | undefined
  createdFrom?: number | null | undefined
  createdTo?: number | null | undefined
  tenant?: string | null | undefined
  rawQuery?: string | null | undefined
  page?: number | undefined
  size?: number | undefined
  sort?: string | undefined
}

export interface PageOptions {
  page?: number | undefined
  size?: number | undefined
}

export interface SearchTicketsOptions extends PageOptions {
  severity?: string | null | undefined
  status?: string | null | undefined
  createdFrom?: number | null | undefined
  createdTo?: number | null | undefined
  tenant?: string | null | undefined
  rawQuery?: string | null | undefined
  sort?: string | undefined
}

export interface GroupAlertsOptions {
  /** The alert field to group by, e.g. `rule_id` or `hostname`. */
  field: string
  /** How many of the largest groups to return. */
  top?: number | undefined
  severity?: string | null | undefined
  status?: string | null | undefined
  createdFrom?: number | null | undefined
  createdTo?: number | null | undefined
  tenant?: string | null | undefined
  rawQuery?: string | null | undefined
}

/** Alerts counted by the value of one field. */
export interface AlertGroups {
  field: string
  /** Alerts matching the filters, as SOAR counts them. */
  total: number
  /** Alerts actually read. Equal to `total` unless `truncated`. */
  scanned: number
  /** True when the scan stopped early: the groups then cover only `scanned` alerts. */
  truncated: boolean
  /** How many different values the field took. */
  distinct: number
  /** Alerts in which the field was absent or empty. */
  missing: number
  /** The largest groups, most alerts first. */
  groups: { value: string, count: number }[]
}

export interface SearchCasesOptions extends PageOptions {
  severity?: string | null | undefined
  status?: string | null | undefined
  createdFrom?: number | null | undefined
  createdTo?: number | null | undefined
  tenant?: string | null | undefined
  rawQuery?: string | null | undefined
  sort?: string | undefined
}

export interface ListNotificationsOptions {
  size?: number | undefined
  onlyUnread?: boolean | undefined
}

export class SoarAdapter {
  private readonly http: SoarHttp
  private readonly tenant: string

  constructor(http: SoarHttp, tenant = 'MASTER') {
    this.http = http
    this.tenant = tenant
  }

  private base(): string {
    return `/soarapi/v1/${this.tenant}`
  }

  async searchAlerts(options: SearchAlertsOptions = {}): Promise<SearchEnvelope<Alert>> {
    const { page = 0, sort = '-created' } = options
    const size = pageSize(options.size ?? 50)
    const body = {
      _from: page * size,
      _size: size,
      _sort: sort,
      _counting: true,
      _fields: '',
      query: buildAlertQuery({
        severity: options.severity,
        status: options.status,
        createdFrom: options.createdFrom,
        createdTo: options.createdTo,
        tenant: options.tenant,
        rawQuery: options.rawQuery,
      }),
    }
    const data = await this.http.postJson(`${this.base()}/alert/_search`, body, SOAR_SCOPES.alertSearch)
    return parseSearchEnvelope<Alert>(data)
  }

  /**
   * The events an alert was raised on.
   * @param alertInternalId - the alert's `_id`, not its `alert_id`.
   */
  async getAlertEvents(alertInternalId: number): Promise<{ count: number, data: Record<string, unknown>[] }> {
    const payload = await this.http.getJson(
      `${this.base()}/alert/${Math.trunc(alertInternalId)}/artifact_event`,
      SOAR_SCOPES.alertEvents,
    )
    const rows = (payload as { data?: unknown } | null)?.data
    if (!Array.isArray(rows)) throw new Error('SOAR returned no `data` array for the alert\'s events')
    return { count: rows.length, data: rows as Record<string, unknown>[] }
  }

  /**
   * Count alerts by the value of one field, over every alert the filters match.
   *
   * SOAR has no grouping of its own, so this reads the matching alerts page by
   * page and counts here. It exists because the alternative — ranking from the
   * first page a search returns — produces a list that looks right and is not:
   * a top five taken from the newest fifty alerts is the top five of those
   * fifty. When the scan has to stop early it says so, and by how much.
   */
  async groupAlerts(options: GroupAlertsOptions): Promise<AlertGroups> {
    const query = buildAlertQuery({
      severity: options.severity,
      status: options.status,
      createdFrom: options.createdFrom,
      createdTo: options.createdTo,
      tenant: options.tenant,
      rawQuery: options.rawQuery,
    })
    const counts = new Map<string, number>()
    let total = 0
    let scanned = 0
    let missing = 0
    for (let from = 0; from < SOAR_GROUP_SCAN_LIMIT; from += SOAR_MAX_SIZE) {
      const body = {
        _from: from,
        _size: SOAR_MAX_SIZE,
        // The order every other search here uses. A closed period gains no
        // new alerts, so paging by creation time walks the set exactly once.
        _sort: '-created',
        _counting: true,
        _fields: options.field,
        query,
      }
      const page = parseSearchEnvelope<Alert>(
        await this.http.postJson(`${this.base()}/alert/_search`, body, SOAR_SCOPES.alertSearch),
      )
      total = page.count
      for (const row of page.data) {
        const value = (row as Record<string, unknown>)[options.field]
        const values = Array.isArray(value) ? value : [value]
        const named = values.filter(item => item !== null && item !== undefined && String(item).trim() !== '')
        if (named.length === 0) missing += 1
        for (const item of named) {
          const key = typeof item === 'object' ? JSON.stringify(item) : String(item)
          counts.set(key, (counts.get(key) ?? 0) + 1)
        }
      }
      scanned += page.data.length
      if (page.data.length === 0 || scanned >= total) break
    }
    const groups = [...counts.entries()]
      .map(([value, count]) => ({ value, count }))
      .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
    return {
      field: options.field,
      total,
      scanned,
      truncated: scanned < total,
      distinct: groups.length,
      missing,
      groups: groups.slice(0, Math.min(Math.max(1, Math.floor(options.top ?? 10)), 100)),
    }
  }

  async listAlertTypes(options: PageOptions = {}): Promise<SearchEnvelope<AlertType>> {
    const { page = 0, size = 100 } = options
    const body = { _from: page * size, _size: size, _counting: true }
    const data = await this.http.postJson(`${this.base()}/alert_type/_search`, body, SOAR_SCOPES.alertTypes)
    return parseSearchEnvelope<AlertType>(data)
  }

  async listAlertFields(options: PageOptions = {}): Promise<SearchEnvelope<AlertField>> {
    const { page = 0, size = 500 } = options
    const body = { _from: page * size, _size: size, _sort: 'name', _counting: true, query: '' }
    const data = await this.http.postJson(`${this.base()}/alert_field/_search`, body, SOAR_SCOPES.alertFields)
    return parseSearchEnvelope<AlertField>(data)
  }

  /**
   * Search cases. They sit beside alerts under the SOAR service and take the
   * same search body and query language; tickets are a different entity under
   * a different service.
   */
  async searchCases(options: SearchCasesOptions = {}): Promise<SearchEnvelope<Case>> {
    const { page = 0, sort = '-created' } = options
    const size = pageSize(options.size ?? 50)
    const body = {
      _from: page * size,
      _size: size,
      _sort: sort,
      _counting: true,
      _fields: '',
      query: buildAlertQuery({
        severity: options.severity,
        status: options.status,
        createdFrom: options.createdFrom,
        createdTo: options.createdTo,
        tenant: options.tenant,
        rawQuery: options.rawQuery,
      }),
    }
    const data = await this.http.postJson(`${this.base()}/case/_search`, body, SOAR_SCOPES.caseSearch)
    return parseSearchEnvelope<Case>(data)
  }

  async searchTickets(options: SearchTicketsOptions = {}): Promise<SearchEnvelope<Ticket>> {
    const { page = 0, sort = '-created' } = options
    const size = pageSize(options.size ?? 50)
    const body = {
      _from: page * size,
      _size: size,
      _sort: sort,
      _counting: true,
      _fields: '',
      query: buildAlertQuery({
        severity: options.severity,
        status: options.status,
        createdFrom: options.createdFrom,
        createdTo: options.createdTo,
        tenant: options.tenant,
        rawQuery: options.rawQuery,
      }),
    }
    // Tickets live under the ticketapi service (not soarapi) and use restricted_search.
    const data = await this.http.postJson(`/ticketapi/v1/${this.tenant}/ticket/restricted_search`, body, SOAR_SCOPES.ticketSearch)
    return parseSearchEnvelope<Ticket>(data)
  }

  async listNotifications(options: ListNotificationsOptions = {}): Promise<NotificationList> {
    const { size = 50, onlyUnread = false } = options
    // soc-client's getJson takes no params object, so the query string is built here.
    const params = new URLSearchParams({
      _from: '0',
      _size: String(size),
      _counting: 'true',
      _only_unread: String(onlyUnread),
    })
    const data = await this.http.getJson(`/notification/v1/notification?${params.toString()}`, SOAR_SCOPES.notifications)
    return parseNotificationList(data)
  }
}
