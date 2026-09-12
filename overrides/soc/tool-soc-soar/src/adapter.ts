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
  ticketSearch: 'read:ticket',
  notifications: 'read:notification',
} as const

export interface SearchAlertsOptions {
  severity?: string | null | undefined
  status?: string | null | undefined
  createdFrom?: number | null | undefined
  createdTo?: number | null | undefined
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
    const { page = 0, size = 50, sort = '-created' } = options
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
        rawQuery: options.rawQuery,
      }),
    }
    const data = await this.http.postJson(`${this.base()}/alert/_search`, body, SOAR_SCOPES.alertSearch)
    return parseSearchEnvelope<Alert>(data)
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

  async searchTickets(options: SearchTicketsOptions = {}): Promise<SearchEnvelope<Ticket>> {
    const { page = 0, size = 50, sort = '-created' } = options
    const body = {
      _from: page * size,
      _size: size,
      _sort: sort,
      _counting: true,
      _fields: '',
      query: options.rawQuery || '',
    }
    const data = await this.http.postJson(`${this.base()}/ticket/_search`, body, SOAR_SCOPES.ticketSearch)
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
