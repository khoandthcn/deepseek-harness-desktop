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
  postJson<T = unknown>(path: string, body: unknown): Promise<T>
  getJson<T = unknown>(path: string): Promise<T>
}

export interface SearchAlertsOptions {
  severity?: string | null
  status?: string | null
  createdFrom?: number | null
  createdTo?: number | null
  rawQuery?: string | null
  page?: number
  size?: number
  sort?: string
}

export interface PageOptions {
  page?: number
  size?: number
}

export interface SearchTicketsOptions extends PageOptions {
  rawQuery?: string | null
  sort?: string
}

export interface ListNotificationsOptions {
  size?: number
  onlyUnread?: boolean
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
    const data = await this.http.postJson(`${this.base()}/alert/_search`, body)
    return parseSearchEnvelope<Alert>(data)
  }

  async listAlertTypes(options: PageOptions = {}): Promise<SearchEnvelope<AlertType>> {
    const { page = 0, size = 100 } = options
    const body = { _from: page * size, _size: size, _counting: true }
    const data = await this.http.postJson(`${this.base()}/alert_type/_search`, body)
    return parseSearchEnvelope<AlertType>(data)
  }

  async listAlertFields(options: PageOptions = {}): Promise<SearchEnvelope<AlertField>> {
    const { page = 0, size = 500 } = options
    const body = { _from: page * size, _size: size, _sort: 'name', _counting: true, query: '' }
    const data = await this.http.postJson(`${this.base()}/alert_field/_search`, body)
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
    const data = await this.http.postJson(`${this.base()}/ticket/_search`, body)
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
    const data = await this.http.getJson(`/notification/v1/notification?${params.toString()}`)
    return parseNotificationList(data)
  }
}
