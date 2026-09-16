/**
 * EdrAdapter — turns the raw EDR API into clean models.
 *
 * Mirrors the SOAR slice's `adapter.ts`. Every HTTP call goes through the
 * injected client (structurally compatible with soc-client's `SocHttp`); this
 * module never touches `fetch` directly. Unlike SOAR there is no per-scope
 * argument: one EDR token is global for every endpoint, so the client carries
 * the credential itself and these methods pass only path and body.
 */

import {
  type EdrAgent,
  type EdrAlert,
  type EdrEvent,
  type EdrFieldList,
  type EdrHuntingEntry,
  type EdrSearchEnvelope,
  parseEdrFieldList,
  parseEdrSearchEnvelope,
} from './contracts.ts'

/** The slice of soc-client's `SocHttp` this adapter needs. */
export interface EdrHttp {
  postJson<T = unknown>(path: string, body: unknown): Promise<T>
  getJson<T = unknown>(path: string): Promise<T>
}

/** EDR API paths, read from the EDR SPA's route map. No tenant path segment. */
export const EDR_PATHS = {
  eventSearch: '/eventHandler/Search',
  eventFields: '/eventHandler/GetEventFieldList',
  alertSearch: '/msalert/Search',
  alertFields: '/msalert/GetAlertFieldList',
  agentSearch: '/agentManagement/Search',
  huntingHistory: '/threatHunting/HistorySearch',
} as const

/** Filters shared by the event and alert searches. */
export interface SearchOptions {
  /** Free-text EDR query expression, sent verbatim as `search_query_str`. */
  searchQuery?: string | null | undefined
  /** A relative time window, in seconds (e.g. the last 3600s). */
  lastSeconds?: number | null | undefined
  /** Absolute window start, epoch milliseconds. */
  fromTimestamp?: number | null | undefined
  /** Absolute window end, epoch milliseconds. */
  toTimestamp?: number | null | undefined
  /** A `since` cursor, epoch milliseconds. */
  since?: number | null | undefined
  sort?: string | undefined
  limit?: number | undefined
}

export interface SearchEventsOptions extends SearchOptions {
  /** Quick keyword search, sent as `keyQuickSearch`. */
  keyQuickSearch?: string | null | undefined
}

export type SearchAlertsOptions = SearchOptions

export interface SearchAgentsOptions {
  query?: string | null | undefined
  since?: number | null | undefined
  limit?: number | undefined
}

export interface HuntingHistoryOptions {
  from?: number | undefined
  size?: number | undefined
}

/**
 * Whether to send `is_use_last_seconds`: explicit when the caller set the flag,
 * otherwise inferred from a `last_seconds` value being present.
 */
function useLastSeconds(explicit: boolean | undefined, lastSeconds: number | null | undefined): boolean {
  return explicit ?? (lastSeconds !== null && lastSeconds !== undefined)
}

export class EdrAdapter {
  private readonly http: EdrHttp

  constructor(http: EdrHttp) {
    this.http = http
  }

  async searchEvents(options: SearchEventsOptions = {}): Promise<EdrSearchEnvelope<EdrEvent>> {
    const { limit = 50, sort = '' } = options
    const body = {
      is_use_last_seconds: useLastSeconds(undefined, options.lastSeconds),
      keyQuickSearch: options.keyQuickSearch ?? '',
      last_seconds: options.lastSeconds ?? 0,
      since: options.since ?? 0,
      sort,
      limit,
      from_timestamp: options.fromTimestamp ?? 0,
      to_timestamp: options.toTimestamp ?? 0,
      search_query_str: options.searchQuery ?? '',
    }
    const data = await this.http.postJson(EDR_PATHS.eventSearch, body)
    return parseEdrSearchEnvelope<EdrEvent>(data, 'data')
  }

  async searchAlerts(options: SearchAlertsOptions = {}): Promise<EdrSearchEnvelope<EdrAlert>> {
    const { limit = 50, sort = '' } = options
    const body = {
      search_query_str: options.searchQuery ?? '',
      since: options.since ?? 0,
      limit,
      sort,
      last_seconds: options.lastSeconds ?? 0,
      from_timestamp: options.fromTimestamp ?? 0,
      to_timestamp: options.toTimestamp ?? 0,
      is_use_last_seconds: useLastSeconds(undefined, options.lastSeconds),
    }
    const data = await this.http.postJson(EDR_PATHS.alertSearch, body)
    return parseEdrSearchEnvelope<EdrAlert>(data, 'data')
  }

  async searchAgents(options: SearchAgentsOptions = {}): Promise<EdrSearchEnvelope<EdrAgent>> {
    const { limit = 50 } = options
    const body = {
      query: options.query ?? '',
      limit,
      since: options.since ?? 0,
    }
    const data = await this.http.postJson(EDR_PATHS.agentSearch, body)
    return parseEdrSearchEnvelope<EdrAgent>(data, 'agent_infos')
  }

  async threatHuntingHistory(options: HuntingHistoryOptions = {}): Promise<EdrSearchEnvelope<EdrHuntingEntry>> {
    const { from = 0, size = 50 } = options
    const body = { from, size }
    const data = await this.http.postJson(EDR_PATHS.huntingHistory, body)
    return parseEdrSearchEnvelope<EdrHuntingEntry>(data, 'list')
  }

  async listEventFields(): Promise<EdrFieldList> {
    const data = await this.http.postJson(EDR_PATHS.eventFields, {})
    return parseEdrFieldList(data)
  }

  async listAlertFields(): Promise<EdrFieldList> {
    const data = await this.http.getJson(EDR_PATHS.alertFields)
    return parseEdrFieldList(data)
  }
}
