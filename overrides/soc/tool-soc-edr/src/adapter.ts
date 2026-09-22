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

/** A search with no explicit window covers the last 24h, matching the SPA default. */
const EDR_DEFAULT_WINDOW_SECONDS = 86400
/**
 * Whether a search should read the relative window. EDR carries both windows in
 * one body and this flag decides which one counts, so an explicit absolute bound
 * has to clear it or it would never take effect.
 * @param options - the window options a search was given.
 * @returns true when no absolute bound was given.
 */
function usesRelativeWindow(options: { fromTimestamp?: number | null | undefined, toTimestamp?: number | null | undefined }): boolean {
  return (options.fromTimestamp ?? 0) === 0 && (options.toTimestamp ?? 0) === 0
}

/** Sort shapes the EDR API expects (an object, not a string). */
const EDR_EVENT_SORT = { field: 'TimeStamp', direction: 'desc' } as const
const EDR_ALERT_SORT = { field: 'timestamp_create', direction: 'desc' } as const

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
  sort?: { field: string, direction: string } | undefined
  limit?: number | undefined
}

export interface SearchEventsOptions extends SearchOptions {
  /** Quick keyword search, sent as `keyQuickSearch`. */
  keyQuickSearch?: string | null | undefined
}

export type SearchAlertsOptions = SearchOptions

export interface SearchAgentsOptions {
  query?: Record<string, unknown> | null | undefined
  since?: number | null | undefined
  limit?: number | undefined
}

export interface HuntingHistoryOptions {
  from?: number | undefined
  size?: number | undefined
}

export class EdrAdapter {
  private readonly http: EdrHttp

  constructor(http: EdrHttp) {
    this.http = http
  }

  async searchEvents(options: SearchEventsOptions = {}): Promise<EdrSearchEnvelope<EdrEvent>> {
    const { limit = 50, sort = EDR_EVENT_SORT } = options
    const body = {
      // The flag picks which window the API reads: with it set, the absolute
      // bounds this call also carries would be ignored.
      is_use_last_seconds: usesRelativeWindow(options),
      keyQuickSearch: options.keyQuickSearch ?? '',
      last_seconds: options.lastSeconds ?? EDR_DEFAULT_WINDOW_SECONDS,
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
    const { limit = 50, sort = EDR_ALERT_SORT } = options
    const body = {
      search_query_str: options.searchQuery ?? '',
      since: options.since ?? 0,
      limit,
      sort,
      last_seconds: options.lastSeconds ?? EDR_DEFAULT_WINDOW_SECONDS,
      from_timestamp: options.fromTimestamp ?? 0,
      to_timestamp: options.toTimestamp ?? 0,
      is_use_last_seconds: usesRelativeWindow(options),
    }
    const data = await this.http.postJson(EDR_PATHS.alertSearch, body)
    return parseEdrSearchEnvelope<EdrAlert>(data, 'data')
  }

  async searchAgents(options: SearchAgentsOptions = {}): Promise<EdrSearchEnvelope<EdrAgent>> {
    const { limit = 100 } = options
    const body = {
      query: options.query ?? {},
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
