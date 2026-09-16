/**
 * EDR response shapes.
 *
 * Mirrors the SOAR slice's `contracts.ts`: the named fields are the ones the
 * model reads, and every entity carries an index signature so the remaining
 * fields pass through untouched. Validation is hand-rolled — no runtime schema
 * library. EDR's search endpoints return `{ <listKey>: [...], total }`, and its
 * field-list endpoints return `{ data: { <field>: <meta> } }`.
 */

export interface Extra {
  [key: string]: unknown
}

/** Normalised envelope of an EDR `Search`/`HistorySearch` endpoint. */
export interface EdrSearchEnvelope<T> {
  total: number
  items: T[]
}

/** A dictionary of field definitions keyed by field name. */
export interface EdrFieldList {
  fields: Record<string, unknown>
}

/** An EDR raw event; unknown fields pass through. */
export interface EdrEvent extends Extra {
  _id?: string | null | undefined
  timestamp?: number | null | undefined
  agent_id?: string | null | undefined
  hostname?: string | null | undefined
  event_type?: string | null | undefined
}

/** An EDR alert; unknown fields pass through. */
export interface EdrAlert extends Extra {
  _id?: string | null | undefined
  alert_id?: string | null | undefined
  severity?: string | null | undefined
  status?: string | null | undefined
  timestamp?: number | null | undefined
  agent_id?: string | null | undefined
  hostname?: string | null | undefined
}

/** An EDR agent (endpoint) record; unknown fields pass through. */
export interface EdrAgent extends Extra {
  agent_id?: string | null | undefined
  hostname?: string | null | undefined
  os?: string | null | undefined
  status?: string | null | undefined
  last_seen?: number | null | undefined
}

/** A threat-hunting history entry; unknown fields pass through. */
export interface EdrHuntingEntry extends Extra {
  _id?: string | null | undefined
  created?: number | null | undefined
  query?: string | null | undefined
  status?: string | null | undefined
}

/** Raised when an upstream payload does not match the expected shape. */
export class EdrContractError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EdrContractError'
  }
}

function asRecord(data: unknown, what: string): Record<string, unknown> {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new EdrContractError(`Expected a ${what} object, got ${describe(data)}`)
  }
  return data as Record<string, unknown>
}

function describe(data: unknown): string {
  if (data === null) return 'null'
  return Array.isArray(data) ? 'an array' : typeof data
}

/**
 * Validate an EDR search envelope. The list of results lives under `listKey`
 * (`data`, `agent_infos`, or `list` depending on the endpoint) and the total
 * count under `countKey` (`total`); both default to empty/0 when absent.
 * @param data - the raw upstream JSON.
 * @param listKey - the field the results array lives under.
 * @param countKey - the field the total count lives under.
 */
export function parseEdrSearchEnvelope<T>(
  data: unknown,
  listKey: string,
  countKey = 'total',
): EdrSearchEnvelope<T> {
  const obj = asRecord(data, 'search envelope')
  const rawItems = obj[listKey] ?? []
  if (!Array.isArray(rawItems)) {
    throw new EdrContractError(`Search envelope \`${listKey}\` must be an array`)
  }
  const total = obj[countKey] ?? 0
  if (typeof total !== 'number') {
    throw new EdrContractError(`Search envelope \`${countKey}\` must be a number`)
  }
  return { total, items: rawItems as T[] }
}

/** Validate a field-list payload: `data` must be a dictionary of definitions. */
export function parseEdrFieldList(data: unknown): EdrFieldList {
  const obj = asRecord(data, 'field list')
  const fields = obj.data ?? {}
  if (typeof fields !== 'object' || fields === null || Array.isArray(fields)) {
    throw new EdrContractError('Field list `data` must be an object')
  }
  return { fields: fields as Record<string, unknown> }
}
