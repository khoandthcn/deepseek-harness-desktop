/**
 * Build the SOAR `_search` query DSL (xtext) from structured filters.
 *
 * Ported 1-to-1 from socp-mcp `modules/soar_query.py`.
 */

export interface AlertQueryFilters {
  severity?: string | null | undefined
  status?: string | null | undefined
  createdFrom?: number | null | undefined
  createdTo?: number | null | undefined
  /** A raw xtext expression, ANDed with the structured clauses. */
  rawQuery?: string | null | undefined
}

/**
 * Escape a value for a double-quoted DSL string literal.
 *
 * Backslashes are escaped FIRST, then double quotes — otherwise a value ending
 * in `\` (or containing `\"`) could break out of the literal if xtext treats
 * `\` as an escape character.
 */
function quote(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

/**
 * AND-join the given clauses, the raw query among them.
 *
 * The raw query used to replace every structured clause. A caller that passed
 * a period and a raw tenant filter together then searched all of time without
 * being told, which is the difference between a month's count and a wrong one.
 * It is parenthesised so an `OR` inside it cannot escape the other filters.
 */
export function buildAlertQuery(filters: AlertQueryFilters = {}): string {
  const { severity, status, createdFrom, createdTo, rawQuery } = filters

  const clauses: string[] = []
  const raw = rawQuery?.trim()
  if (raw) clauses.push(`( ${raw} )`)
  if (severity) clauses.push(`severity = "${quote(severity)}"`)
  if (status) clauses.push(`status = "${quote(status)}"`)

  const from = createdFrom ?? null
  const to = createdTo ?? null
  if (from !== null && to !== null) {
    clauses.push(`( created >= ${Math.trunc(from)} AND created <= ${Math.trunc(to)} )`)
  } else if (from !== null) {
    clauses.push(`created >= ${Math.trunc(from)}`)
  } else if (to !== null) {
    clauses.push(`created <= ${Math.trunc(to)}`)
  }

  // A raw query on its own goes through exactly as written.
  return clauses.length === 1 && raw ? raw : clauses.join(' AND ')
}
