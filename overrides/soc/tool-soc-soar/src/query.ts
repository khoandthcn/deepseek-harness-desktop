/**
 * Build the SOAR `_search` query DSL (xtext) from structured filters.
 *
 * Ported 1-to-1 from socp-mcp `modules/soar_query.py`.
 */

export interface AlertQueryFilters {
  severity?: string | null
  status?: string | null
  createdFrom?: number | null
  createdTo?: number | null
  /** Escape hatch: used verbatim, skipping every structured clause. */
  rawQuery?: string | null
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

/** AND-join the given clauses; `rawQuery` (when present) wins outright. */
export function buildAlertQuery(filters: AlertQueryFilters = {}): string {
  const { severity, status, createdFrom, createdTo, rawQuery } = filters
  if (rawQuery) return rawQuery

  const clauses: string[] = []
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

  return clauses.join(' AND ')
}
