/** CSV and TSV, read and written the way spreadsheets exchange them (RFC 4180 quoting). */

/** Which separator a delimited text most likely uses: the one that splits its first line most. */
export function sniffDelimiter(text: string): string {
  const firstLine = text.split(/\r?\n/, 1)[0] ?? ''
  const counts = [',', ';', '\t', '|'].map(sep => [sep, firstLine.split(sep).length] as const)
  counts.sort((a, b) => b[1] - a[1])
  return counts[0]![1] > 1 ? counts[0]![0] : ','
}

/**
 * Parse delimited text into rows of cells.
 * @param text - the file's text; a byte-order mark is ignored.
 * @param delimiter - the separator; sniffed from the first line when omitted.
 */
export function parseCsv(text: string, delimiter = sniffDelimiter(text)): string[][] {
  const source = text.replace(/^﻿/, '')
  const rows: string[][] = []
  let row: string[] = []
  let cell = ''
  let quoted = false
  for (let i = 0; i < source.length; i++) {
    const ch = source[i]!
    if (quoted) {
      if (ch === '"') {
        if (source[i + 1] === '"') { cell += '"'; i++ } else quoted = false
      } else cell += ch
      continue
    }
    if (ch === '"' && cell === '') quoted = true
    else if (ch === delimiter) { row.push(cell); cell = '' }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && source[i + 1] === '\n') i++
      row.push(cell); rows.push(row); row = []; cell = ''
    } else cell += ch
  }
  if (cell !== '' || row.length > 0) { row.push(cell); rows.push(row) }
  return rows
}

/** Write rows as CSV, quoting only the cells that need it. */
export function toCsv(rows: readonly (readonly unknown[])[], delimiter = ','): string {
  const quote = (value: unknown) => {
    const text = value === null || value === undefined ? '' : value instanceof Date ? value.toISOString() : String(value)
    return /["\r\n]/.test(text) || text.includes(delimiter) ? `"${text.replace(/"/g, '""')}"` : text
  }
  return rows.map(row => row.map(quote).join(delimiter)).join('\r\n') + '\r\n'
}
