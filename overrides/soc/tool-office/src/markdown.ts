/**
 * The small Markdown subset a model writes documents in: headings, paragraphs,
 * bullet and numbered lists (two levels), pipe tables, block quotes, page
 * breaks, and inline bold, italic and code. Parsed into blocks that each
 * document builder renders in its own format.
 */

export interface Run { text: string, bold?: boolean, italic?: boolean, code?: boolean }

export type Block =
  | { kind: 'heading', level: number, runs: Run[] }
  | { kind: 'paragraph', runs: Run[] }
  | { kind: 'quote', runs: Run[] }
  | { kind: 'list', ordered: boolean, items: { level: number, runs: Run[] }[] }
  | { kind: 'table', header: Run[][], rows: Run[][][] }
  | { kind: 'pagebreak' }

/** Split inline text into runs: `**bold**`, `*italic*` or `_italic_`, `` `code` ``. */
export function parseInline(text: string): Run[] {
  const runs: Run[] = []
  const pattern = /(\*\*([^*]+)\*\*|__([^_]+)__|\*([^*]+)\*|_([^_]+)_|`([^`]+)`)/g
  let last = 0
  for (const match of text.matchAll(pattern)) {
    if (match.index! > last) runs.push({ text: text.slice(last, match.index) })
    if (match[2] ?? match[3]) runs.push({ text: (match[2] ?? match[3])!, bold: true })
    else if (match[4] ?? match[5]) runs.push({ text: (match[4] ?? match[5])!, italic: true })
    else runs.push({ text: match[6]!, code: true })
    last = match.index! + match[0].length
  }
  if (last < text.length) runs.push({ text: text.slice(last) })
  return runs.length > 0 ? runs : [{ text: '' }]
}

/** The plain text of some runs. */
export function plain(runs: Run[]): string {
  return runs.map(run => run.text).join('')
}

const TABLE_ROW = /^\s*\|.*\|\s*$/
const TABLE_RULE = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/
const cells = (line: string) => line.trim().replace(/^\||\|$/g, '').split('|').map(cell => parseInline(cell.trim()))

/** Parse Markdown into blocks. */
export function parseMarkdown(source: string): Block[] {
  const lines = source.replace(/\r\n?/g, '\n').split('\n')
  const blocks: Block[] = []
  let paragraph: string[] = []
  const flush = () => {
    if (paragraph.length > 0) blocks.push({ kind: 'paragraph', runs: parseInline(paragraph.join(' ')) })
    paragraph = []
  }
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!
    const heading = /^(#{1,6})\s+(.*)$/.exec(line)
    const item = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/.exec(line)
    if (line.trim() === '') { flush(); continue }
    if (/^\s*(\\pagebreak|<!--\s*pagebreak\s*-->|---\s*pagebreak\s*---)\s*$/i.test(line)) { flush(); blocks.push({ kind: 'pagebreak' }); continue }
    if (heading) { flush(); blocks.push({ kind: 'heading', level: heading[1]!.length, runs: parseInline(heading[2]!.trim()) }); continue }
    if (TABLE_ROW.test(line) && TABLE_RULE.test(lines[i + 1] ?? '')) {
      flush()
      const header = cells(line)
      const rows: Run[][][] = []
      i += 2
      while (i < lines.length && TABLE_ROW.test(lines[i]!)) rows.push(cells(lines[i++]!))
      i--
      blocks.push({ kind: 'table', header, rows })
      continue
    }
    if (item) {
      flush()
      const ordered = /\d/.test(item[2]!)
      const items: { level: number, runs: Run[] }[] = []
      let j = i
      while (j < lines.length) {
        const m = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/.exec(lines[j]!)
        if (!m || /\d/.test(m[2]!) !== ordered) break
        items.push({ level: m[1]!.replace(/\t/g, '    ').length >= 2 ? 1 : 0, runs: parseInline(m[3]!) })
        j++
      }
      blocks.push({ kind: 'list', ordered, items })
      i = j - 1
      continue
    }
    if (/^\s*>\s?/.test(line)) { flush(); blocks.push({ kind: 'quote', runs: parseInline(line.replace(/^\s*>\s?/, '')) }); continue }
    paragraph.push(line.trim())
  }
  flush()
  return blocks
}
