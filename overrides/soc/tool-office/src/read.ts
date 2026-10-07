/**
 * Read an office document into text a model can work with: Markdown for Word,
 * a Markdown table per sheet for Excel and CSV, text per slide for PowerPoint,
 * text per page for PDF.
 */
import ExcelJSImport from 'exceljs'
import JSZipImport from 'jszip'
import mammothImport from 'mammoth'
import { extractText, getDocumentProxy } from 'unpdf'
import { parseCsv } from './csv.ts'
import { cjs } from './interop.ts'

const ExcelJS = cjs<typeof ExcelJSImport>(ExcelJSImport)
const JSZip = cjs<typeof JSZipImport>(JSZipImport)
const mammoth = cjs<typeof mammothImport>(mammothImport)

export type OfficeFormat = 'docx' | 'xlsx' | 'pptx' | 'pdf' | 'csv' | 'tsv'

/** The format a file name names, or undefined for one this package does not read. */
export function formatOf(path: string): OfficeFormat | undefined {
  const ext = /\.([a-z0-9]+)$/i.exec(path)?.[1]?.toLowerCase()
  switch (ext) {
    case 'docx': case 'docm': return 'docx'
    case 'xlsx': case 'xlsm': return 'xlsx'
    case 'pptx': case 'pptm': return 'pptx'
    case 'pdf': return 'pdf'
    case 'csv': return 'csv'
    case 'tsv': case 'tab': return 'tsv'
    default: return undefined
  }
}

export interface ReadOptions {
  /** Excel: only this sheet (name or 1-based index). */
  sheet?: string | undefined
  /** Excel and CSV: rows per table before it is cut, header included. */
  maxRows?: number | undefined
  /** PDF and PowerPoint: a page or slide range such as "1-3,7". */
  pages?: string | undefined
}

export interface ReadResult {
  format: OfficeFormat
  /** What the document holds, in Markdown. */
  text: string
  /** Counts that say how much there is: sheets, rows, slides, pages. */
  summary: Record<string, unknown>
}

/**
 * A range such as "3,1-2" as page numbers in the order written, within 1..last.
 * Repeats are kept: extracting "1,1" gives the page twice.
 */
export function pageList(range: string | undefined, last: number): number[] {
  if (range === undefined || range.trim() === '') return Array.from({ length: last }, (_, i) => i + 1)
  const out: number[] = []
  for (const part of range.split(',')) {
    const m = /^\s*(\d+)\s*(?:-\s*(\d+)?\s*)?$/.exec(part)
    if (!m) throw new Error(`cannot read the page range "${range}": use numbers and ranges like "1-3,7"`)
    const from = Number(m[1])
    const to = m[2] !== undefined ? Number(m[2]) : part.includes('-') ? last : from
    for (let n = Math.max(1, from); n <= Math.min(last, to); n++) out.push(n)
  }
  return out
}

/** A range such as "1-3,7" as a set of 1-based numbers within 1..last. */
export function pageSet(range: string | undefined, last: number): number[] {
  if (range === undefined || range.trim() === '') return Array.from({ length: last }, (_, i) => i + 1)
  const out = new Set<number>()
  for (const part of range.split(',')) {
    const m = /^\s*(\d+)\s*(?:-\s*(\d+)?\s*)?$/.exec(part)
    if (!m) throw new Error(`cannot read the page range "${range}": use numbers and ranges like "1-3,7"`)
    const from = Number(m[1])
    const to = m[2] !== undefined ? Number(m[2]) : part.includes('-') ? last : from
    for (let n = Math.max(1, from); n <= Math.min(last, to); n++) out.add(n)
  }
  return [...out].sort((a, b) => a - b)
}

/** A cell value as the text a reader would see. */
export function cellText(value: unknown): string {
  if (value === null || value === undefined) return ''
  if (value instanceof Date) return value.toISOString().replace('T00:00:00.000Z', '').replace(/\.000Z$/, 'Z')
  if (typeof value === 'object') {
    const v = value as { result?: unknown, formula?: string, sharedFormula?: string, richText?: { text: string }[], text?: string, hyperlink?: string, error?: string }
    if (v.richText) return v.richText.map(part => part.text).join('')
    if (v.formula !== undefined || v.sharedFormula !== undefined) {
      return v.result !== undefined && v.result !== null ? cellText(v.result) : `=${v.formula ?? v.sharedFormula}`
    }
    if (v.text !== undefined) return String(v.text)
    if (v.error !== undefined) return String(v.error)
    return JSON.stringify(value)
  }
  return String(value)
}

const escapeCell = (text: string) => text.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ')

/** Rows as a Markdown table, the first row taken as the header. */
export function markdownTable(rows: string[][]): string {
  if (rows.length === 0) return '_(empty)_'
  const width = Math.max(...rows.map(row => row.length), 1)
  const pad = (row: string[]) => Array.from({ length: width }, (_, i) => escapeCell(row[i] ?? ''))
  const [head, ...body] = rows
  return [
    `| ${pad(head!).join(' | ')} |`,
    `| ${Array(width).fill('---').join(' | ')} |`,
    ...body.map(row => `| ${pad(row).join(' | ')} |`),
  ].join('\n')
}

const decodeHtml = (text: string) => text
  .replace(/<br\s*\/?>/gi, ' ').replace(/<[^>]+>/g, '')
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
  .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n))).replace(/&amp;/g, '&')

/** Inline HTML as Markdown: strong, em and links kept, everything else as text. */
function inlineMarkdown(html: string): string {
  return decodeHtml(html
    .replace(/<(strong|b)>([\s\S]*?)<\/\1>/gi, '**$2**')
    .replace(/<(em|i)>([\s\S]*?)<\/\1>/gi, '*$2*')
    .replace(/<a [^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi, '[$2]($1)'))
    .replace(/\s+/g, ' ').trim()
}

/**
 * The HTML Word documents convert to, as Markdown. Mammoth's own Markdown
 * writer drops tables, and tables are often what a document is read for.
 */
export function htmlToMarkdown(html: string): string {
  const out: string[] = []
  const blocks = html.match(/<(h[1-6]|p|ul|ol|table|blockquote)\b[^>]*>[\s\S]*?<\/\1>/gi) ?? []
  for (const block of blocks) {
    const tag = /^<([a-z0-9]+)/i.exec(block)![1]!.toLowerCase()
    const inner = block.replace(/^<[^>]+>|<\/[^>]+>$/g, '')
    if (/^h[1-6]$/.test(tag)) out.push(`${'#'.repeat(Number(tag[1]))} ${inlineMarkdown(inner)}`)
    else if (tag === 'p') { const text = inlineMarkdown(inner); if (text) out.push(text) }
    else if (tag === 'blockquote') out.push(`> ${inlineMarkdown(inner)}`)
    else if (tag === 'ul' || tag === 'ol') {
      const lines: string[] = []
      const walk = (list: string, depth: number, ordered: boolean) => {
        let n = 0
        for (const item of list.match(/<li>[\s\S]*?<\/li>(?![\s\S]*?<\/li>[\s\S]*?<\/(?:ul|ol)>[\s\S]*?<li>)/gi) ?? []) {
          const nested = /<(ul|ol)>([\s\S]*)<\/\1>/i.exec(item)
          const own = item.replace(/<(ul|ol)>[\s\S]*<\/\1>/i, '')
          n += 1
          lines.push(`${'  '.repeat(depth)}${ordered ? `${n}.` : '-'} ${inlineMarkdown(own)}`)
          if (nested) walk(nested[2]!, depth + 1, nested[1]!.toLowerCase() === 'ol')
        }
      }
      walk(inner, 0, tag === 'ol')
      out.push(lines.join('\n'))
    } else if (tag === 'table') {
      const rows = (block.match(/<tr>[\s\S]*?<\/tr>/gi) ?? []).map(row =>
        (row.match(/<t[dh][^>]*>[\s\S]*?<\/t[dh]>/gi) ?? []).map(cell => inlineMarkdown(cell.replace(/<\/p>\s*<p>/gi, ' '))))
      out.push(markdownTable(rows))
    }
  }
  return out.join('\n\n')
}

async function readDocx(bytes: Uint8Array): Promise<ReadResult> {
  const { value } = await mammoth.convertToHtml({ buffer: Buffer.from(bytes) })
  const text = htmlToMarkdown(value).trim()
  return { format: 'docx', text, summary: { characters: text.length } }
}

async function readXlsx(bytes: Uint8Array, options: ReadOptions): Promise<ReadResult> {
  const workbook = new ExcelJS.Workbook()
  await workbook.xlsx.load(Buffer.from(bytes) as unknown as ArrayBuffer)
  const maxRows = options.maxRows ?? 200
  const sheets = workbook.worksheets
  const wanted = options.sheet === undefined ? sheets
    : sheets.filter((sheet, i) => sheet.name === options.sheet || String(i + 1) === options.sheet)
  if (wanted.length === 0) {
    throw new Error(`no sheet "${options.sheet}"; the workbook has: ${sheets.map(s => s.name).join(', ')}`)
  }
  const parts: string[] = []
  const summary: Record<string, unknown> = { sheets: sheets.map(s => ({ name: s.name, rows: s.actualRowCount, columns: s.actualColumnCount })) }
  for (const sheet of wanted) {
    const rows: string[][] = []
    sheet.eachRow({ includeEmpty: false }, row => {
      const values = row.values as unknown[]
      rows.push(values.slice(1).map(cellText))
    })
    const shown = rows.slice(0, maxRows)
    parts.push(`## Sheet: ${sheet.name}\n\n${markdownTable(shown)}`
      + (rows.length > shown.length ? `\n\n_(${rows.length - shown.length} more rows not shown; pass max_rows to see more)_` : ''))
  }
  return { format: 'xlsx', text: parts.join('\n\n'), summary }
}

function readDelimited(bytes: Uint8Array, format: 'csv' | 'tsv', options: ReadOptions): ReadResult {
  const text = new TextDecoder('utf-8').decode(bytes)
  const rows = format === 'tsv' ? parseCsv(text, '\t') : parseCsv(text)
  const maxRows = options.maxRows ?? 200
  const shown = rows.slice(0, maxRows)
  return {
    format,
    text: markdownTable(shown) + (rows.length > shown.length ? `\n\n_(${rows.length - shown.length} more rows not shown; pass max_rows to see more)_` : ''),
    summary: { rows: rows.length, columns: Math.max(0, ...rows.map(row => row.length)) },
  }
}

const decodeXml = (text: string) => text
  .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'")
  .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n))).replace(/&amp;/g, '&')

/** The paragraphs of a DrawingML part, one line each. */
function drawingText(xml: string): string {
  return xml.split(/<\/a:p>/).map(paragraph => [...paragraph.matchAll(/<a:t(?:\s[^>]*)?>([^<]*)<\/a:t>/g)].map(m => decodeXml(m[1]!)).join(''))
    .filter(line => line.trim() !== '').join('\n')
}

async function readPptx(bytes: Uint8Array, options: ReadOptions): Promise<ReadResult> {
  const zip = await JSZip.loadAsync(bytes)
  const slideNames = Object.keys(zip.files).filter(name => /^ppt\/slides\/slide\d+\.xml$/.test(name))
    .sort((a, b) => Number(/(\d+)\.xml$/.exec(a)![1]) - Number(/(\d+)\.xml$/.exec(b)![1]))
  const wanted = pageSet(options.pages, slideNames.length)
  const parts: string[] = []
  for (const n of wanted) {
    const xml = await zip.file(slideNames[n - 1]!)!.async('string')
    const notesName = `ppt/notesSlides/notesSlide${/(\d+)\.xml$/.exec(slideNames[n - 1]!)![1]}.xml`
    // A notes page also carries the slide-number field; only the speaker's text is wanted.
    const notes = zip.file(notesName)
      ? drawingText(await zip.file(notesName)!.async('string')).split('\n').filter(line => !/^\s*\d+\s*$/.test(line)).join('\n')
      : ''
    parts.push(`## Slide ${n}\n\n${drawingText(xml) || '_(no text)_'}${notes ? `\n\n_Notes:_ ${notes.replace(/\n/g, ' ')}` : ''}`)
  }
  return { format: 'pptx', text: parts.join('\n\n'), summary: { slides: slideNames.length } }
}

async function readPdf(bytes: Uint8Array, options: ReadOptions): Promise<ReadResult> {
  const pdf = await getDocumentProxy(new Uint8Array(bytes))
  const { totalPages, text } = await extractText(pdf, { mergePages: false })
  const pages = text as unknown as string[]
  const wanted = pageSet(options.pages, totalPages)
  const body = wanted.map(n => `## Page ${n}\n\n${(pages[n - 1] ?? '').trim() || '_(no text: a scanned page needs OCR)_'}`).join('\n\n')
  return { format: 'pdf', text: body, summary: { pages: totalPages } }
}

/**
 * Read a document's bytes.
 * @param bytes - the file content.
 * @param format - its format, from {@link formatOf}.
 */
export async function readOffice(bytes: Uint8Array, format: OfficeFormat, options: ReadOptions = {}): Promise<ReadResult> {
  switch (format) {
    case 'docx': return readDocx(bytes)
    case 'xlsx': return readXlsx(bytes, options)
    case 'pptx': return readPptx(bytes, options)
    case 'pdf': return readPdf(bytes, options)
    case 'csv': case 'tsv': return readDelimited(bytes, format, options)
  }
}
