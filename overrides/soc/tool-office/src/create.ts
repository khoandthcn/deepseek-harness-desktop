/** Build Word, Excel and PowerPoint files from what a model can write: Markdown and rows. */
import {
  AlignmentType, BorderStyle, Document, HeadingLevel, LevelFormat, Packer, PageBreak, Paragraph,
  ShadingType, Table, TableCell, TableRow, TextRun, WidthType,
} from 'docx'
import ExcelJSImport from 'exceljs'
import PptxGenJSImport from 'pptxgenjs'
import { cjs } from './interop.ts'
import { parseMarkdown, plain, type Block, type Run } from './markdown.ts'

const ExcelJS = cjs<typeof ExcelJSImport>(ExcelJSImport)
const PptxGenJS = cjs<typeof PptxGenJSImport>(PptxGenJSImport)

const HEADINGS = [HeadingLevel.HEADING_1, HeadingLevel.HEADING_2, HeadingLevel.HEADING_3, HeadingLevel.HEADING_4, HeadingLevel.HEADING_5, HeadingLevel.HEADING_6]

const textRuns = (runs: Run[], extra: { bold?: boolean } = {}) => runs.map(run => new TextRun({
  text: run.text,
  ...(run.bold || extra.bold ? { bold: true } : {}),
  ...(run.italic ? { italics: true } : {}),
  ...(run.code ? { font: 'Consolas' } : {}),
}))

export interface DocxOptions {
  /** Shown in the file's properties; also a title heading when the Markdown has no top heading. */
  title?: string | undefined
  /** Body font, e.g. "Times New Roman"; Calibri by default. */
  font?: string | undefined
  /** Body size in points; 11 by default. */
  fontSize?: number | undefined
}

/** A Word document from Markdown. */
export async function buildDocx(markdown: string, options: DocxOptions = {}): Promise<Uint8Array> {
  const blocks = parseMarkdown(markdown)
  if (options.title && !blocks.some(block => block.kind === 'heading' && block.level === 1)) {
    blocks.unshift({ kind: 'heading', level: 1, runs: [{ text: options.title }] })
  }
  const children: (Paragraph | Table)[] = []
  for (const block of blocks) children.push(...docxBlock(block))
  const document = new Document({
    title: options.title ?? '',
    styles: { default: { document: { run: { font: options.font ?? 'Calibri', size: Math.round((options.fontSize ?? 11) * 2) } } } },
    numbering: {
      config: [{
        reference: 'numbered',
        levels: [0, 1].map(level => ({
          level,
          format: level === 0 ? LevelFormat.DECIMAL : LevelFormat.LOWER_LETTER,
          text: level === 0 ? '%1.' : '%2.',
          alignment: AlignmentType.START,
          style: { paragraph: { indent: { left: 720 * (level + 1), hanging: 360 } } },
        })),
      }],
    },
    sections: [{ children }],
  })
  return new Uint8Array(await Packer.toBuffer(document))
}

function docxBlock(block: Block): (Paragraph | Table)[] {
  switch (block.kind) {
    case 'heading':
      return [new Paragraph({ heading: HEADINGS[Math.min(block.level, 6) - 1]!, children: textRuns(block.runs) })]
    case 'paragraph':
      return [new Paragraph({ children: textRuns(block.runs), spacing: { after: 120 } })]
    case 'quote':
      return [new Paragraph({ children: textRuns(block.runs), indent: { left: 720 }, border: { left: { style: BorderStyle.SINGLE, size: 12, color: '999999', space: 8 } } })]
    case 'pagebreak':
      return [new Paragraph({ children: [new PageBreak()] })]
    case 'list':
      return block.items.map(item => new Paragraph({
        children: textRuns(item.runs),
        ...(block.ordered ? { numbering: { reference: 'numbered', level: item.level } } : { bullet: { level: item.level } }),
      }))
    case 'table': {
      const width = Math.max(block.header.length, ...block.rows.map(row => row.length))
      const row = (cells: Run[][], header: boolean) => new TableRow({
        tableHeader: header,
        children: Array.from({ length: width }, (_, i) => new TableCell({
          children: [new Paragraph({ children: textRuns(cells[i] ?? [{ text: '' }], { bold: header }) })],
          ...(header ? { shading: { type: ShadingType.CLEAR, color: 'auto', fill: 'D9E2F3' } } : {}),
        })),
      })
      return [
        new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows: [row(block.header, true), ...block.rows.map(r => row(r, false))] }),
        new Paragraph({ children: [] }),
      ]
    }
  }
}

export interface SheetSpec {
  name: string
  /** Rows of cells. A string starting with "=" is a formula; numbers and booleans keep their type. */
  rows: unknown[][]
  /** Treat the first row as a header: bold, filter, frozen. Default true. */
  header?: boolean | undefined
  /** Column widths in characters; measured from the content when omitted. */
  columnWidths?: number[] | undefined
}

/** A cell value as Excel should store it. */
export function excelValue(value: unknown): ExcelJSImport.CellValue {
  if (value === null || value === undefined) return null
  if (typeof value === 'number' || typeof value === 'boolean') return value
  const text = String(value)
  if (text.startsWith('=') && text.length > 1) return { formula: text.slice(1) } as ExcelJSImport.CellFormulaValue
  if (/^-?\d+(\.\d+)?$/.test(text) && !/^0\d/.test(text) && text.length < 16) return Number(text)
  if (/^\d{4}-\d{2}-\d{2}$/.test(text)) return new Date(`${text}T00:00:00Z`)
  return text
}

/** An Excel workbook from rows. */
export async function buildXlsx(sheets: SheetSpec[]): Promise<Uint8Array> {
  if (sheets.length === 0) throw new Error('a workbook needs at least one sheet')
  const workbook = new ExcelJS.Workbook()
  const used = new Set<string>()
  for (const spec of sheets) {
    const name = (spec.name || `Sheet${used.size + 1}`).replace(/[\\/?*[\]:]/g, '-').slice(0, 31)
    if (used.has(name.toLowerCase())) throw new Error(`two sheets are named "${name}"`)
    used.add(name.toLowerCase())
    const sheet = workbook.addWorksheet(name)
    for (const row of spec.rows) sheet.addRow(row.map(excelValue))
    const width = Math.max(0, ...spec.rows.map(row => row.length))
    for (let c = 1; c <= width; c++) {
      const given = spec.columnWidths?.[c - 1]
      const longest = Math.max(4, ...spec.rows.map(row => String(row[c - 1] ?? '').length))
      sheet.getColumn(c).width = given ?? Math.min(60, longest + 2)
    }
    if ((spec.header ?? true) && spec.rows.length > 0 && width > 0) {
      const head = sheet.getRow(1)
      head.font = { bold: true }
      head.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFD9E2F3' } }
      sheet.views = [{ state: 'frozen', ySplit: 1 }]
      sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: width } }
    }
  }
  return new Uint8Array(await workbook.xlsx.writeBuffer() as ArrayBuffer)
}

export interface SlideSpec {
  title?: string | undefined
  /** Bullet points; an item starting with two spaces is indented one level. */
  bullets?: string[] | undefined
  /** A paragraph of text instead of, or after, the bullets. */
  text?: string | undefined
  /** A table: rows of cells, the first row the header. */
  table?: string[][] | undefined
  /** Speaker notes. */
  notes?: string | undefined
  /** An image file's bytes and kind, placed on the right half (or full width with no text). */
  image?: { data: Uint8Array, mime: string } | undefined
}

export interface PptxOptions {
  /** The deck's title, also its first slide when `title_slide` is set. */
  title?: string | undefined
  subtitle?: string | undefined
  /** Accent color as hex, e.g. "1F4E79". */
  accent?: string | undefined
}

/** A PowerPoint deck, 16:9, from slide specs. */
export async function buildPptx(slides: SlideSpec[], options: PptxOptions = {}): Promise<Uint8Array> {
  const PptxCtor = PptxGenJS as unknown as new () => PptxGenJSImport
  const deck = new PptxCtor()
  deck.layout = 'LAYOUT_WIDE'
  if (options.title) deck.title = options.title
  const accent = (options.accent ?? '1F4E79').replace(/^#/, '')
  if (options.title) {
    const cover = deck.addSlide()
    cover.addShape('rect', { x: 0, y: 0, w: 13.33, h: 0.25, fill: { color: accent } })
    cover.addText(options.title, { x: 0.8, y: 2.6, w: 11.7, h: 1.2, fontSize: 40, bold: true, color: '1A1A1A' })
    if (options.subtitle) cover.addText(options.subtitle, { x: 0.8, y: 3.9, w: 11.7, h: 0.8, fontSize: 20, color: '555555' })
  }
  for (const spec of slides) {
    const slide = deck.addSlide()
    slide.addShape('rect', { x: 0, y: 0, w: 13.33, h: 0.12, fill: { color: accent } })
    let top = 0.4
    if (spec.title) {
      slide.addText(spec.title, { x: 0.6, y: top, w: 12.1, h: 0.9, fontSize: 28, bold: true, color: accent })
      top += 1.1
    }
    const hasText = (spec.bullets?.length ?? 0) > 0 || !!spec.text || !!spec.table
    const textWidth = spec.image ? 6.6 : 12.1
    if (spec.bullets && spec.bullets.length > 0) {
      slide.addText(spec.bullets.map(item => ({
        text: item.trim(),
        options: { bullet: true, indentLevel: /^\s{2,}/.test(item) ? 1 : 0, breakLine: true },
      })), { x: 0.6, y: top, w: textWidth, h: spec.text || spec.table ? 2.6 : 5.6, fontSize: 18, color: '262626', valign: 'top', paraSpaceAfter: 6 })
      top += spec.text || spec.table ? 2.7 : 5.7
    }
    if (spec.text) {
      slide.addText(spec.text, { x: 0.6, y: top, w: textWidth, h: spec.table ? 1.4 : 5.6 - (top - 1.5), fontSize: 16, color: '404040', valign: 'top' })
      top += spec.table ? 1.5 : 0
    }
    if (spec.table && spec.table.length > 0) {
      const rows = spec.table.map((row, r) => row.map(cell => ({
        text: String(cell),
        options: r === 0 ? { bold: true, color: 'FFFFFF', fill: { color: accent } } : {},
      })))
      slide.addTable(rows, { x: 0.6, y: top, w: textWidth, fontSize: 12, border: { type: 'solid', pt: 0.5, color: 'BFBFBF' } })
    }
    if (spec.image) {
      const data = `data:${spec.image.mime};base64,${Buffer.from(spec.image.data).toString('base64')}`
      slide.addImage(hasText
        ? { data, x: 7.5, y: 1.5, w: 5.2, h: 5.2, sizing: { type: 'contain', w: 5.2, h: 5.2 } }
        : { data, x: 0.6, y: top, w: 12.1, h: 7.5 - top - 0.3, sizing: { type: 'contain', w: 12.1, h: 7.5 - top - 0.3 } })
    }
    if (spec.notes) slide.addNotes(spec.notes)
  }
  const out = await deck.write({ outputType: 'nodebuffer' }) as Buffer
  return new Uint8Array(out)
}

export { plain }
