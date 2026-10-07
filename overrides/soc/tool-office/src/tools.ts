/**
 * The office tools as plain definitions over an injected file seam, so they
 * can be tested without the harness: read Word, Excel, PowerPoint, PDF and
 * CSV; create Word, Excel and PowerPoint; PDF page operations; conversions.
 */
import { buildDocx, buildPptx, buildXlsx, type SheetSpec, type SlideSpec } from './create.ts'
import { parseCsv, toCsv } from './csv.ts'
import { extractPages, mergePdfs, pdfInfo, splitPdf } from './pdf.ts'
import { formatOf, readOffice, cellText } from './read.ts'
import ExcelJSImport from 'exceljs'
import { cjs } from './interop.ts'

const ExcelJS = cjs<typeof ExcelJSImport>(ExcelJSImport)

/** What the tools need from the filesystem: paths resolve against the session's workspace. */
export interface OfficeFiles {
  read(path: string): Promise<Uint8Array>
  /** Write a new file inside the workspace; refuses to replace one unless `overwrite`. */
  write(path: string, bytes: Uint8Array, overwrite: boolean): Promise<string>
}

export interface ToolParamSpec {
  type: 'string' | 'number' | 'integer' | 'boolean' | 'array' | 'object' | 'json'
  required?: true | undefined
  description?: string | undefined
  enum?: readonly string[] | undefined
  items?: ToolParamSpec | undefined
  properties?: Record<string, ToolParamSpec> | undefined
}

export interface OfficeToolDef {
  name: string
  description: string
  parameters: Record<string, ToolParamSpec>
  output: { schema: { type: 'json' }, render: (args: unknown, value: unknown) => { type: 'text', text: string }[] }
  execute: (args: Record<string, any>, files: OfficeFiles) => Promise<unknown>
}

/** How much text one read returns before it is cut. */
export const DEFAULT_MAX_CHARS = 60_000

const OUTPUT: OfficeToolDef['output'] = {
  schema: { type: 'json' },
  render: (_args, value) => [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value) }],
}

const OVERWRITE: ToolParamSpec = { type: 'boolean', description: 'Replace the file if it exists. Default false: an existing file is never replaced silently.' }

function need(args: Record<string, any>, name: string): string {
  const value = args[name]
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`\`${name}\` is required`)
  return value.trim()
}

function withExtension(path: string, ext: string): string {
  if (!new RegExp(`\\.${ext}$`, 'i').test(path)) throw new Error(`\`output\` must end in .${ext}`)
  return path
}

const IMAGE_TYPES: Record<string, string> = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', svg: 'image/svg+xml' }

/** Build the tool definitions. */
export function createOfficeToolDefs(): OfficeToolDef[] {
  return [
    {
      name: 'office_read',
      description: 'Read a Word (.docx), Excel (.xlsx), PowerPoint (.pptx), PDF or CSV/TSV file as Markdown: Word as headings, lists'
        + ' and tables; each Excel sheet and CSV as a table; slides and PDF pages one section each. Use it instead of `read`, which'
        + ' handles plain text only. Long documents are cut at `max_chars`; read a later part with `offset`. Scanned PDFs have no'
        + ' text layer and come back empty.',
      parameters: {
        path: { type: 'string', required: true, description: 'The file, relative to the workspace or absolute.' },
        sheet: { type: 'string', description: 'Excel only: one sheet, by name or 1-based number.' },
        max_rows: { type: 'integer', description: 'Excel/CSV: rows shown per sheet, header included (default 200).' },
        pages: { type: 'string', description: 'PDF/PowerPoint: pages or slides, e.g. "1-3,7".' },
        offset: { type: 'integer', description: 'Character offset to continue a long document from (default 0).' },
        max_chars: { type: 'integer', description: `Characters returned (default ${DEFAULT_MAX_CHARS}).` },
      },
      output: OUTPUT,
      execute: async (args, files) => {
        const path = need(args, 'path')
        const format = formatOf(path)
        if (!format) throw new Error('office_read reads .docx, .xlsx, .pptx, .pdf, .csv and .tsv; use `read` for plain text')
        const result = await readOffice(await files.read(path), format, {
          sheet: args.sheet === undefined ? undefined : String(args.sheet),
          maxRows: typeof args.max_rows === 'number' ? Math.max(1, Math.floor(args.max_rows)) : undefined,
          pages: typeof args.pages === 'string' ? args.pages : undefined,
        })
        const offset = Math.max(0, Math.floor(Number(args.offset ?? 0)))
        const max = Math.max(1000, Math.floor(Number(args.max_chars ?? DEFAULT_MAX_CHARS)))
        const text = result.text.slice(offset, offset + max)
        const rest = result.text.length - offset - text.length
        return {
          path, format: result.format, ...result.summary,
          ...(rest > 0 ? { truncated: `${rest} more characters; call again with offset ${offset + text.length}` } : {}),
          text,
        }
      },
    },
    {
      name: 'office_create_docx',
      description: 'Create a Word document (.docx) from Markdown: # headings, paragraphs, - and 1. lists (indent two spaces for a'
        + ' second level), | pipe | tables |, > quotes, **bold**, *italic*, `code`, and a line `\\pagebreak` for a page break.'
        + ' Write the whole document in one call; to change it later, create it again.',
      parameters: {
        output: { type: 'string', required: true, description: 'The .docx file to write, relative to the workspace.' },
        markdown: { type: 'string', required: true, description: 'The document content in Markdown.' },
        title: { type: 'string', description: 'Document title (file properties; also a heading if the Markdown has no # heading).' },
        font: { type: 'string', description: 'Body font, e.g. "Times New Roman" (default Calibri).' },
        font_size: { type: 'number', description: 'Body size in points (default 11).' },
        overwrite: OVERWRITE,
      },
      output: OUTPUT,
      execute: async (args, files) => {
        const output = withExtension(need(args, 'output'), 'docx')
        const bytes = await buildDocx(need(args, 'markdown'), { title: args.title, font: args.font, fontSize: args.font_size })
        return { written: await files.write(output, bytes, args.overwrite === true), bytes: bytes.length }
      },
    },
    {
      name: 'office_create_xlsx',
      description: 'Create an Excel workbook (.xlsx). Each sheet is rows of cells; the first row is a header (bold, filtered, frozen)'
        + ' unless `header` is false. A cell starting with "=" is a formula ("=SUM(B2:B9)"); numbers stay numbers and'
        + ' YYYY-MM-DD becomes a date. Prefer formulas for totals so the sheet recalculates.',
      parameters: {
        output: { type: 'string', required: true, description: 'The .xlsx file to write, relative to the workspace.' },
        sheets: {
          type: 'array', required: true, description: 'The sheets, in order.',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string', description: 'Sheet name (max 31 characters).' },
              rows: { type: 'array', items: { type: 'array', items: { type: 'json' } }, description: 'Rows of cells.' },
              header: { type: 'boolean', description: 'First row is a header (default true).' },
              column_widths: { type: 'array', items: { type: 'number' }, description: 'Widths in characters.' },
            },
          },
        },
        overwrite: OVERWRITE,
      },
      output: OUTPUT,
      execute: async (args, files) => {
        const output = withExtension(need(args, 'output'), 'xlsx')
        if (!Array.isArray(args.sheets)) throw new Error('`sheets` must be a list')
        const sheets: SheetSpec[] = args.sheets.map((sheet: any, i: number) => ({
          name: String(sheet?.name ?? `Sheet${i + 1}`),
          rows: Array.isArray(sheet?.rows) ? sheet.rows.map((row: unknown) => (Array.isArray(row) ? row : [row])) : [],
          header: sheet?.header,
          columnWidths: Array.isArray(sheet?.column_widths) ? sheet.column_widths.map(Number) : undefined,
        }))
        const bytes = await buildXlsx(sheets)
        return { written: await files.write(output, bytes, args.overwrite === true), sheets: sheets.map(s => ({ name: s.name, rows: s.rows.length })) }
      },
    },
    {
      name: 'office_create_pptx',
      description: 'Create a PowerPoint deck (.pptx, 16:9). Give a `title` for a cover slide, then one entry per slide with a title and'
        + ' any of: bullets (indent an item with two spaces for a sub-point), text, a table (rows, first row header), an image'
        + ' file from the workspace, speaker notes. Keep five or six bullets per slide at most.',
      parameters: {
        output: { type: 'string', required: true, description: 'The .pptx file to write, relative to the workspace.' },
        title: { type: 'string', description: 'Deck title; adds a cover slide.' },
        subtitle: { type: 'string', description: 'Cover subtitle.' },
        accent: { type: 'string', description: 'Accent color as hex, e.g. "1F4E79".' },
        slides: {
          type: 'array', required: true, description: 'The slides after the cover.',
          items: {
            type: 'object',
            properties: {
              title: { type: 'string' },
              bullets: { type: 'array', items: { type: 'string' } },
              text: { type: 'string' },
              table: { type: 'array', items: { type: 'array', items: { type: 'string' } } },
              image: { type: 'string', description: 'An image file in the workspace (.png, .jpg, .gif, .svg).' },
              notes: { type: 'string' },
            },
          },
        },
        overwrite: OVERWRITE,
      },
      output: OUTPUT,
      execute: async (args, files) => {
        const output = withExtension(need(args, 'output'), 'pptx')
        if (!Array.isArray(args.slides)) throw new Error('`slides` must be a list')
        const slides: SlideSpec[] = []
        for (const slide of args.slides as any[]) {
          let image: SlideSpec['image']
          if (typeof slide?.image === 'string' && slide.image.trim() !== '') {
            const ext = /\.([a-z]+)$/i.exec(slide.image)?.[1]?.toLowerCase() ?? ''
            const mime = IMAGE_TYPES[ext]
            if (!mime) throw new Error(`slide image "${slide.image}" must be .png, .jpg, .gif or .svg`)
            image = { data: await files.read(slide.image), mime }
          }
          slides.push({
            title: slide?.title, text: slide?.text, notes: slide?.notes, image,
            bullets: Array.isArray(slide?.bullets) ? slide.bullets.map(String) : undefined,
            table: Array.isArray(slide?.table) ? slide.table.map((row: unknown[]) => row.map(cell => String(cell ?? ''))) : undefined,
          })
        }
        const bytes = await buildPptx(slides, { title: args.title, subtitle: args.subtitle, accent: args.accent })
        return { written: await files.write(output, bytes, args.overwrite === true), slides: slides.length + (args.title ? 1 : 0) }
      },
    },
    {
      name: 'office_pdf',
      description: 'PDF page operations. `info`: page count, sizes, metadata. `merge`: join `inputs` (each a path, or "path:1-3" for some'
        + ' pages) into `output`. `extract`: the `pages` of `input` into `output`, in the order given. `split`: `input` into one'
        + ' file per range of `pages` ("1-3,4-6"), or per page, named after `output` with a number. To read text use office_read.',
      parameters: {
        action: { type: 'string', required: true, enum: ['info', 'merge', 'extract', 'split'] },
        input: { type: 'string', description: 'The PDF for info, extract and split.' },
        inputs: { type: 'array', items: { type: 'string' }, description: 'merge: the PDFs, in order; "file.pdf:2-5" takes some pages.' },
        pages: { type: 'string', description: 'extract/split: pages or ranges, e.g. "1-3,7".' },
        output: { type: 'string', description: 'The PDF to write (split: the base name).' },
        overwrite: OVERWRITE,
      },
      output: OUTPUT,
      execute: async (args, files) => {
        const action = need(args, 'action')
        if (action === 'info') return pdfInfo(await files.read(need(args, 'input')))
        const output = withExtension(need(args, 'output'), 'pdf')
        const overwrite = args.overwrite === true
        if (action === 'merge') {
          if (!Array.isArray(args.inputs) || args.inputs.length === 0) throw new Error('merge needs `inputs`')
          const parts = []
          for (const spec of args.inputs.map(String)) {
            const m = /^(.*\.pdf)(?::([\d,\s-]+))?$/i.exec(spec)
            if (!m) throw new Error(`"${spec}" is not a .pdf path (optionally followed by :pages)`)
            parts.push({ bytes: await files.read(m[1]!), pages: m[2] })
          }
          const bytes = await mergePdfs(parts)
          return { written: await files.write(output, bytes, overwrite) }
        }
        const source = await files.read(need(args, 'input'))
        if (action === 'extract') {
          return { written: await files.write(output, await extractPages(source, need(args, 'pages')), overwrite) }
        }
        if (action === 'split') {
          const parts = await splitPdf(source, typeof args.pages === 'string' ? args.pages : undefined)
          const written: string[] = []
          for (const [i, bytes] of parts.entries()) {
            written.push(await files.write(output.replace(/\.pdf$/i, `-${String(i + 1).padStart(2, '0')}.pdf`), bytes, overwrite))
          }
          return { written }
        }
        throw new Error('`action` must be info, merge, extract or split')
      },
    },
    {
      name: 'office_convert',
      description: 'Convert between formats: .csv/.tsv → .xlsx (one sheet), .xlsx → .csv (one sheet, values not formulas), .md → .docx.'
        + ' The output extension picks the conversion.',
      parameters: {
        input: { type: 'string', required: true, description: 'The source file.' },
        output: { type: 'string', required: true, description: 'The file to write.' },
        sheet: { type: 'string', description: 'xlsx → csv: which sheet (name or 1-based number; default the first).' },
        overwrite: OVERWRITE,
      },
      output: OUTPUT,
      execute: async (args, files) => {
        const input = need(args, 'input')
        const output = need(args, 'output')
        const overwrite = args.overwrite === true
        const from = /\.([a-z]+)$/i.exec(input)?.[1]?.toLowerCase()
        const to = /\.([a-z]+)$/i.exec(output)?.[1]?.toLowerCase()
        if ((from === 'csv' || from === 'tsv') && to === 'xlsx') {
          const text = new TextDecoder().decode(await files.read(input))
          const rows = from === 'tsv' ? parseCsv(text, '\t') : parseCsv(text)
          const name = input.split(/[\\/]/).pop()!.replace(/\.[^.]+$/, '')
          return { written: await files.write(output, await buildXlsx([{ name, rows }]), overwrite), rows: rows.length }
        }
        if (from === 'xlsx' && (to === 'csv' || to === 'tsv')) {
          const workbook = new ExcelJS.Workbook()
          await workbook.xlsx.load(Buffer.from(await files.read(input)) as unknown as ArrayBuffer)
          const wanted = args.sheet === undefined ? workbook.worksheets[0]
            : workbook.worksheets.find((s, i) => s.name === String(args.sheet) || String(i + 1) === String(args.sheet))
          if (!wanted) throw new Error(`no sheet "${args.sheet}"; the workbook has: ${workbook.worksheets.map(s => s.name).join(', ')}`)
          const rows: string[][] = []
          wanted.eachRow({ includeEmpty: true }, row => { rows.push((row.values as unknown[]).slice(1).map(cellText)) })
          const csv = '﻿' + toCsv(rows, to === 'tsv' ? '\t' : ',')
          return { written: await files.write(output, new TextEncoder().encode(csv), overwrite), rows: rows.length, sheet: wanted.name }
        }
        if ((from === 'md' || from === 'markdown' || from === 'txt') && to === 'docx') {
          const markdown = new TextDecoder().decode(await files.read(input))
          return { written: await files.write(output, await buildDocx(markdown), overwrite) }
        }
        throw new Error(`cannot convert .${from} to .${to}; supported: csv/tsv → xlsx, xlsx → csv/tsv, md → docx`)
      },
    },
  ]
}
