import { describe, expect, it } from 'vitest'
import { PDFDocument, StandardFonts } from 'pdf-lib'
import { createOfficeToolDefs, type OfficeFiles } from '../src/tools.ts'
import { parseCsv, toCsv } from '../src/csv.ts'
import { parseMarkdown } from '../src/markdown.ts'
import { excelValue } from '../src/create.ts'
import { pageSet } from '../src/read.ts'

/** An in-memory workspace standing in for the session's files. */
function memory(initial: Record<string, Uint8Array | string> = {}) {
  const store = new Map<string, Uint8Array>(Object.entries(initial).map(([k, v]) => [k, typeof v === 'string' ? new TextEncoder().encode(v) : v]))
  const files: OfficeFiles = {
    async read(path) {
      const bytes = store.get(path)
      if (!bytes) throw new Error(`no such file: ${path}`)
      return bytes
    },
    async write(path, bytes, overwrite) {
      if (store.has(path) && !overwrite) throw new Error(`${path} already exists`)
      store.set(path, bytes)
      return path
    },
  }
  return { store, files }
}

const tool = (name: string) => createOfficeToolDefs().find(def => def.name === name)!

async function samplePdf(pages: string[]): Promise<Uint8Array> {
  const doc = await PDFDocument.create()
  const font = await doc.embedFont(StandardFonts.Helvetica)
  for (const text of pages) doc.addPage([300, 200]).drawText(text, { x: 20, y: 100, size: 14, font })
  return doc.save()
}

describe('the tool set', () => {
  it('offers reading, creating, PDF and conversion tools', () => {
    expect(createOfficeToolDefs().map(def => def.name)).toEqual([
      'office_read', 'office_create_docx', 'office_create_xlsx', 'office_create_pptx', 'office_pdf', 'office_convert',
    ])
  })
})

describe('Word', () => {
  it('writes Markdown as a document that reads back with its headings, lists, emphasis and table', async () => {
    const { files, store } = memory()
    await tool('office_create_docx').execute({
      output: 'report.docx',
      title: 'Weekly report',
      markdown: '# Weekly report\n\nThe week was **quiet** and *stable*.\n\n## Findings\n\n- First point\n  - Detail\n- Second point\n\n1. Step one\n2. Step two\n\n| Host | Alerts |\n| --- | --- |\n| web-01 | 12 |\n\n\\pagebreak\n\nAppendix text.',
    }, files)
    expect(store.get('report.docx')!.length).toBeGreaterThan(1000)
    const out = await tool('office_read').execute({ path: 'report.docx' }, files) as any
    expect(out.format).toBe('docx')
    expect(out.text).toMatch(/Weekly report/)
    expect(out.text).toMatch(/__quiet__|\*\*quiet\*\*/)
    expect(out.text).toMatch(/First point/)
    expect(out.text).toMatch(/web-01/)
    expect(out.text).toMatch(/Appendix text/)
  })

  it('refuses to replace an existing file unless asked', async () => {
    const { files } = memory({ 'a.docx': 'x' })
    await expect(tool('office_create_docx').execute({ output: 'a.docx', markdown: 'hi' }, files)).rejects.toThrow(/already exists/)
    await expect(tool('office_create_docx').execute({ output: 'a.docx', markdown: 'hi', overwrite: true }, files)).resolves.toBeDefined()
  })

  it('refuses an output with the wrong extension', async () => {
    await expect(tool('office_create_docx').execute({ output: 'a.doc', markdown: 'hi' }, memory().files)).rejects.toThrow(/\.docx/)
  })
})

describe('Excel', () => {
  it('writes sheets with typed cells and formulas, and reads them back as tables', async () => {
    const { files } = memory()
    await tool('office_create_xlsx').execute({
      output: 'data.xlsx',
      sheets: [
        { name: 'Alerts', rows: [['Tenant', 'Count', 'Since'], ['acme', 12, '2026-10-01'], ['globex', '30', '2026-10-02'], ['Total', '=SUM(B2:B3)', '']] },
        { name: 'Notes', rows: [['Line'], ['ok']], header: false },
      ],
    }, files)
    const all = await tool('office_read').execute({ path: 'data.xlsx' }, files) as any
    expect(all.sheets).toEqual([{ name: 'Alerts', rows: 4, columns: 3 }, { name: 'Notes', rows: 2, columns: 1 }])
    expect(all.text).toMatch(/## Sheet: Alerts/)
    expect(all.text).toMatch(/\| acme \| 12 \| 2026-10-01 \|/)
    // No spreadsheet program has computed the total yet: the formula is shown.
    expect(all.text).toMatch(/=SUM\(B2:B3\)/)
    const one = await tool('office_read').execute({ path: 'data.xlsx', sheet: '2' }, files) as any
    expect(one.text).not.toMatch(/Alerts/)
    await expect(tool('office_read').execute({ path: 'data.xlsx', sheet: 'Nope' }, files)).rejects.toThrow(/the workbook has: Alerts, Notes/)
  })

  it('keeps identifiers with leading zeros as text, and converts only plain numbers and dates', () => {
    expect(excelValue('007')).toBe('007')
    expect(excelValue('42')).toBe(42)
    expect(excelValue('3.5')).toBe(3.5)
    expect(excelValue('=A1*2')).toEqual({ formula: 'A1*2' })
    expect(excelValue('2026-10-02')).toEqual(new Date('2026-10-02T00:00:00Z'))
    expect(excelValue('12345678901234567')).toBe('12345678901234567')
  })

  it('cuts a long sheet at max_rows and says how many rows were left out', async () => {
    const { files } = memory()
    const rows = [['n'], ...Array.from({ length: 30 }, (_, i) => [i])]
    await tool('office_create_xlsx').execute({ output: 'long.xlsx', sheets: [{ name: 'S', rows }] }, files)
    const out = await tool('office_read').execute({ path: 'long.xlsx', max_rows: 11 }, files) as any
    expect(out.text).toMatch(/20 more rows not shown/)
  })
})

describe('PowerPoint', () => {
  it('writes a cover and slides with bullets, a table and notes, and reads them back per slide', async () => {
    const { files } = memory()
    const out = await tool('office_create_pptx').execute({
      output: 'deck.pptx', title: 'SOC weekly', subtitle: 'Week 40',
      slides: [
        { title: 'Highlights', bullets: ['412 alerts', '  most from EDR', 'No incident'], notes: 'Mention the backup job.' },
        { title: 'Top tenants', table: [['Tenant', 'Alerts'], ['acme', '200']] },
      ],
    }, files) as any
    expect(out.slides).toBe(3)
    const read = await tool('office_read').execute({ path: 'deck.pptx' }, files) as any
    expect(read.slides).toBe(3)
    expect(read.text).toMatch(/## Slide 1[\s\S]*SOC weekly/)
    expect(read.text).toMatch(/## Slide 2[\s\S]*412 alerts[\s\S]*most from EDR/)
    expect(read.text).toMatch(/Notes:_ Mention the backup job/)
    expect(read.text).toMatch(/## Slide 3[\s\S]*acme/)
    // The cover has no notes; the slide-number field on a notes page is not a note.
    expect(read.text).not.toMatch(/Notes:_ \d/)
    const second = await tool('office_read').execute({ path: 'deck.pptx', pages: '3' }, files) as any
    expect(second.text).not.toMatch(/Highlights/)
  })
})

describe('PDF', () => {
  it('reads text per page, and a page range', async () => {
    const { files } = memory({ 'a.pdf': await samplePdf(['Alpha page', 'Beta page', 'Gamma page']) })
    const all = await tool('office_read').execute({ path: 'a.pdf' }, files) as any
    expect(all.pages).toBe(3)
    expect(all.text).toMatch(/## Page 1\n\nAlpha page[\s\S]*## Page 3\n\nGamma page/)
    const some = await tool('office_read').execute({ path: 'a.pdf', pages: '2' }, files) as any
    expect(some.text).toBe('## Page 2\n\nBeta page')
  })

  it('merges, extracts, splits and describes', async () => {
    const { files, store } = memory({ 'a.pdf': await samplePdf(['A1', 'A2']), 'b.pdf': await samplePdf(['B1', 'B2', 'B3']) })
    const pdf = tool('office_pdf')
    await pdf.execute({ action: 'merge', inputs: ['a.pdf', 'b.pdf:2-3'], output: 'm.pdf' }, files)
    expect((await pdf.execute({ action: 'info', input: 'm.pdf' }, files) as any).pages).toBe(4)
    const merged = await tool('office_read').execute({ path: 'm.pdf' }, files) as any
    expect(merged.text).toMatch(/A1[\s\S]*A2[\s\S]*B2[\s\S]*B3/)
    await pdf.execute({ action: 'extract', input: 'b.pdf', pages: '3,1', output: 'e.pdf' }, files)
    expect((await tool('office_read').execute({ path: 'e.pdf' }, files) as any).text).toMatch(/B3[\s\S]*B1/)
    const split = await pdf.execute({ action: 'split', input: 'b.pdf', output: 'part.pdf' }, files) as any
    expect(split.written).toEqual(['part-01.pdf', 'part-02.pdf', 'part-03.pdf'])
    expect(store.has('part-03.pdf')).toBe(true)
  })
})

describe('CSV and conversions', () => {
  it('parses quoted cells, embedded separators and line breaks, and sniffs the delimiter', () => {
    expect(parseCsv('a,b\n"x, y","say ""hi"""\n')).toEqual([['a', 'b'], ['x, y', 'say "hi"']])
    expect(parseCsv('a;b\n1;2')).toEqual([['a', 'b'], ['1', '2']])
    expect(parseCsv('﻿a\tb\n"l1\nl2"\t3', '\t')).toEqual([['a', 'b'], ['l1\nl2', '3']])
    expect(toCsv([['a', 'b,c'], ['x"y', null]])).toBe('a,"b,c"\r\n"x""y",\r\n')
  })

  it('turns a CSV into a workbook and a workbook back into a CSV', async () => {
    const { files, store } = memory({ 'in.csv': 'name,count\nacme,3\nglobex,5\n' })
    const convert = tool('office_convert')
    await convert.execute({ input: 'in.csv', output: 'out.xlsx' }, files)
    const read = await tool('office_read').execute({ path: 'out.xlsx' }, files) as any
    expect(read.text).toMatch(/\| globex \| 5 \|/)
    await convert.execute({ input: 'out.xlsx', output: 'back.csv' }, files)
    expect(new TextDecoder('utf-8', { ignoreBOM: true }).decode(store.get('back.csv')!)).toBe('﻿name,count\r\nacme,3\r\nglobex,5\r\n')
  })

  it('turns Markdown into a Word document, and says which conversions exist', async () => {
    const { files } = memory({ 'notes.md': '# Notes\n\n- one\n- two' })
    await tool('office_convert').execute({ input: 'notes.md', output: 'notes.docx' }, files)
    expect((await tool('office_read').execute({ path: 'notes.docx' }, files) as any).text).toMatch(/Notes[\s\S]*one/)
    await expect(tool('office_convert').execute({ input: 'notes.md', output: 'notes.pdf' }, files)).rejects.toThrow(/supported: csv\/tsv → xlsx/)
  })
})

describe('helpers', () => {
  it('reads page ranges, open-ended ones and out-of-range ones', () => {
    expect(pageSet('1-3,7', 10)).toEqual([1, 2, 3, 7])
    expect(pageSet('8-', 10)).toEqual([8, 9, 10])
    expect(pageSet('9-20', 10)).toEqual([9, 10])
    expect(pageSet(undefined, 3)).toEqual([1, 2, 3])
    expect(() => pageSet('one', 3)).toThrow(/page range/)
  })

  it('parses the Markdown subset documents are written in', () => {
    const blocks = parseMarkdown('# T\n\npara **b** and *i*\nmore\n\n- a\n  - b\n\n| x | y |\n|---|---|\n| 1 | 2 |\n\n> q')
    expect(blocks.map(block => block.kind)).toEqual(['heading', 'paragraph', 'list', 'table', 'quote'])
    expect(blocks[1]).toEqual({ kind: 'paragraph', runs: [{ text: 'para ' }, { text: 'b', bold: true }, { text: ' and ' }, { text: 'i', italic: true }, { text: ' more' }] })
    expect((blocks[2] as any).items.map((item: any) => item.level)).toEqual([0, 1])
  })
})
