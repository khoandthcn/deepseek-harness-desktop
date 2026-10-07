/** PDF page operations: merge, split, extract, and information. */
import { PDFDocument } from 'pdf-lib'
import { pageList } from './read.ts'

/** Several PDFs, or page ranges of them, as one. */
export async function mergePdfs(inputs: { bytes: Uint8Array, pages?: string | undefined }[]): Promise<Uint8Array> {
  if (inputs.length === 0) throw new Error('nothing to merge')
  const out = await PDFDocument.create()
  for (const input of inputs) {
    const source = await PDFDocument.load(input.bytes, { ignoreEncryption: true })
    const wanted = pageList(input.pages, source.getPageCount()).map(n => n - 1)
    for (const page of await out.copyPages(source, wanted)) out.addPage(page)
  }
  return out.save()
}

/** One PDF made of some pages of another, in the order given. */
export async function extractPages(bytes: Uint8Array, pages: string): Promise<Uint8Array> {
  return mergePdfs([{ bytes, pages }])
}

/** A PDF split into one file per range: "1-3,4-6" gives two files; no ranges gives one file per page. */
export async function splitPdf(bytes: Uint8Array, ranges?: string): Promise<Uint8Array[]> {
  const source = await PDFDocument.load(bytes, { ignoreEncryption: true })
  const count = source.getPageCount()
  const parts = ranges && ranges.trim() !== '' ? ranges.split(',').map(part => part.trim()) : Array.from({ length: count }, (_, i) => String(i + 1))
  const out: Uint8Array[] = []
  for (const part of parts) out.push(await extractPages(bytes, part))
  return out
}

/** Page count, page sizes and the document's own metadata. */
export async function pdfInfo(bytes: Uint8Array): Promise<Record<string, unknown>> {
  const doc = await PDFDocument.load(bytes, { ignoreEncryption: true, updateMetadata: false })
  const sizes = doc.getPages().map(page => `${Math.round(page.getWidth())}x${Math.round(page.getHeight())}`)
  const distinct = [...new Set(sizes)]
  return {
    pages: doc.getPageCount(),
    page_sizes_pt: distinct.length === 1 ? distinct[0] : sizes,
    title: doc.getTitle() ?? null,
    author: doc.getAuthor() ?? null,
    subject: doc.getSubject() ?? null,
    producer: doc.getProducer() ?? null,
    created: doc.getCreationDate()?.toISOString() ?? null,
    modified: doc.getModificationDate()?.toISOString() ?? null,
    encrypted: doc.isEncrypted,
  }
}
