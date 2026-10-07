/**
 * `tool-office` — office documents for the agent, with no Office, Python or
 * network on the machine: read Word, Excel, PowerPoint, PDF and CSV; create
 * Word, Excel and PowerPoint; PDF page operations; CSV and Markdown
 * conversions. Paths resolve against the session's workspace, and files are
 * written only inside it.
 *
 * @module @deepseek-ai/dsh-tool-office
 */
import { mkdir, writeFile, stat } from 'node:fs/promises'
import { dirname } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { defineTool, type ToolExecution } from '@deepseek-ai/dsh-tools'
import type {} from '@deepseek-ai/dsh-fs'
import { createOfficeToolDefs, type OfficeFiles, type OfficeToolDef } from './tools.ts'

export * from './tools.ts'
export * from './read.ts'
export * from './create.ts'
export * from './pdf.ts'
export * from './csv.ts'
export * from './markdown.ts'

export const name = 'tool-office'
export const inject = ['tools', 'fs']

/** The largest file the tools read. */
export const MAX_FILE_BYTES = 200 * 1024 * 1024

type Registrable = Omit<OfficeToolDef, 'execute'> & { execute: (args: Record<string, any>, exec: ToolExecution) => Promise<unknown> }
const define = defineTool as unknown as (options: Registrable) => Parameters<Context['tools']['register']>[0]

/**
 * Files for one call: relative paths resolve against the calling session's
 * workspace, and a write must land inside it.
 */
export function filesFor(ctx: Context, exec: ToolExecution): OfficeFiles {
  const cwd = exec.agent?.session.header.cwd
  const options = { ...(cwd !== undefined ? { cwd } : {}), signal: exec.signal }
  return {
    async read(path) {
      const target = await ctx.fs.resolve(path, options)
      return ctx.fs.readBytes(target, exec.signal, MAX_FILE_BYTES)
    },
    async write(path, bytes, overwrite) {
      const target = await ctx.fs.resolve(path, options)
      const workspace = await ctx.fs.resolve(cwd ?? '.', options)
      if (!ctx.fs.contains(workspace, target)) {
        throw new Error(`${path} is outside the workspace; write office files inside it`)
      }
      const hostPath = ctx.fs.processPath(target)
      const exists = await stat(hostPath).then(() => true, () => false)
      if (exists && !overwrite) throw new Error(`${path} already exists; pass overwrite: true to replace it, or choose another name`)
      await mkdir(dirname(hostPath), { recursive: true })
      await writeFile(hostPath, bytes)
      return hostPath
    },
  }
}

/** Register the office tools. */
export function apply(ctx: Context): void {
  for (const def of createOfficeToolDefs()) {
    ctx.tools.register(define({
      ...def,
      execute: (args, exec) => def.execute(args, filesFor(ctx, exec)),
    }))
  }
}
