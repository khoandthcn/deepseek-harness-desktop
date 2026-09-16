/**
 * Drives the REAL plugin bodies: mounts `soc-auth` and `tool-soc-edr` on a real
 * `ToolRuntime` and invokes a registered tool through `ctx.tools.execute`.
 *
 * The unit tests exercise the tool bodies directly and so cannot see the wiring
 * — `inject`, `defineTool`, the EDR cookie auth seam. This spec does, and it
 * needs no network: it calls a read tool while logged out, which is exactly the
 * fail-closed path. No credentials are configured either, which is the point —
 * they must only be demanded by a login, never by a mount.
 *
 * `tool-soc-edr` registers no `soc_login` (that lives in `tool-soc-soar`); this
 * spec mounts EDR alone and reaches the session only through `edr_*` tools.
 */
import { describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import * as socAuth from '@deepseek-ai/dsh-soc-auth'
import * as edrTools from '../src/index.ts'

const signal = new AbortController().signal

async function setup(): Promise<Context> {
  const ctx = new Context()
  // ToolRuntime declares `static inject = ['systemPrompt']`.
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  await ctx.plugin(socAuth, {
    iamUrl: 'https://iam.example',
    clientId: 'TEST',
    redirectUri: 'https://soc.example',
    soarBaseUrl: 'https://soar.example',
    edrBaseUrl: 'https://edr.example',
  })
  // Exactly as the preset mounts it: a row with no `config:` block.
  await ctx.plugin(edrTools)
  return ctx
}

describe('tool-soc-edr wiring', () => {
  it('takes the EDR endpoint from soc-auth when the row carries no config', async () => {
    const ctx = await setup()
    expect(ctx.socAuth.edrBaseUrl).toBe('https://edr.example')
  })

  it('registers no soc_login (it reuses tool-soc-soar\'s session)', async () => {
    const ctx = await setup()
    expect(ctx.tools.get('edr_search_events')).toBeDefined()
    expect(ctx.tools.get('soc_login')).toBeUndefined()
  })

  it('mounts without credentials and fails closed when logged out', async () => {
    const ctx = await setup()
    const result = await ctx.tools.execute({
      signal,
      callId: ToolCallId('call-1'),
      name: 'edr_search_events',
      arguments: {},
    })
    expect(JSON.stringify(result)).toContain('not_authenticated')
  })
})
