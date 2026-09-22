/**
 * Drives the REAL plugin bodies: mounts `soc-auth` and `tool-soc-nsm` on a real
 * `ToolRuntime` and invokes a registered tool through `ctx.tools.execute`.
 *
 * The unit tests exercise the tool bodies directly and so cannot see the wiring
 * — `inject`, `defineTool`, the NSM session seam. This spec does, and it needs
 * no network: it calls a read tool while logged out, which is exactly the
 * fail-closed path. No credentials are configured either, which is the point —
 * they must only be demanded by a login, never by a mount.
 *
 * `tool-soc-nsm` registers no `soc_login` (that lives in `tool-soc-soar`); this
 * spec mounts NSM alone and reaches the session only through `nsm_*` tools.
 */
import { describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import * as socAuth from '@deepseek-ai/dsh-soc-auth'
import * as nsmTools from '../src/index.ts'

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
    nsmBaseUrl: 'https://nsm.example',
  })
  // Exactly as the preset mounts it: a row with no `config:` block.
  await ctx.plugin(nsmTools)
  return ctx
}

describe('tool-soc-nsm wiring', () => {
  it('takes the NSM endpoint from soc-auth when the row carries no config', async () => {
    const ctx = await setup()
    expect(ctx.socAuth.nsmBaseUrl).toBe('https://nsm.example')
  })

  it('registers the NSM tools but no soc_login (it reuses tool-soc-soar\'s session)', async () => {
    const ctx = await setup()
    expect(ctx.tools.get('nsm_search_alerts')).toBeDefined()
    expect(ctx.tools.get('nsm_check_access')).toBeDefined()
    expect(ctx.tools.get('soc_login')).toBeUndefined()
  })

  it('mounts without credentials and fails closed when logged out', async () => {
    const ctx = await setup()
    const result = await ctx.tools.execute({
      signal,
      callId: ToolCallId('call-1'),
      name: 'nsm_search_alerts',
      arguments: {},
    })
    expect(JSON.stringify(result)).toContain('not_authenticated')
  })
})
