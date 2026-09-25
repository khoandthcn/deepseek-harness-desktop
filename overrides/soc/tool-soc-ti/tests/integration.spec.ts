/**
 * Drives the REAL plugin body: mounts `tool-soc-ti` on a real `ToolRuntime`
 * and invokes a registered tool through `ctx.tools.execute`.
 *
 * The unit tests exercise the tool bodies directly and so cannot see the
 * wiring — `inject`, `defineTool`, the credential seam. This spec does, and it
 * needs no network: with no account configured, every tool reports that rather
 * than reaching the platform.
 */
import { describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import { ToolCallId } from '@deepseek-ai/dsh-llm'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import * as tiTools from '../src/index.ts'

const signal = new AbortController().signal

async function setup(): Promise<Context> {
  const ctx = new Context()
  // ToolRuntime declares `static inject = ['systemPrompt']`.
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  // Exactly as the preset mounts it: a row with no `config:` block.
  await ctx.plugin(tiTools)
  return ctx
}

describe('tool-soc-ti wiring', () => {
  it('registers the Threat Intelligence tools and no login tool', async () => {
    const ctx = await setup()
    expect(ctx.tools.get('ti_lookup_indicator')).toBeDefined()
    expect(ctx.tools.get('ti_search_compromised_systems')).toBeDefined()
    // TI has its own account: it neither needs nor provides the SOC session
    expect(ctx.tools.get('soc_login')).toBeUndefined()
  })

  it('mounts with no credentials and says so rather than calling the platform', async () => {
    const ctx = await setup()
    const result = await ctx.tools.execute({
      signal,
      callId: ToolCallId('call-1'),
      name: 'ti_search_phishing',
      arguments: {},
    })
    expect(JSON.stringify(result)).toContain('not_configured')
  })
})
