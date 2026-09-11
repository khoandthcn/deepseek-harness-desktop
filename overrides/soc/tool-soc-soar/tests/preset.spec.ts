/**
 * Mounts the SOC rows of the shipped `soc-cloud` preset through the real preset
 * layer.
 *
 * The other specs mount the plugins straight onto a `Context`, which skips
 * everything the preset layer enforces — and twice that gap let a broken preset
 * reach a user: a row with no `config:` block, then a service published into the
 * root realm. Neither was visible below this layer.
 *
 * What is mounted here is the generator's own output, sliced at the SOC group.
 * The rest of the composition is upstream's `standard`, whose rows wait on host
 * services (shell, fs, skills, subagents, ...) that only the application
 * provides; rebuilding the host here would test upstream's composition instead
 * of ours. The slice is therefore deliberate: it is exactly the part this
 * repository writes.
 *
 * Needs the workspace, so it runs only inside the upstream checkout; the
 * package's local vitest config excludes it.
 */
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import Include from '@deepseek-ai/cordis-plugin-include'
import Group from '@deepseek-ai/cordis-plugin-group'
import LlmRuntime from '@deepseek-ai/dsh-llm'
import SessionStore, { SessionId } from '@deepseek-ai/dsh-session'
import SessionProjectionRegistry from '@deepseek-ai/dsh-session-projection'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime from '@deepseek-ai/dsh-tools'
import AgentRegistry from '@deepseek-ai/dsh-agent'
import AgentLoop from '@deepseek-ai/dsh-agent-loop'
import AgentPresets, { leakedServices, livePresetMounts } from '@deepseek-ai/dsh-agent-presets'

const HERE = dirname(fileURLToPath(import.meta.url))
const CHECKOUT = join(HERE, '..', '..', '..', '..')
/**
 * Where a row's `@deepseek-ai/...` name resolves from: the dsh meta package is
 * the one place in the workspace that depends on every shipped plugin.
 */
const CLI_ROOT = join(CHECKOUT, 'apps', 'cli')
const SHIPPED_SOC_CLOUD = join(
  CHECKOUT, 'packages', 'preset', 'agent-presets', 'presets', 'soc-cloud', 'agent.cordis.yml',
)
/** The row the generator appends; the SOC group starts here. */
const SOC_GROUP_START = '- id: soc-cloud'
const PRESET_ID = 'soc-rows'

let ctx: Context
let presetRoot: string

/** Write the generator's SOC group, alone, as a mountable preset directory. */
async function writeSocOnlyPreset(): Promise<string> {
  const composition = await readFile(SHIPPED_SOC_CLOUD, 'utf8')
  const start = composition.indexOf(SOC_GROUP_START)
  if (start === -1) {
    throw new Error(`preset.spec: ${SHIPPED_SOC_CLOUD} no longer contains ${SOC_GROUP_START}`)
  }
  const root = await mkdtemp(join(tmpdir(), 'soc-preset-'))
  const dir = join(root, PRESET_ID)
  await mkdir(dir)
  await writeFile(join(dir, 'agent.cordis.yml'), composition.slice(start))
  await writeFile(
    join(dir, 'preset.yml'),
    'name: SOC rows\ndescription: The SOC group alone, for the preset-layer spec.\norder: 1\n',
  )
  return root
}

beforeEach(async () => {
  presetRoot = await writeSocOnlyPreset()
  ctx = new Context()
  ctx.baseUrl = `${pathToFileURL(CLI_ROOT).href}/`
  await ctx.plugin(Loader)
  ctx.loader.builtins.include = Include
  // A preset composes `cordis:group` by name, which resolves only as a builtin.
  ctx.loader.builtins.group = Group
  await ctx.plugin(LlmRuntime)
  await ctx.plugin(SessionStore)
  await ctx.plugin(SessionProjectionRegistry)
  await ctx.plugin(SystemPrompt, { personaPrefix: '' })
  await ctx.plugin(ToolRuntime)
  await ctx.plugin(AgentRegistry)
  await ctx.plugin(AgentLoop, { agents: [] })
  await ctx.plugin(AgentPresets, {
    default: PRESET_ID,
    roots: [{ path: presetRoot, trust: 'system' as const }],
    includeShippedRoot: false,
    includeUserRoot: false,
  })
})

afterEach(async () => {
  await ctx.fiber.dispose()
  await rm(presetRoot, { recursive: true, force: true })
})

async function mountFor(sessionId: string): Promise<{ dispose: () => Promise<void> }> {
  const handle = await ctx.agents.create({
    sessionId: SessionId(sessionId),
    setup: async (agentCtx: Context) => void await ctx.agentPresets.mount(agentCtx, PRESET_ID),
  })
  return { dispose: () => handle.dispose() }
}

describe('the soc-cloud preset rows', () => {
  it('mount with no credentials configured and no config block on the tool row', async () => {
    const handle = await mountFor('sess-soc')
    await handle.dispose()
  })

  it('keep socAuth out of the root realm', async () => {
    const handle = await mountFor('sess-soc-realm')
    const [entry] = livePresetMounts().filter(mounted => mounted.presetId === PRESET_ID)
    expect(entry).toBeDefined()
    // Published without an `isolate` realm the service lands under the root's
    // symbol and is process-global; the application refuses such a preset.
    expect(leakedServices(ctx, entry!.fiber)).toEqual([])
    await handle.dispose()
  })
})
