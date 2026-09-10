#!/usr/bin/env node
// Prepare a deepseek-ai/deepseek-harness checkout for this repository's desktop build.
//
//   node scripts/patch-upstream.mjs <path-to-upstream-checkout>
//
// 1. File overrides (overrides/manifest.json): each upstream file must still hash
//    to the recorded SHA-256 before it is replaced, so an upstream change fails
//    here instead of silently dropping the override or its upstream fix.
//      - unsigned electron-builder config (ad-hoc macOS, unsigned Windows)
//      - first-run onboarding that walks users through a custom model provider
// 2. Snippet patches, each matching exactly one upstream snippet:
//      - skip Developer ID re-signing of the macOS seed store
//      - onboarding copy (English + Chinese)
//      - Desktop default agent preset = standard-brave
// 3. The Brave Search web-search preset, generated into the shipped preset root.
import { createHash } from 'node:crypto'
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { PRESET_ID, writeSearchPreset } from './make-search-preset.mjs'

const root = resolve(process.argv[2] ?? 'upstream')
const here = resolve(import.meta.dirname, '..')

const sha256 = path => createHash('sha256').update(readFileSync(path)).digest('hex')

// ── 1. file overrides ────────────────────────────────────────────────────────
const manifest = JSON.parse(readFileSync(join(here, 'overrides', 'manifest.json'), 'utf8'))
for (const { target, source, upstreamSha256 } of manifest) {
  const targetPath = join(root, target)
  const sourcePath = join(here, source)
  if (existsSync(targetPath) && sha256(targetPath) === sha256(sourcePath)) {
    console.log(`already overridden: ${target}`)
    continue
  }
  if (upstreamSha256 === null) {
    if (existsSync(targetPath)) throw new Error(`patch-upstream: ${target} now exists upstream; review the override`)
  } else {
    if (!existsSync(targetPath)) throw new Error(`patch-upstream: ${target} is missing upstream`)
    const actual = sha256(targetPath)
    if (actual !== upstreamSha256) {
      throw new Error(`patch-upstream: ${target} changed upstream (sha256 ${actual}); port ${source} to it and update overrides/manifest.json`)
    }
  }
  mkdirSync(dirname(targetPath), { recursive: true })
  copyFileSync(sourcePath, targetPath)
  console.log(`overridden: ${target}`)
}

// ── 2. snippet patches ───────────────────────────────────────────────────────
function patch(relativePath, from, to) {
  const path = join(root, relativePath)
  const text = readFileSync(path, 'utf8')
  if (text.includes(to)) {
    console.log(`already patched: ${relativePath}`)
    return
  }
  const count = text.split(from).length - 1
  if (count !== 1) {
    throw new Error(`patch-upstream: expected exactly one match in ${relativePath}, found ${count}:\n${from}`)
  }
  writeFileSync(path, text.replace(from, to))
  console.log(`patched: ${relativePath}`)
}

// Prebuilt native modules keep their own signatures; the bundled upstream
// Node.js loads them as it does for any npm install.
patch(
  'apps/desktop/scripts/prepare-seed.ts',
  "    if (targetPlatform === 'darwin') {\n      macOSSigning = resolveMacOSSigningEnvironment(process.env)",
  "    if (targetPlatform === 'darwin' && process.env.DSH_DESKTOP_UNSIGNED !== '1') {\n      macOSSigning = resolveMacOSSigningEnvironment(process.env)",
)

// First-start progress window: the seed install runs before any window exists.
const MAIN_TS = 'apps/desktop/src/main.ts'
patch(
  MAIN_TS,
  'async function main(): Promise<void> {\n',
  readFileSync(join(here, 'overrides', 'desktop', 'setup-window.snippet.ts'), 'utf8') + 'async function main(): Promise<void> {\n',
)
patch(
  MAIN_TS,
  '  if (development === undefined) {\n    await manager.applyRelease(resources.seed, app.getVersion(), {\n',
  [
    '  // deepseek-harness-desktop: show progress while a new release installs.',
    '  const installsRelease = development === undefined && ((): boolean => {',
    '    try {',
    '      return manager.releaseVersion() !== app.getVersion()',
    '    } catch {',
    '      // No readable desktop-release.json: the profile has never been installed.',
    '      return true',
    '    }',
    '  })()',
    '  const setupWindow = installsRelease ? await openSetupWindow(app.getLocale()) : undefined',
    '  if (development === undefined) {',
    '    await manager.applyRelease(resources.seed, app.getVersion(), {',
    '',
  ].join('\n'),
)
patch(
  MAIN_TS,
  '  mainWindow = createMainWindow()\n  await mainWindow.loadURL(`${SCHEME}://app/index.html`)\n',
  '  mainWindow = createMainWindow()\n  await mainWindow.loadURL(`${SCHEME}://app/index.html`)\n  setupWindow?.destroy()\n',
)

// Windows ARM64 target: upstream packages win-x64 only, which Windows on ARM runs
// under x64 emulation (slow enough that the first start looks hung).
const DESKTOP_SCRIPTS = 'apps/desktop/scripts'
patch(
  `${DESKTOP_SCRIPTS}/package-target.ts`,
  "export type DesktopPackageTargetName = 'mac-arm64' | 'mac-x64' | 'win-x64'\n",
  "export type DesktopPackageTargetName = 'mac-arm64' | 'mac-x64' | 'win-x64' | 'win-arm64'\n",
)
patch(
  `${DESKTOP_SCRIPTS}/package-target.ts`,
  "    name: 'win-x64',\n    platform: 'win32',\n    arch: 'x64',\n    builderPlatform: '--win',\n    builderArch: '--x64',\n  },\n}\n",
  "    name: 'win-x64',\n    platform: 'win32',\n    arch: 'x64',\n    builderPlatform: '--win',\n    builderArch: '--x64',\n  },\n  'win-arm64': {\n    name: 'win-arm64',\n    platform: 'win32',\n    arch: 'arm64',\n    builderPlatform: '--win',\n    builderArch: '--arm64',\n  },\n}\n",
)
patch(
  `${DESKTOP_SCRIPTS}/package-target.ts`,
  "  if (target.platform === 'win32' && (hostPlatform !== 'win32' || hostArch !== 'x64')) {\n    throw new Error('desktop package: win-x64 requires a Windows x64 build host')\n",
  "  if (target.platform === 'win32' && (hostPlatform !== 'win32' || hostArch !== target.arch)) {\n    throw new Error(`desktop package: ${name} requires a Windows ${target.arch} build host`)\n",
)
for (const file of ['desktop-build-paths.mjs', 'desktop-auto-update-environment.mjs']) {
  patch(`${DESKTOP_SCRIPTS}/${file}`, "new Set(['mac-arm64', 'mac-x64', 'win-x64'])", "new Set(['mac-arm64', 'mac-x64', 'win-x64', 'win-arm64'])")
}
patch(
  `${DESKTOP_SCRIPTS}/desktop-auto-update-environment.d.mts`,
  "export type DesktopAutoUpdateTarget = 'mac-arm64' | 'mac-x64' | 'win-x64'",
  "export type DesktopAutoUpdateTarget = 'mac-arm64' | 'mac-x64' | 'win-x64' | 'win-arm64'",
)
patch(
  `${DESKTOP_SCRIPTS}/upload-target.ts`,
  "new Set<DesktopPackageTargetName>(['mac-arm64', 'mac-x64', 'win-x64'])",
  "new Set<DesktopPackageTargetName>(['mac-arm64', 'mac-x64', 'win-x64', 'win-arm64'])",
)
patch(
  `${DESKTOP_SCRIPTS}/desktop-upload-plan.ts`,
  "  'win-x64': { platform: 'win32', arch: 'x64', os: 'win' },\n",
  "  'win-x64': { platform: 'win32', arch: 'x64', os: 'win' },\n  'win-arm64': { platform: 'win32', arch: 'arm64', os: 'win' },\n",
)
function addScripts(relativePath, entries) {
  const path = join(root, relativePath)
  const manifest = JSON.parse(readFileSync(path, 'utf8'))
  const missing = Object.entries(entries).filter(([name]) => manifest.scripts?.[name] === undefined)
  if (missing.length === 0) {
    console.log(`already patched: ${relativePath}`)
    return
  }
  for (const [name, command] of missing) manifest.scripts[name] = command
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`)
  console.log(`patched: ${relativePath}`)
}
addScripts('apps/desktop/package.json', {
  'package:win:arm64': 'tsx scripts/package-target.ts win-arm64',
  'package:win:arm64:dir': 'tsx scripts/package-target.ts win-arm64 --dir',
})
addScripts('package.json', {
  'package:desktop:win:arm64': 'pnpm --filter @deepseek-ai/dsh-desktop run package:win:arm64',
})

const ONBOARDING_COPY = {
  en: {
    anchor: "  onboardingSaving: 'Saving…',\n",
    entries: {
      onboardingChooseTitle: 'Set up a model provider',
      onboardingChooseDescription: 'DeepSeek Harness needs a model provider before it can work. Create a custom provider for any OpenAI- or Anthropic-compatible endpoint, or use an official DeepSeek API key.',
      onboardingCreateCustom: 'Create a custom provider',
      onboardingUseDeepSeek: 'Use a DeepSeek API key',
      onboardingBack: 'Back',
      onboardingCustomTitle: 'Create a custom provider',
      onboardingCustomDescription: 'Fill in the form below, following these steps:',
      onboardingGuideRoute: 'Provider ID: a short lowercase name such as my-gateway. It identifies the provider and names its stored key.',
      onboardingGuideEndpoint: 'Base URL and API protocol: the endpoint your provider documents, and whether it speaks OpenAI Chat Completions, OpenAI Responses, or Anthropic Messages.',
      onboardingGuideKey: 'API key: saved in the local credential store, never in the settings file.',
      onboardingGuideModels: 'Models: use Fetch available models, or add model IDs by hand.',
      onboardingGuideCreate: 'Create, then pick one of the new models in the model picker under the message box.',
      onboardingCustomDoneTitle: 'Provider created',
      onboardingCustomDone: 'Your provider is saved. Pick one of its models in the model picker under the message box to start a session.',
      onboardingDone: 'Get started',
    },
  },
  zh: {
    anchor: "  onboardingSaving: '保存中…',\n",
    entries: {
      onboardingChooseTitle: '设置模型提供方',
      onboardingChooseDescription: 'DeepSeek Harness 需要先配置模型提供方。你可以为任意 OpenAI 或 Anthropic 兼容端点创建自定义提供方，或使用 DeepSeek 官方 API Key。',
      onboardingCreateCustom: '创建自定义提供方',
      onboardingUseDeepSeek: '使用 DeepSeek API Key',
      onboardingBack: '返回',
      onboardingCustomTitle: '创建自定义提供方',
      onboardingCustomDescription: '按以下步骤填写下方表单：',
      onboardingGuideRoute: 'Provider ID：简短的小写名称，例如 my-gateway，用于标识提供方并命名其密钥。',
      onboardingGuideEndpoint: 'API 地址与协议：提供方文档中的端点，以及它使用 OpenAI Chat Completions、OpenAI Responses 还是 Anthropic Messages。',
      onboardingGuideKey: 'API Key：保存在本地凭据存储中，不会写入设置文件。',
      onboardingGuideModels: '模型：点击获取可用模型，或手动添加模型 ID。',
      onboardingGuideCreate: '点击创建，然后在输入框下方的模型选择器中选择一个新模型。',
      onboardingCustomDoneTitle: '提供方已创建',
      onboardingCustomDone: '提供方已保存。在输入框下方的模型选择器中选择它的一个模型即可开始会话。',
      onboardingDone: '开始使用',
    },
  },
}
for (const { anchor, entries } of Object.values(ONBOARDING_COPY)) {
  const lines = Object.entries(entries).map(([key, value]) => `  ${key}: ${JSON.stringify(value).replaceAll("'", "\\'").replace(/^"|"$/g, "'")},\n`)
  patch('packages/client/ui-settings-models/src/client/locales.ts', anchor, anchor + lines.join(''))
}

// ── 3. Brave Search preset, shipped and default in Desktop ───────────────────
writeSearchPreset(root, join(root, 'packages/preset/agent-presets/presets', PRESET_ID))
console.log(`generated: packages/preset/agent-presets/presets/${PRESET_ID}`)

const overlay = 'apps/desktop-host/config/desktop.cordis.patch.yml'
const overlayText = readFileSync(join(root, overlay), 'utf8')
if (overlayText.includes(`default: ${PRESET_ID}`)) {
  console.log(`already patched: ${overlay}`)
} else {
  writeFileSync(join(root, overlay), `${overlayText.trimEnd()}\n\n# deepseek-harness-desktop: Brave Search web-search preset for new sessions.\n- id: agent-presets\n  config:\n    default: ${PRESET_ID}\n`)
  console.log(`patched: ${overlay}`)
}
