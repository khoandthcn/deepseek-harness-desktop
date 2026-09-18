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
// 4. A per-build version stamp on the `dsh` family, so every build installs its
//    own Desktop profile (DSH_SOC_BUILD_STAMP fixes it; default: build time).
// 5. The SOC native packages (overrides/soc/* → packages/soc/*) and the
//    `soc-cloud` preset that mounts them.
// 6. The SOC Cloud credentials card in Settings → Plugins.
import { createHash } from 'node:crypto'
import { copyFileSync, cpSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { PRESET_ID, writeSearchPreset } from './make-search-preset.mjs'
import { PRESET_ID as SOC_PRESET_ID, writeSocPreset } from './make-soc-preset.mjs'

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

// The app menu has no Edit submenu, so on macOS Cmd+C/V/X/A are never wired and
// nothing can be pasted into an input. Electron's `editMenu` role supplies the
// standard undo/redo/cut/copy/paste/selectAll items with their accelerators.
patch(
  MAIN_TS,
  "      { role: 'quit' },\n    ],\n  }]))",
  "      { role: 'quit' },\n    ],\n  }, { role: 'editMenu' }]))",
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

// ── 4. per-build family version ──────────────────────────────────────────────
// Desktop reinstalls its profile only when the seed's version differs from the
// installed one (`applyRelease` compares desktop-release.json, the installed
// `@deepseek-ai/dsh` and the host package against Electron's own version).
// Every build of one upstream ref carries the same version, so a fresh .dmg
// kept running the previous build's profile until `~/.dsh/profiles/desktop`
// was removed by hand. Stamp a prerelease identifier onto the whole `dsh`
// family (every manifest carrying the family version: root, apps, packages —
// never `vendor/`, which keeps its own version lines) so each build installs
// itself. `DSH_SOC_BUILD_STAMP` fixes the stamp (CI passes its run number);
// a local build takes the build time.
const STAMP_SUFFIX = /\.soc\.[0-9A-Za-z]+$/
const readVersion = path => JSON.parse(readFileSync(path, 'utf8')).version
const checkoutVersion = readVersion(join(root, 'packages', 'core', 'tools', 'package.json'))
const baseVersion = checkoutVersion.replace(STAMP_SUFFIX, '')
const stamp = process.env.DSH_SOC_BUILD_STAMP ?? String(Math.floor(Date.now() / 1000))
if (!/^[0-9A-Za-z]+$/.test(stamp)) {
  throw new Error(`patch-upstream: DSH_SOC_BUILD_STAMP must be a semver prerelease identifier, got ${stamp}`)
}
const familyVersion = `${baseVersion}.soc.${stamp}`
const SKIPPED_DIRECTORIES = new Set(['node_modules', 'vendor', '.git', '.desktop-build', 'lib', 'dist'])
function* manifestsUnder(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRECTORIES.has(entry.name)) yield* manifestsUnder(join(directory, entry.name))
    } else if (entry.name === 'package.json') {
      yield join(directory, entry.name)
    }
  }
}
let stamped = 0
for (const manifestPath of manifestsUnder(root)) {
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  if (manifest.version !== checkoutVersion) continue
  manifest.version = familyVersion
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)
  stamped += 1
}
if (stamped === 0) throw new Error(`patch-upstream: no manifest carried the family version ${checkoutVersion}`)
console.log(`stamped: ${stamped} manifests ${checkoutVersion} → ${familyVersion}`)

// ── 5. SOC native packages + the soc-cloud preset that mounts them ───────────
// These are new first-party workspace packages, so there is no upstream file to
// hash-guard: the sources are simply copied in. The workspace glob `packages/*/*`
// already picks up `packages/soc/*`. Only the sources travel — `node_modules`,
// `lib`, `package-lock.json` and `.gitignore` are local build artefacts of this
// repository and must never land in the checkout.
const SOC_PACKAGE_ENTRIES = new Set(['package.json', 'tsconfig.json', 'src', 'tests'])
// Project references are added here rather than kept in `overrides/`, because the
// paths they name (`vendor/`, `packages/core/`) only exist inside the checkout —
// carrying them in the source tree would break `vitest` runs against the package
// in place. `tsc -b` needs them to build each dependency before its dependents.
const SOC_PACKAGE_REFERENCES = {
  'soc-client': [],
  'soc-auth': [
    '../../../vendor/cosmokit',
    '../../../vendor/cordis',
    '../../../vendor/schemastery',
    '../../credentials/credentials',
    '../../settings/settings',
    '../../util/launch-environment',
    '../soc-client',
  ],
  'tool-soc-soar': [
    '../../../vendor/cosmokit',
    '../../../vendor/cordis',
    '../../core/tools',
    '../soc-client',
    '../soc-auth',
  ],
  'tool-soc-edr': [
    '../../../vendor/cosmokit',
    '../../../vendor/cordis',
    '../../core/tools',
    '../soc-client',
    '../soc-auth',
  ],
  'tool-soc-siem': [
    '../../../vendor/cosmokit',
    '../../../vendor/cordis',
    '../../core/tools',
    '../soc-client',
    '../soc-auth',
  ],
}
for (const name of ['soc-client', 'soc-auth', 'tool-soc-soar', 'tool-soc-edr', 'tool-soc-siem']) {
  const from = join(here, 'overrides', 'soc', name)
  const to = join(root, 'packages', 'soc', name)
  cpSync(from, to, {
    recursive: true,
    filter: source => {
      const path = relative(from, source)
      // The package root itself, then only the allowed top-level entries and
      // everything beneath them.
      return path === '' || SOC_PACKAGE_ENTRIES.has(path.split(sep)[0])
    },
  })
  // The release packer requires one version across the whole `dsh` family:
  // the stamped one from section 4.
  const manifestPath = join(to, 'package.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))
  manifest.version = familyVersion
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`)

  const tsconfigPath = join(to, 'tsconfig.json')
  const tsconfig = JSON.parse(readFileSync(tsconfigPath, 'utf8'))
  tsconfig.references = SOC_PACKAGE_REFERENCES[name].map(path => ({ path }))
  writeFileSync(tsconfigPath, `${JSON.stringify(tsconfig, null, 2)}\n`)
  console.log(`copied: packages/soc/${name}`)
}

// The Desktop seed is the dependency closure of `@deepseek-ai/dsh` (apps/cli),
// so a package nothing depends on gets packed but never seeded: the profile
// would offer the soc-cloud preset and then fail to mount it, because the two
// plugins it names are not installable. Declare them on the meta package, the
// way every shipped tool is declared.
const cliManifestPath = join(root, 'apps', 'cli', 'package.json')
const cliManifest = JSON.parse(readFileSync(cliManifestPath, 'utf8'))
for (const name of ['dsh-soc-client', 'dsh-soc-auth', 'dsh-tool-soc-soar', 'dsh-tool-soc-edr', 'dsh-tool-soc-siem']) {
  cliManifest.dependencies[`@deepseek-ai/${name}`] = 'workspace:^'
}
cliManifest.dependencies = Object.fromEntries(
  Object.entries(cliManifest.dependencies).sort(([left], [right]) => left.localeCompare(right)),
)
writeFileSync(cliManifestPath, `${JSON.stringify(cliManifest, null, 2)}\n`)
console.log('patched: apps/cli/package.json (soc dependencies)')

// The soc packages must be registered like any other workspace package: a `paths`
// entry so source-plane imports resolve, and a host aggregate reference so
// `tsc -b` actually emits their lib/.
patch(
  'tsconfig.base.json',
  '      "@deepseek-ai/dsh-tool-todo": ["./packages/todo/tool-todo/src"],\n',
  '      "@deepseek-ai/dsh-tool-todo": ["./packages/todo/tool-todo/src"],\n'
  + '      "@deepseek-ai/dsh-soc-client": ["./packages/soc/soc-client/src"],\n'
  + '      "@deepseek-ai/dsh-soc-auth": ["./packages/soc/soc-auth/src"],\n'
  + '      "@deepseek-ai/dsh-tool-soc-soar": ["./packages/soc/tool-soc-soar/src"],\n'
  + '      "@deepseek-ai/dsh-tool-soc-edr": ["./packages/soc/tool-soc-edr/src"],\n'
  + '      "@deepseek-ai/dsh-tool-soc-siem": ["./packages/soc/tool-soc-siem/src"],\n',
)
patch(
  'tsconfig.host.json',
  '    { "path": "./packages/client/ui-deliverables/tsconfig.host.json" },\n',
  '    { "path": "./packages/client/ui-deliverables/tsconfig.host.json" },\n'
  + '    { "path": "./packages/soc/soc-client" },\n'
  + '    { "path": "./packages/soc/soc-auth" },\n'
  + '    { "path": "./packages/soc/tool-soc-soar" },\n'
  + '    { "path": "./packages/soc/tool-soc-edr" },\n'
  + '    { "path": "./packages/soc/tool-soc-siem" },\n',
)

writeSocPreset(root, join(root, 'packages/preset/agent-presets/presets', SOC_PRESET_ID))
console.log(`generated: packages/preset/agent-presets/presets/${SOC_PRESET_ID}`)

// ── 6. SOC Cloud credentials card in Settings → Plugins ──────────────────────
// A self-contained card that always renders and writes SOC_USERNAME /
// SOC_PASSWORD through the credentials domain, so the two secrets never pass
// through the model or the settings file. The two card sources are new files
// with no upstream to hash-guard; the existing plugins-settings package is
// snippet-patched to construct the controller and register the card.
const UI_SETTINGS_PLUGINS_CLIENT = 'packages/client/ui-settings-plugins/src/client'
for (const file of ['soc-credentials-card-controller.ts', 'SocCredentialsCard.tsx']) {
  copyFileSync(
    join(here, 'overrides', 'ui-settings-plugins', file),
    join(root, UI_SETTINGS_PLUGINS_CLIENT, file),
  )
  console.log(`copied: ${UI_SETTINGS_PLUGINS_CLIENT}/${file}`)
}

const PLUGINS_INDEX = `${UI_SETTINGS_PLUGINS_CLIENT}/index.ts`
patch(
  PLUGINS_INDEX,
  "import { WebSearchCard } from './WebSearchCard.tsx'\n",
  "import { WebSearchCard } from './WebSearchCard.tsx'\nimport { SocCredentialsCard } from './SocCredentialsCard.tsx'\n",
)
patch(
  PLUGINS_INDEX,
  "import { WEB_SEARCH_NS, WebSearchCardController } from './web-search-card-controller.ts'\n",
  "import { WEB_SEARCH_NS, WebSearchCardController } from './web-search-card-controller.ts'\n"
  + "import { SOC_CREDENTIALS_NS, SocCredentialsCardController } from './soc-credentials-card-controller.ts'\n",
)
patch(
  PLUGINS_INDEX,
  "export type { WebSearchCardFace, WebSearchCardState } from './web-search-card-controller.ts'\n",
  "export type { WebSearchCardFace, WebSearchCardState } from './web-search-card-controller.ts'\n"
  + "export type { SocCredentialsCardFace, SocCredentialsCardState } from './soc-credentials-card-controller.ts'\n",
)
patch(
  PLUGINS_INDEX,
  "  const webSearch = new WebSearchCardController(\n    ctx.settingsScope.bind({ namespace: WEB_SEARCH_NS }), ctx)\n",
  "  const webSearch = new WebSearchCardController(\n    ctx.settingsScope.bind({ namespace: WEB_SEARCH_NS }), ctx)\n"
  + "  const socCredentials = new SocCredentialsCardController(\n"
  + "    ctx.settingsScope.bind<Record<string, never>>({ namespace: SOC_CREDENTIALS_NS }), ctx)\n",
)
patch(
  PLUGINS_INDEX,
  "    () => ctx.remote.$on('credentials/reference-updated', (ref) => { webSearch.refreshCredential(ref) }),\n",
  "    () => ctx.remote.$on('credentials/reference-updated', (ref) => {\n"
  + '      webSearch.refreshCredential(ref)\n'
  + '      socCredentials.refreshCredential(ref)\n'
  + '    }),\n',
)
patch(
  PLUGINS_INDEX,
  "      inject: () => webSearch.inject(),\n    }, WebSearchCard)\n  })\n",
  "      inject: () => webSearch.inject(),\n    }, WebSearchCard)\n"
  + '    yield ctx.slots.register({\n'
  + "      name: 'settings.plugin.item',\n"
  + '      key: SOC_CREDENTIALS_NS,\n'
  + '      locale: NS,\n'
  + '      inject: () => socCredentials.inject(),\n'
  + '    }, SocCredentialsCard)\n  })\n',
)

// Locale keys the card renders (verify-client-ui-i18n requires locale-owned copy).
const PLUGINS_LOCALES = `${UI_SETTINGS_PLUGINS_CLIENT}/locales.ts`
patch(
  PLUGINS_LOCALES,
  "  | 'subagentModelSelectionRequired' | 'subagentModelSelectionConflict' | 'subagentModelSelectionOff'\n",
  "  | 'subagentModelSelectionRequired' | 'subagentModelSelectionConflict' | 'subagentModelSelectionOff'\n"
  + "  | 'socTitle' | 'socDescription'\n"
  + "  | 'socUsername' | 'socUsernameHint' | 'socUsernameSet' | 'socUsernameUnset'\n"
  + "  | 'socPassword' | 'socPasswordHint' | 'socPasswordSet' | 'socPasswordUnset'\n",
)
patch(
  PLUGINS_LOCALES,
  "  subagentModelSelectionOff: 'Subagents use configured defaults or inherit the parent agent\\'s model. Saved model choices are retained.',\n}",
  "  subagentModelSelectionOff: 'Subagents use configured defaults or inherit the parent agent\\'s model. Saved model choices are retained.',\n"
  + "  socTitle: 'SOC Cloud credentials',\n"
  + "  socDescription: 'The sign-in the SOC Cloud tools use.',\n"
  + "  socUsername: 'Username',\n"
  + "  socUsernameHint: 'Stored outside the settings file. Leave blank to keep the current username.',\n"
  + "  socUsernameSet: 'A username is configured.',\n"
  + "  socUsernameUnset: 'No username is configured.',\n"
  + "  socPassword: 'Password',\n"
  + "  socPasswordHint: 'Stored outside the settings file. Leave blank to keep the current password.',\n"
  + "  socPasswordSet: 'A password is configured.',\n"
  + "  socPasswordUnset: 'No password is configured.',\n}",
)
patch(
  PLUGINS_LOCALES,
  "  subagentModelSelectionOff: '关闭后，Subagent 使用配置的默认模型或继承父 Agent 的模型；已选模型会保留。',\n}",
  "  subagentModelSelectionOff: '关闭后，Subagent 使用配置的默认模型或继承父 Agent 的模型；已选模型会保留。',\n"
  + "  socTitle: 'SOC 云凭据',\n"
  + "  socDescription: 'SOC 云工具使用的登录凭据。',\n"
  + "  socUsername: '用户名',\n"
  + "  socUsernameHint: '不写入设置文件。留空表示保持当前用户名。',\n"
  + "  socUsernameSet: '已配置用户名。',\n"
  + "  socUsernameUnset: '未配置用户名。',\n"
  + "  socPassword: '密码',\n"
  + "  socPasswordHint: '不写入设置文件。留空表示保持当前密码。',\n"
  + "  socPasswordSet: '已配置密码。',\n"
  + "  socPasswordUnset: '未配置密码。',\n}",
)

// The generated slot inventory enumerates the settings.plugin.item occupants.
patch(
  'packages/extensions/cordis-client-runner/src/client/slot-catalog.ts',
  "      'client-ui-settings-plugins WebSearchCard',\n    ],",
  "      'client-ui-settings-plugins WebSearchCard',\n      'client-ui-settings-plugins SocCredentialsCard',\n    ],",
)

// The package test asserts the exact set of shipped cards.
const PLUGINS_TEST = 'packages/client/ui-settings-plugins/tests/apply.client.spec.ts'
patch(
  PLUGINS_TEST,
  "      .toEqual(['shell', 'agent-loop', 'subagent-model-selection', 'web-search-deepseek'])",
  "      .toEqual(['shell', 'agent-loop', 'subagent-model-selection', 'web-search-deepseek', 'soc-credentials'])",
)
patch(
  PLUGINS_TEST,
  "    expect(slots.entries('settings.plugin.item')).toHaveLength(4)",
  "    expect(slots.entries('settings.plugin.item')).toHaveLength(5)",
)
