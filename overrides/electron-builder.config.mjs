// Unsigned replacement for apps/desktop/electron-builder.config.mjs.
//
// The official config requires an Apple Developer ID + notarization and a Windows
// EV token, and refuses to build without them. This copy keeps every packaging
// field (app files, bundled Node.js runtime, offline seed, NSIS options) but:
//   - macOS: ad-hoc signature ("-"), no hardened runtime, no notarization
//   - Windows: no Authenticode signing
//   - publish: GitHub Releases of DSH_DESKTOP_GITHUB_REPOSITORY when set
// scripts/apply-unsigned.mjs copies it over the upstream file before packaging.
import { resolveDesktopAppId } from './scripts/desktop-release-environment.mjs'
import { resolveDesktopAutoUpdateConfig } from './scripts/desktop-auto-update-environment.mjs'
import { desktopTargetBuildPaths } from './scripts/desktop-build-paths.mjs'

/**
 * @param {NodeJS.ProcessEnv} env
 * @returns {object[]} electron-builder publish providers.
 */
function resolvePublish(env, publicUrl) {
  const repository = env.DSH_DESKTOP_GITHUB_REPOSITORY?.trim()
  if (!repository) return [{ provider: 'generic', url: publicUrl }]
  const [owner, repo] = repository.split('/')
  if (!owner || !repo) throw new Error('DSH_DESKTOP_GITHUB_REPOSITORY must look like owner/repo')
  return [{ provider: 'github', owner, repo, releaseType: 'release' }]
}

export function createElectronBuilderConfig(
  env = process.env,
  hostPlatform = process.platform,
  hostArch = process.arch,
) {
  const appId = resolveDesktopAppId(env)
  const resolvedPlatform = env.DSH_DESKTOP_TARGET_PLATFORM ?? hostPlatform
  const resolvedArch = env.DSH_DESKTOP_TARGET_ARCH ?? hostArch
  const update = resolveDesktopAutoUpdateConfig(env, resolvedPlatform, resolvedArch)
  const buildPaths = desktopTargetBuildPaths(update.target)
  return {
    appId,
    productName: 'DeepSeek Harness',
    artifactName: 'deepseek-harness-${version}-${os}-${arch}.${ext}',
    directories: { output: buildPaths.artifacts },
    asar: true,
    files: [
      'lib/*.js',
      'lib/*.cjs',
      'renderer/**/*',
      'package.json',
    ],
    extraResources: [
      { from: buildPaths.runtime, to: 'runtime' },
      { from: buildPaths.seed, to: 'seed' },
    ],
    mac: {
      category: 'public.app-category.developer-tools',
      identity: '-',
      hardenedRuntime: false,
      notarize: false,
      target: ['dmg', 'zip'],
      // Squirrel.Mac rejects ad-hoc signed updates, so macOS builds ship without
      // app-update.yml; DesktopUpdateCoordinator then stays idle.
      publish: null,
    },
    dmg: {
      sign: false,
      writeUpdateInfo: false,
    },
    win: {
      target: ['nsis'],
      // win-x64 and win-arm64 would both publish latest.yml to one release; only
      // win-x64 keeps the update channel, so the arm64 build ships no app-update.yml.
      ...resolvedArch === 'arm64' ? { publish: null } : {},
    },
    nsis: {
      oneClick: false,
      allowToChangeInstallationDirectory: true,
      differentialPackage: true,
    },
    publish: resolvePublish(env, update.publicUrl),
  }
}

export default createElectronBuilderConfig()
