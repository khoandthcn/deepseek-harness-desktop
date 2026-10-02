import { describe, expect, it } from 'vitest'
import { aboutRows, RELEASES_URL } from '../src/client/AboutSection.tsx'

const WINDOWS_ELECTRON = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
  + 'DeepSeekHarness/0.1.5 Chrome/138.0.7204.243 Electron/37.4.0 Safari/537.36'

describe('aboutRows', () => {
  it('shows the stamped name, version and build, and the runtime the app reports', () => {
    const rows = Object.fromEntries(aboutRows({
      DSH_CLIENT_TITLE: 'DeepSeek Harness',
      DSH_CLIENT_VERSION: '0.1.5-rc.1.soc.12',
      DSH_CLIENT_COMMIT_HASH: '6f97b7d',
    }, WINDOWS_ELECTRON).map(row => [row.key, row.value]))
    expect(rows).toEqual({
      'about.app': 'DeepSeek Harness',
      'about.version': '0.1.5-rc.1.soc.12',
      'about.build': '6f97b7d',
      'about.runtime': 'Electron 37.4.0 · Chromium 138.0.7204.243',
      'about.platform': 'Windows NT 10.0',
      'about.releases': RELEASES_URL,
    })
  })

  it('marks what the build did not stamp instead of inventing it', () => {
    const rows = Object.fromEntries(aboutRows({}, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/138.0.0.0')
      .map(row => [row.key, row.value]))
    expect(rows['about.app']).toBe('DeepSeek Harness')
    expect(rows['about.version']).toBe('—')
    expect(rows['about.build']).toBe('—')
    expect(rows['about.runtime']).toBe('Chromium 138.0.0.0')
    expect(rows['about.platform']).toBe('Mac OS X 10.15.7')
  })

  it('flags a build made from uncommitted changes', () => {
    const build = aboutRows({ DSH_CLIENT_COMMIT_HASH: 'abc1234', DSH_CLIENT_GIT_DIRTY: 'true' }, '')
      .find(row => row.key === 'about.build')
    expect(build?.value).toBe('abc1234-dirty')
  })
})
