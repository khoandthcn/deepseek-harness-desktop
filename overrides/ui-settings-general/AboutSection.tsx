/**
 * The About section: which application this is, which build, and where newer
 * builds are published. What a person is asked for first when they report a
 * problem, so every value can be copied, one at a time or all together.
 */
import { useState } from 'react'
import type { PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import css from './AboutSection.module.css'

/** Where this distribution publishes its installers. */
export const RELEASES_URL = 'https://github.com/khoandthcn/deepseek-harness-desktop/releases'

/** Full component props: the section seat plus the settings dictionary. */
export type AboutSectionComponentProps = PropsRuntime<'settings.section'> & PropsLocale<'settings'>

/** One labelled value of the About section. */
export interface AboutRow {
  key: 'about.app' | 'about.version' | 'about.build' | 'about.runtime' | 'about.platform' | 'about.releases'
  value: string
}

/**
 * The values the About section shows, from what the build stamped into the
 * client and what the runtime reports.
 * @param env - the build-time client values (`process.env` is replaced at build).
 * @param userAgent - the runtime's user agent.
 * @returns the rows, in display order; a value the build did not stamp is "—".
 */
export function aboutRows(
  env: Record<string, string | undefined>,
  userAgent: string,
): AboutRow[] {
  const commit = env.DSH_CLIENT_COMMIT_HASH
  const electron = /Electron\/([\d.]+)/.exec(userAgent)?.[1]
  const chrome = /Chrome\/([\d.]+)/.exec(userAgent)?.[1]
  const platform = /Windows NT [\d.]+|Mac OS X [\d_]+|Linux [\w-]+|Android [\d.]+/.exec(userAgent)?.[0]?.replace(/_/g, '.')
  return [
    { key: 'about.app', value: env.DSH_CLIENT_TITLE ?? 'DeepSeek Harness' },
    { key: 'about.version', value: env.DSH_CLIENT_VERSION ?? '—' },
    { key: 'about.build', value: commit === undefined ? '—' : `${commit}${env.DSH_CLIENT_GIT_DIRTY === 'true' ? '-dirty' : ''}` },
    { key: 'about.runtime', value: electron !== undefined ? `Electron ${electron}${chrome ? ` · Chromium ${chrome}` : ''}` : chrome !== undefined ? `Chromium ${chrome}` : '—' },
    { key: 'about.platform', value: platform ?? '—' },
    { key: 'about.releases', value: RELEASES_URL },
  ]
}

/** Copy text, reporting whether it worked: the clipboard can be refused. */
async function copy(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

/**
 * Render the About section.
 * @param props - composed slot props.
 * @returns the section element tree.
 */
export function AboutSection({ t }: AboutSectionComponentProps) {
  const rows = aboutRows(
    {
      DSH_CLIENT_TITLE: process.env.DSH_CLIENT_TITLE,
      DSH_CLIENT_VERSION: process.env.DSH_CLIENT_VERSION,
      DSH_CLIENT_COMMIT_HASH: process.env.DSH_CLIENT_COMMIT_HASH,
      DSH_CLIENT_GIT_DIRTY: process.env.DSH_CLIENT_GIT_DIRTY,
    },
    typeof navigator === 'undefined' ? '' : navigator.userAgent,
  )
  const [copied, setCopied] = useState<string | undefined>(undefined)
  const flash = (key: string, ok: boolean) => {
    setCopied(ok ? key : 'error')
    setTimeout(() => setCopied(current => (current === key || current === 'error' ? undefined : current)), 1500)
  }
  const summary = rows.map(row => `${t(row.key)}: ${row.value}`).join('\n')
  return (
    <div className={css.section}>
      <p className={css.description}>{t('about.description')}</p>
      {rows.map(row => (
        <div key={row.key} className={css.row}>
          <span className={css.label}>{t(row.key)}</span>
          <span className={css.value}>{row.value}</span>
          {row.value !== '—' && (
            <button
              type="button"
              className={css.copy}
              aria-label={`${t('about.copy')}: ${t(row.key)}`}
              onClick={() => { void copy(row.value).then(ok => flash(row.key, ok)) }}
            >
              {copied === row.key ? t('about.copied') : t('about.copy')}
            </button>
          )}
        </div>
      ))}
      <div className={css.actions}>
        <button
          type="button"
          className={css.copyAll}
          onClick={() => { void copy(summary).then(ok => flash('all', ok)) }}
        >
          {copied === 'all' ? t('about.copied') : t('about.copyAll')}
        </button>
        {copied === 'error' && <span className={css.error} role="status">{t('about.copyFailed')}</span>}
      </div>
    </div>
  )
}
