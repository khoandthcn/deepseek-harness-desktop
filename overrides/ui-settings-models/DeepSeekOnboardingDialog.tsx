/**
 * First-run model-provider step. Readiness comes from the same
 * provider/settings/credential join as the Models page: any provider the user
 * can already talk to ends the step. A user with none is walked through
 * declaring a custom provider with the Models page's own creation card, and is
 * offered the official DeepSeek credential as the alternative while that route
 * is present. (deepseek-harness-desktop replaces the upstream DeepSeek-only step.)
 */

import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import type { SnapshotStore } from '@deepseek-ai/dsh-client-store'
import type { InjectFace, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import type { ModelsSettingsState, ModelsSettingsStore } from './store.ts'
import { onboardingReadiness, protocolChoices } from './store.ts'
import type { ModelsOperations } from './operations.ts'
import type { SettingsSchemaOperations } from './schema-operations.ts'
import { CustomProviderCard } from './CustomProviderCard.tsx'
import { ProviderEditor } from './ProviderEditor.tsx'
import type { en } from './locales.ts'
import { OnboardingModal } from './OnboardingModal.tsx'
import styles from './DeepSeekOnboardingDialog.module.css'
import onboarding from './ProviderOnboarding.module.css'
import buttons from './ModelsSection.module.css'

/** Registration-side dependencies of {@link DeepSeekOnboardingDialog}. */
export interface DeepSeekOnboardingInjected {
  hooks: {
    /** Shared Models-page join state, bound by the slot renderer. */
    models: SnapshotStore<ModelsSettingsState>
  }
  /** Shared Models-page join controller. */
  controller: ModelsSettingsStore
  /** The Host operations the reused Models editors write through. */
  operations: ModelsOperations
  /** Settings schema and immutable path callbacks. */
  schema: SettingsSchemaOperations
  /** Feature copy. */
  t: (key: keyof typeof en) => string
}

/** Slot owner props plus the feature's injected dependencies. */
export type DeepSeekOnboardingDialogProps =
  PropsRuntime<'settings.onboarding'> & InjectFace<DeepSeekOnboardingInjected>

/** Wizard pages; `done` stays open until the user dismisses it. */
type Step = 'choose' | 'custom' | 'deepseek' | 'done'

/** Guide lines shown above the custom-provider card, in field order. */
const GUIDE: readonly (keyof typeof en)[] = [
  'onboardingGuideRoute',
  'onboardingGuideEndpoint',
  'onboardingGuideKey',
  'onboardingGuideModels',
  'onboardingGuideCreate',
]

/** Settings namespace custom routes are declared in. */
const CUSTOM_NS = 'llm-pi-ai'

/**
 * Walk a first-run user without any usable provider through creating one.
 * @param props - settings-shell owner state and Models feature dependencies.
 * @returns the onboarding modal, or null when onboarding needs no intervention.
 */
export function DeepSeekOnboardingDialog(props: DeepSeekOnboardingDialogProps): ReactNode {
  const { complete, controller, useModels, operations, schema, t } = props
  const state = useModels(snapshot => snapshot)
  const readiness = onboardingReadiness(state)
  const [step, setStep] = useState<Step>('choose')

  const customNamespace = state.namespaces.get(CUSTOM_NS)
  const canDeclare = state.writable && customNamespace !== undefined
  const deepSeekRow = readiness.kind === 'credential-missing'
    ? state.rows.find(candidate =>
      candidate.entry.provider === 'deepseek-official'
      && candidate.entry.settingsNs === 'llm-deepseek'
      && candidate.entry.settingsPath.length === 0)
    : undefined
  const deepSeekNamespace = state.namespaces.get('llm-deepseek')
  const offerDeepSeek = deepSeekRow !== undefined && deepSeekNamespace !== undefined
  // `adapter-absent` is only reached past the usable-provider gate, so it also
  // means no provider at all; a writable custom namespace can still fix that.
  const needsProvider = offerDeepSeek || (readiness.kind === 'adapter-absent' && canDeclare)
  const settled = readiness.kind !== 'loading' && !needsProvider

  useEffect(() => {
    if (state.status === 'idle') void controller.load()
  }, [controller, state.status])

  useEffect(() => {
    if (settled && step !== 'done') complete()
  }, [complete, settled, step])

  if (step === 'done') {
    return (
      <OnboardingModal title={t('onboardingCustomDoneTitle')} focusTitle>
        <p className={styles['description']}>{t('onboardingCustomDone')}</p>
        <div className={onboarding['actions']}>
          <button type="button" className={buttons['primaryButton']} onClick={() => { complete() }}>
            {t('onboardingDone')}
          </button>
        </div>
      </OnboardingModal>
    )
  }
  if (!needsProvider) return null

  const current: Step = canDeclare ? step : 'deepseek'

  if (current === 'deepseek' && deepSeekRow !== undefined && deepSeekNamespace !== undefined) {
    return (
      <OnboardingModal title={t('onboardingTitle')}>
        <p className={styles['description']}>{t('onboardingDescription')}</p>
        <div className={styles['editor']}>
          <ProviderEditor
            provider={deepSeekRow.entry.provider}
            displayName={deepSeekRow.entry.displayName}
            namespace={deepSeekNamespace}
            schema={schema}
            settingsPath={deepSeekRow.entry.settingsPath}
            operations={operations}
            t={t}
            readOnly={false}
            hideTitle
            credentialOnly
            credentialRequired
            autoFocusCredential
            cancelLabelKey={canDeclare ? 'onboardingBack' : 'onboardingLater'}
            submitLabelKey="onboardingSave"
            submitBusyLabelKey="onboardingSaving"
            onClose={(changed) => {
              if (changed) {
                void controller.load()
                return
              }
              if (canDeclare) setStep('choose')
              else complete()
            }}
          />
        </div>
      </OnboardingModal>
    )
  }

  if (current === 'custom' && customNamespace !== undefined) {
    return (
      <OnboardingModal title={t('onboardingCustomTitle')}>
        <p className={styles['description']}>{t('onboardingCustomDescription')}</p>
        <ol className={onboarding['guide']}>
          {GUIDE.map(key => <li key={key}>{t(key)}</li>)}
        </ol>
        <div className={styles['editor']}>
          <CustomProviderCard
            taken={state.rows.map(row => row.entry.provider)}
            protocols={protocolChoices(customNamespace, schema)}
            revision={customNamespace.revision}
            operations={operations}
            t={t}
            readOnly={!state.writable}
            onClose={(changed) => {
              if (!changed) {
                setStep('choose')
                return
              }
              setStep('done')
              void controller.load()
            }}
          />
        </div>
      </OnboardingModal>
    )
  }

  return (
    <OnboardingModal title={t('onboardingChooseTitle')} focusTitle>
      <p className={styles['description']}>{t('onboardingChooseDescription')}</p>
      <div className={onboarding['actions']}>
        <button type="button" className={buttons['primaryButton']} onClick={() => { setStep('custom') }}>
          {t('onboardingCreateCustom')}
        </button>
        {offerDeepSeek
          ? (
            <button type="button" className={buttons['secondaryButton']} onClick={() => { setStep('deepseek') }}>
              {t('onboardingUseDeepSeek')}
            </button>
          )
          : null}
        <button type="button" className={buttons['linkButton']} onClick={() => { complete() }}>
          {t('onboardingLater')}
        </button>
      </div>
    </OnboardingModal>
  )
}
