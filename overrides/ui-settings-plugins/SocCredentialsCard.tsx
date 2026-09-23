/**
 * The SOC Cloud credentials card: the SOC username and password, each written
 * through the credentials domain rather than into any settings section, so the
 * literal never rides a response. The card always renders — it gates on no
 * settings namespace — because the plugin that reads these credentials is
 * composed only inside the soc-cloud preset, per agent session.
 */

import type { InjectFace, PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import { SecretField } from './fields.tsx'
import { ENDPOINT_FIELDS } from './soc-credentials-card-controller.ts'
import { PluginCard } from './PluginCard.tsx'
import type { SocCredentialsCardFace } from './soc-credentials-card-controller.ts'
import type {} from './slot-contract.ts'

/** Props the renderer binds for the SOC Cloud credentials card. */
export type SocCredentialsCardProps =
  PropsRuntime<'settings.plugin.item'>
  & PropsLocale<'settings.plugins'>
  & InjectFace<SocCredentialsCardFace>

/**
 * Render the SOC Cloud credentials card.
 * @param props - locale copy, the card snapshot, and its form actions.
 * @returns the card.
 */
export function SocCredentialsCard(props: SocCredentialsCardProps) {
  const { t } = props
  const state = props.useSocCredentialsCard(snapshot => snapshot)
  return (
    <PluginCard
      t={t}
      titleKey="socTitle"
      descriptionKey="socDescription"
      state={state}
      onSave={props.save}
      onDiscard={props.discard}
    >
      <SecretField
        id="plugin-config-soc-username"
        label={t('socUsername')}
        hint={t('socUsernameHint')}
        // Its own writability disables the control — a value sourced from the
        // process environment cannot be written from here.
        disabled={!state.usernameWritable}
        text={state.username.text}
        configured={state.usernameConfigured}
        stateLabel={state.usernameConfigured ? t('socUsernameSet') : t('socUsernameUnset')}
        onEdit={(text) => { props.edit('username', text) }}
      />
      <SecretField
        id="plugin-config-soc-password"
        label={t('socPassword')}
        hint={t('socPasswordHint')}
        disabled={!state.passwordWritable}
        text={state.password.text}
        configured={state.passwordConfigured}
        stateLabel={state.passwordConfigured ? t('socPasswordSet') : t('socPasswordUnset')}
        onEdit={(text) => { props.edit('password', text) }}
      />
      {/* The deployment's own addresses. A build ships none, so whoever installs
          it points the tools at their systems here. */}
      {ENDPOINT_FIELDS.map((field) => {
        const endpoint = state.endpoints[field]
        return (
          <SecretField
            key={field}
            id={`plugin-config-soc-${field}`}
            label={t(`soc_${field}` as never)}
            hint={t(`soc_${field}Hint` as never)}
            disabled={!endpoint.writable}
            text={endpoint.text}
            configured={endpoint.configured}
            stateLabel={endpoint.configured ? t('socValueSet') : t('socValueUnset')}
            onEdit={(text) => { props.edit(field, text) }}
          />
        )
      })}
    </PluginCard>
  )
}
