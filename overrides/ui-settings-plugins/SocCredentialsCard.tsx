/**
 * The two SOC cards in Settings: the SOC platform with its sign-in, and the
 * Threat Intelligence platform with its own account.
 *
 * Every control is write-only — the values go through the credentials domain,
 * so a literal never rides a response — which is why each shows whether the
 * Host holds a value rather than the value itself.
 */

import type { InjectFace, PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import { SecretField } from './fields.tsx'
import { PluginCard } from './PluginCard.tsx'
import {
  SOC_FIELDS, TI_FIELDS,
  type CardCredentialField, type SocCredentialsCardFace,
} from './soc-credentials-card-controller.ts'
import type {} from './slot-contract.ts'

/** Props the renderer binds for either card. */
export type SocCredentialsCardProps =
  PropsRuntime<'settings.plugin.item'>
  & PropsLocale<'settings.plugins'>
  & InjectFace<SocCredentialsCardFace>

/**
 * Render one platform's card.
 * @param props - locale copy, the card snapshot, and its form actions.
 * @param titleKey - locale key of the card's title.
 * @param descriptionKey - locale key of its one-line description.
 * @param fields - the controls to render, in order.
 * @returns the card.
 */
function renderCard(
  props: SocCredentialsCardProps,
  titleKey: string,
  descriptionKey: string,
  fields: readonly CardCredentialField[],
) {
  const { t } = props
  const state = props.useSocCredentialsCard(snapshot => snapshot)
  return (
    <PluginCard
      t={t}
      titleKey={titleKey as never}
      descriptionKey={descriptionKey as never}
      state={state}
      onSave={props.save}
      onDiscard={props.discard}
    >
      {fields.map(({ field }) => {
        const control = state.fields[field]
        if (control === undefined) return null
        return (
          <SecretField
            key={field}
            id={`plugin-config-soc-${field}`}
            label={t(`soc_${field}` as never)}
            hint={t(`soc_${field}Hint` as never)}
            // Its own writability disables the control — a value sourced from
            // the process environment cannot be written from here.
            disabled={!control.writable}
            text={control.text}
            configured={control.configured}
            stateLabel={control.configured ? t('socValueSet') : t('socValueUnset')}
            onEdit={(text) => { props.edit(field, text) }}
          />
        )
      })}
    </PluginCard>
  )
}

/**
 * The SOC platform card: the domain every system is derived from, the tenant,
 * and the sign-in the SOC tools use.
 * @param props - locale copy, the card snapshot, and its form actions.
 * @returns the card.
 */
export function SocCredentialsCard(props: SocCredentialsCardProps) {
  return renderCard(props, 'socTitle', 'socDescription', SOC_FIELDS)
}

/**
 * The Threat Intelligence card: a separate platform, so a separate account and
 * a card of its own.
 * @param props - locale copy, the card snapshot, and its form actions.
 * @returns the card.
 */
export function SocThreatIntelCard(props: SocCredentialsCardProps) {
  return renderCard(props, 'tiTitle', 'tiDescription', TI_FIELDS)
}
