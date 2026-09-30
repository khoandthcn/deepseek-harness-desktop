/**
 * The two SOC cards in Settings: the SOC platform with its sign-in, and the
 * Threat Intelligence platform with its own account.
 *
 * Every control is write-only — the values go through the credentials domain,
 * so a literal never rides a response — which is why each shows whether the
 * Host holds a value rather than the value itself.
 */

import type { InjectFace, PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import { Tag } from '@deepseek-ai/dsh-client-ui-primitives'
import css from './fields.module.css'
import { PluginCard } from './PluginCard.tsx'
import {
  SOC_FIELDS, TI_FIELDS,
  type CardCredentialField, type SocCredentialsCardFace,
} from './soc-credentials-card-controller.ts'
import type {} from './slot-contract.ts'

/**
 * One control on a card, in either of its two forms.
 *
 * A secret is write-only: it travels to the credentials domain, never rides a
 * response, so it starts blank, masks what is typed, and carries a badge
 * saying whether the Host holds a value. Everything else is configuration
 * kept in the card's settings section: it shows its stored value, unmasked, so
 * the user types a domain once and can proof-read it afterwards.
 * @param props - the field's copy, its staged text, and the edit action.
 * @returns the labelled control.
 */
function CredentialField(props: {
  /** Stable id associating the label with its control. */
  id: string
  /** Visible label. */
  label: string
  /** One-line explanation rendered under the control. */
  hint: string
  /** Draft text this control renders. */
  text: string
  /** Whether the Host reports a value for this reference. */
  configured: boolean
  /**
   * Copy describing the configured state, for a control whose value cannot be
   * read back. Undefined for one that shows its value, where a badge saying it
   * is configured would only repeat what the control already shows.
   */
  stateLabel?: string | undefined
  /** Whether what is typed is masked. */
  masked: boolean
  /** Disables the control — a value sourced elsewhere cannot be written here. */
  disabled: boolean
  /** Stage draft text. */
  onEdit: (text: string) => void
}) {
  return (
    <div className={css.field}>
      <div className={css.head}>
        <label className={css.label} htmlFor={props.id}>{props.label}</label>
        {props.stateLabel === undefined
          ? null
          : (
            <span className={css.badges}>
              <Tag tone={props.configured ? 'neutral' : 'quiet'}>{props.stateLabel}</Tag>
            </span>
          )}
      </div>
      <input
        id={props.id}
        className={css.input}
        type={props.masked ? 'password' : 'text'}
        autoComplete="off"
        value={props.text}
        disabled={props.disabled}
        onChange={(event) => { props.onEdit(event.target.value) }}
      />
      <p className={css.hint}>{props.hint}</p>
    </div>
  )
}

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
      {fields.map(({ field, secret }) => {
        const control = state.fields[field]
        if (control === undefined) return null
        return (
          <CredentialField
            key={field}
            id={`plugin-config-soc-${field}`}
            label={t(`soc_${field}` as never)}
            hint={t(`soc_${field}Hint` as never)}
            // Its own writability disables the control — a value sourced from
            // the process environment cannot be written from here.
            disabled={!control.writable}
            text={control.text}
            masked={secret === true}
            configured={control.configured}
            // Only a write-only control needs the badge; the rest show their value.
            stateLabel={secret === true
              ? (control.configured ? t('socValueSet') : t('socValueUnset'))
              : undefined}
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
