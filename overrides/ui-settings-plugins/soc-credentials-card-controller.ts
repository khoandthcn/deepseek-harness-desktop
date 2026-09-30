/**
 * The staged forms behind the two SOC cards in Settings.
 *
 * Each card writes to two places, because its controls are two different
 * kinds of thing.
 *
 * The **secrets** — the password and the API key — go through the credentials
 * domain. A credential's literal never rides a response, so those controls
 * learn only whether the Host holds a value, start blank, and a blank draft
 * writes nothing.
 *
 * Everything else — the platform domains, the sign-in client id, the account
 * names — is configuration, and lives in the card's own **settings section**.
 * A settings value does ride a response, so those controls come back filled
 * in: the user types a domain once rather than on every visit to this tab.
 * `soc-auth` reads the same section when it signs in.
 *
 * There are two cards because there are two platforms: the SOC systems behind
 * one sign-in, and the Threat Intelligence platform, which is a separate
 * account on a separate host. Each card saves on its own.
 *
 * @module
 */

import type { Context as ClientContext } from '@deepseek-ai/cordis'
// Type-only: pulls the ctx.remote merge into this program.
import type {} from '@deepseek-ai/dsh-api-remotes/client'
import type { SnapshotStore } from '@deepseek-ai/dsh-client-store'
import type { SettingsScope } from '@deepseek-ai/dsh-client-ui-settings/client'
import {
  CardForm, textField, type CardActions, type CardFieldState, type CardShell,
} from './card-form.ts'

/**
 * Namespace of the SOC card. Its values do not live in that section — they go
 * through the credentials domain — but the Plugins tab dispatches a card only
 * for a namespace the Host serves, so the section exists to say "this
 * deployment has SOC Cloud".
 */
export const SOC_CREDENTIALS_NS = 'soc-credentials'

/** Namespace of the Threat Intelligence card, for the same reason. */
export const SOC_TI_NS = 'soc-threat-intel'

/** One control on a card: the form field it stages under, and where it is kept. */
export interface CardCredentialField {
  /**
   * The field name. It is the locale key suffix (`soc_<field>`) and, for
   * everything but a secret, the key inside the card's settings section.
   */
  readonly field: string
  /**
   * The credential reference the Host stores it under. A secret is written
   * there; for the rest it names the environment variable and the older store
   * entry that still answer for the field when the section carries nothing.
   */
  readonly ref: string
  /**
   * Whether this control holds a secret: written to the credentials domain,
   * masked, write-only, and blank until typed. Everything else is
   * configuration, kept in the settings section and shown filled in.
   */
  readonly secret?: boolean
}

/**
 * The SOC card's controls: the platform domain every system's URL is derived
 * from, the OAuth client the platform issued for this app, and the sign-in.
 *
 * The client id is per deployment, not per user, but it has to be here: a
 * public build carries no platform's identifiers, so without this control a
 * user who installed one has no way to supply it and sign-in cannot start.
 *
 * The tenant is deliberately absent — it defaults to the account's own
 * top-level one, which already sees every tenant below it the account may see.
 * A deployment that needs another value sets it in `soc-endpoints.json` or in
 * its preset row.
 */
export const SOC_FIELDS: readonly CardCredentialField[] = [
  { field: 'socDomain', ref: 'SOC_DOMAIN' },
  { field: 'socClientId', ref: 'SOC_CLIENT_ID' },
  { field: 'socUsername', ref: 'SOC_USERNAME' },
  { field: 'socPassword', ref: 'SOC_PASSWORD', secret: true },
]

/** The section keys a card edits: every control that is not a secret. */
export function sectionFields(fields: readonly CardCredentialField[]): string[] {
  return fields.filter(entry => entry.secret !== true).map(entry => entry.field)
}

/** The Threat Intelligence card's controls: its host and its account. */
export const TI_FIELDS: readonly CardCredentialField[] = [
  { field: 'tiDomain', ref: 'TI_DOMAIN' },
  { field: 'tiUsername', ref: 'TI_USERNAME' },
  { field: 'tiApiKey', ref: 'TI_API_KEY', secret: true },
]

/** What the credentials domain last reported for one reference. */
interface CredentialState {
  /** Whether any layer supplies a value for it. */
  configured: boolean
  /** Whether `credentials/set` can affect it; false disables the control. */
  writable: boolean
}

/** One rendered control: its staged draft plus what the Host holds. */
export type CardCredentialState = CardFieldState & CredentialState

/** What either card renders. */
export interface SocCredentialsCardState extends CardShell {
  /** One entry per control, keyed by field, in the card's own order. */
  fields: Record<string, CardCredentialState>
}

/** The registration-side face a card's slot entry injects. */
export interface SocCredentialsCardFace extends CardActions {
  hooks: {
    /** Card snapshot bound by the renderer as useSocCredentialsCard. */
    socCredentialsCard: SnapshotStore<SocCredentialsCardState>
  }
}

/**
 * The state a reference reports before any answer, and for a reference the Host
 * does not recognize: not configured, and writable so the control stays usable
 * and the Host is what refuses.
 */
const UNKNOWN_CREDENTIAL: CredentialState = { configured: false, writable: true }

/** Bridges one platform's credential references onto its card. */
export class SocCredentialsCardController {
  private readonly form: CardForm<Record<string, unknown>>
  private readonly store: SnapshotStore<SocCredentialsCardState>
  private readonly secrets: readonly CardCredentialField[]
  private states: Record<string, CredentialState>

  /**
   * @param scope - a bound settings scope, used only to drive the shared form
   *   model; this card's values live in the credentials domain.
   * @param ctx - the card plugin's context, whose `remote.credentials`
   *   namespace answers for this card's references.
   * @param fields - the controls this card carries, in render order.
   */
  constructor(
    scope: SettingsScope<Record<string, unknown>>,
    private readonly ctx: ClientContext,
    private readonly fields: readonly CardCredentialField[],
  ) {
    this.secrets = fields.filter(entry => entry.secret === true)
    this.states = Object.fromEntries(this.secrets.map(entry => [entry.field, UNKNOWN_CREDENTIAL]))
    this.form = new CardForm(
      scope,
      // Configuration: kept in the section, so each control comes back with
      // what the user typed rather than empty.
      sectionFields(fields).map(field => textField(field)),
      // Secrets: written to the credentials domain, which answers only whether
      // it holds one.
      this.secrets.map(entry => ({
        field: entry.field,
        write: (text: string) => this.writeRef(entry.ref, text),
      })),
    )
    this.store = this.form.bind(() => this.projection())
    void this.readCredentials()
  }

  private projection(): SocCredentialsCardState {
    return {
      ...this.form.shell(),
      // The card always renders: its Host section exists to say the deployment
      // has this platform, and carries no values to wait for.
      available: true,
      // A card is writable when any of its controls is: the section answers
      // for the configuration, the credentials domain for the secrets.
      writable: this.form.shell().writable
        || this.secrets.some(entry => this.states[entry.field]?.writable ?? true),
      fields: Object.fromEntries(this.fields.map(entry => [entry.field, {
        ...this.form.field(entry.field),
        // A section field reports no credential state: it shows its value, so
        // there is nothing for a "configured" badge to add.
        configured: this.states[entry.field]?.configured ?? false,
        writable: this.states[entry.field]?.writable ?? true,
      }])),
    }
  }

  /**
   * Read whether the Host holds each of this card's references, in one describe
   * batch. A failed read leaves the last-known states in place.
   */
  private async readCredentials(): Promise<void> {
    if (this.secrets.length === 0) return
    const response = await this.ctx.remote.credentials.describe(this.secrets.map(entry => entry.ref))
    if (!response.ok) return
    this.states = Object.fromEntries(this.secrets.map((entry) => {
      const view = response.value[entry.ref]
      // An unknown reference is treated as writable: the control stays usable
      // and the Host is what refuses, rather than the card guessing a refusal.
      return [entry.field, { configured: view?.configured ?? false, writable: view?.writable ?? true }]
    }))
    this.store.set(this.projection())
  }

  /**
   * Re-read after the Host reports a change to one of this card's references.
   *
   * A credential can be written from elsewhere — the file store, another
   * surface — without any settings section changing, so this event is the only
   * signal that reaches the card.
   * @param ref - the reference the Host reports as changed.
   */
  refreshCredential(ref: string): void {
    if (!this.secrets.some(entry => entry.ref === ref)) return
    void this.readCredentials()
  }

  /**
   * Build the face this card's slot registration injects.
   * @returns the card's snapshot and its form actions.
   */
  inject(): SocCredentialsCardFace {
    return { hooks: { socCredentialsCard: this.store }, ...this.form.actions() }
  }

  /**
   * Write one staged value, then re-read whether the Host now holds it. The
   * value is never logged or echoed.
   * @param ref - the credential reference to write.
   * @param value - the staged literal.
   * @returns whether the Host reports the reference configured afterwards.
   */
  private async writeRef(ref: string, value: string): Promise<boolean> {
    // Refusals surface through the re-read: the Host is the only authority on
    // whether the value now exists.
    await this.ctx.remote.credentials.set(ref, value)
    await this.readCredentials()
    const field = this.secrets.find(entry => entry.ref === ref)?.field
    return field === undefined ? false : this.states[field]?.configured ?? false
  }
}
