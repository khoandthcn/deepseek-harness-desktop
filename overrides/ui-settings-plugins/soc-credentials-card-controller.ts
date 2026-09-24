/**
 * The staged forms behind the two SOC cards in Settings.
 *
 * Both cards write through the **credentials domain**, not into a settings
 * section: a credential's literal never rides a response, so each control
 * learns only whether the Host holds a value for its reference. The platform's
 * domain and tenant are configuration rather than secrets, but they share the
 * store because it is the one surface a card can write to, and because it keeps
 * every setting of one platform in one place. `soc-auth` reads the same
 * references when it signs in.
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
  CardForm, type CardActions, type CardFieldState, type CardShell,
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
  /** The field name, which is also the locale key suffix (`soc_<field>`). */
  readonly field: string
  /** The credential reference the Host stores it under. */
  readonly ref: string
}

/**
 * The SOC card's controls: the platform domain every system's URL is derived
 * from, the tenant its SOAR tools query, and the sign-in itself.
 *
 * The portal's OAuth client id is deliberately absent. IAM needs one to accept
 * an authorize, but it is fixed per platform and no user ever changes it, so it
 * belongs in `soc-endpoints.json` or the preset row, not on a card.
 */
export const SOC_FIELDS: readonly CardCredentialField[] = [
  { field: 'socDomain', ref: 'SOC_DOMAIN' },
  { field: 'tenant', ref: 'SOC_TENANT' },
  { field: 'socUsername', ref: 'SOC_USERNAME' },
  { field: 'socPassword', ref: 'SOC_PASSWORD' },
]

/** The Threat Intelligence card's controls: its host and its account. */
export const TI_FIELDS: readonly CardCredentialField[] = [
  { field: 'vtiDomain', ref: 'VTI_DOMAIN' },
  { field: 'vtiUsername', ref: 'VTI_USERNAME' },
  { field: 'vtiApiKey', ref: 'VTI_API_KEY' },
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
  private readonly form: CardForm<Record<string, never>>
  private readonly store: SnapshotStore<SocCredentialsCardState>
  private states: Record<string, CredentialState>

  /**
   * @param scope - a bound settings scope, used only to drive the shared form
   *   model; this card's values live in the credentials domain.
   * @param ctx - the card plugin's context, whose `remote.credentials`
   *   namespace answers for this card's references.
   * @param fields - the controls this card carries, in render order.
   */
  constructor(
    scope: SettingsScope<Record<string, never>>,
    private readonly ctx: ClientContext,
    private readonly fields: readonly CardCredentialField[],
  ) {
    this.states = Object.fromEntries(fields.map(entry => [entry.field, UNKNOWN_CREDENTIAL]))
    this.form = new CardForm(
      scope,
      [],
      fields.map(entry => ({
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
      // The credentials domain, not a settings document, is the backing store;
      // its writability is what the shell reports.
      writable: this.fields.some(entry => this.states[entry.field]?.writable ?? true),
      fields: Object.fromEntries(this.fields.map(entry => [entry.field, {
        ...this.form.field(entry.field),
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
    const response = await this.ctx.remote.credentials.describe(this.fields.map(entry => entry.ref))
    if (!response.ok) return
    this.states = Object.fromEntries(this.fields.map((entry) => {
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
    if (!this.fields.some(entry => entry.ref === ref)) return
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
    const field = this.fields.find(entry => entry.ref === ref)?.field
    return field === undefined ? false : this.states[field]?.configured ?? false
  }
}
