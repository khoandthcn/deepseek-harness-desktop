/**
 * The SOC Cloud credentials card's staged form over the SOC sign-in the SOC
 * Cloud tools use.
 *
 * Both controls live outside any settings section: their literals never ride a
 * response, so the card learns only whether each is configured and writes them
 * through the credentials domain, addressed by the fixed references the
 * `soc-auth` Host plugin reads. That plugin is composed only inside the
 * `soc-cloud` preset, per agent session, so the card gates on no settings
 * namespace — it always renders, and the credentials domain is its one backing
 * store.
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
 * Nominal namespace this card binds its form to. No Host plugin serves it, so
 * the bound scope never turns ready; the card forces its own availability and
 * reads state from the credentials domain instead. It doubles as the card's
 * keyed slot key.
 */
export const SOC_CREDENTIALS_NS = 'soc-credentials'

/** Credential reference holding the SOC username. */
const USERNAME_REF = 'SOC_USERNAME'

/** Credential reference holding the SOC password. */
const PASSWORD_REF = 'SOC_PASSWORD'

/** Form field the username control stages under. */
const USERNAME_FIELD = 'username'

/** Form field the password control stages under. */
const PASSWORD_FIELD = 'password'

/** What the credentials domain last reported for one reference. */
interface CredentialState {
  /** Whether any layer supplies a value for it. */
  configured: boolean
  /** Whether `credentials/set` can affect it; false disables the control. */
  writable: boolean
}

/** What the SOC Cloud credentials card renders. */
export interface SocCredentialsCardState extends CardShell {
  /** The staged username, which starts blank on every load. */
  username: CardFieldState
  /** Whether the Host reports a username configured for the reference. */
  usernameConfigured: boolean
  /** Whether the credentials domain accepts a write for the username; false disables the control. */
  usernameWritable: boolean
  /** The staged password, which starts blank on every load. */
  password: CardFieldState
  /** Whether the Host reports a password configured for the reference. */
  passwordConfigured: boolean
  /** Whether the credentials domain accepts a write for the password; false disables the control. */
  passwordWritable: boolean
}

/** The registration-side face the SOC Cloud credentials card's slot entry injects. */
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

/** Bridges the SOC sign-in credentials onto the always-rendered card. */
export class SocCredentialsCardController {
  private readonly form: CardForm<Record<string, never>>
  private readonly store: SnapshotStore<SocCredentialsCardState>
  private username: CredentialState = UNKNOWN_CREDENTIAL
  private password: CredentialState = UNKNOWN_CREDENTIAL

  /**
   * @param scope - a bound settings scope used only to drive the shared form
   * model; no Host plugin serves its namespace.
   * @param ctx - the card plugin's context, whose `remote.credentials` namespace
   * answers for the two SOC references.
   */
  constructor(
    scope: SettingsScope<Record<string, never>>,
    private readonly ctx: ClientContext,
  ) {
    this.form = new CardForm(
      scope,
      [],
      [
        { field: USERNAME_FIELD, write: text => this.writeRef(USERNAME_REF, text) },
        { field: PASSWORD_FIELD, write: text => this.writeRef(PASSWORD_REF, text) },
      ],
    )
    this.store = this.form.bind(() => this.projection())
    void this.readCredentials()
  }

  private projection(): SocCredentialsCardState {
    return {
      ...this.form.shell(),
      // The card always renders: gating on a settings namespace would flicker
      // it in and out, because the soc-auth Host plugin is composed only inside
      // the soc-cloud preset.
      available: true,
      // The credentials domain, not a settings document, is this card's store;
      // its writability is what the shell reports.
      writable: this.username.writable || this.password.writable,
      username: this.form.field(USERNAME_FIELD),
      usernameConfigured: this.username.configured,
      usernameWritable: this.username.writable,
      password: this.form.field(PASSWORD_FIELD),
      passwordConfigured: this.password.configured,
      passwordWritable: this.password.writable,
    }
  }

  /**
   * Read whether the Host holds each SOC credential, in one describe batch.
   * A failed read leaves the last-known states in place.
   */
  private async readCredentials(): Promise<void> {
    const response = await this.ctx.remote.credentials.describe([USERNAME_REF, PASSWORD_REF])
    if (!response.ok) return
    const read = (ref: string): CredentialState => {
      const view = response.value[ref]
      // An unknown reference is treated as writable: the control stays usable
      // and the Host is what refuses, rather than the card guessing a refusal.
      return { configured: view?.configured ?? false, writable: view?.writable ?? true }
    }
    this.username = read(USERNAME_REF)
    this.password = read(PASSWORD_REF)
    this.store.set(this.projection())
  }

  /**
   * Re-read after the Host reports a change to either SOC reference.
   *
   * A credential can be written from elsewhere — the file store, another
   * surface — without any settings section changing, so this event is the only
   * signal that reaches the card.
   * @param ref - the reference the Host reports as changed.
   */
  refreshCredential(ref: string): void {
    if (ref !== USERNAME_REF && ref !== PASSWORD_REF) return
    void this.readCredentials()
  }

  /**
   * Build the face the card's slot registration injects.
   * @returns the card's snapshot and its form actions.
   */
  inject(): SocCredentialsCardFace {
    return { hooks: { socCredentialsCard: this.store }, ...this.form.actions() }
  }

  /**
   * Write one staged credential, then re-read whether the Host now holds it.
   * The value is never logged or echoed.
   * @param ref - the credential reference to write.
   * @param value - the staged literal.
   * @returns whether the Host reports the reference configured afterwards.
   */
  private async writeRef(ref: string, value: string): Promise<boolean> {
    // Refusals surface through the re-read: the Host is the only authority on
    // whether the credential now exists.
    await this.ctx.remote.credentials.set(ref, value)
    await this.readCredentials()
    return (ref === USERNAME_REF ? this.username : this.password).configured
  }
}
