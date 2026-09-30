// @vitest-environment jsdom

/**
 * Renders the two SOC cards themselves.
 *
 * They are the only place a user of a public build can point the tools at
 * their own platforms, and a card that throws while rendering leaves the
 * Plugins tab showing every other card and no sign of this one — which is
 * exactly how a missing control would present. So this renders the real
 * components with a full snapshot and asserts every control is there.
 */
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { bindSnapshotSelector } from '@deepseek-ai/dsh-client-test-runtime'
import { createSnapshotStore } from '@deepseek-ai/dsh-client-store'
import { SocCredentialsCard, SocThreatIntelCard } from '../src/client/SocCredentialsCard.tsx'
import type { SocCredentialsCardProps } from '../src/client/SocCredentialsCard.tsx'
import { SOC_FIELDS, TI_FIELDS } from '../src/client/soc-credentials-card-controller.ts'
import type {
  CardCredentialField, SocCredentialsCardState,
} from '../src/client/soc-credentials-card-controller.ts'
import { en } from '../src/client/locales.ts'

const t = (key: keyof typeof en) => en[key]

const draft = { text: '', initial: '', overridden: false, invalid: false }

function state(
  fields: readonly CardCredentialField[],
  configured: (field: string) => boolean = () => false,
): SocCredentialsCardState {
  return {
    available: true,
    writable: true,
    dirty: false,
    invalid: false,
    saving: false,
    failed: false,
    fields: Object.fromEntries(fields.map(entry => [entry.field, {
      ...draft,
      configured: configured(entry.field),
      writable: true,
    }])),
  } as SocCredentialsCardState
}

function renderCard(
  Card: typeof SocCredentialsCard,
  fields: readonly CardCredentialField[],
  configured?: (field: string) => boolean,
) {
  const store = createSnapshotStore<SocCredentialsCardState>(state(fields, configured))
  const actions = { edit: vi.fn(), resetField: vi.fn(), save: vi.fn(), discard: vi.fn() }
  const props = {
    ...actions,
    t,
    useSocCredentialsCard: bindSnapshotSelector(store),
  } as unknown as SocCredentialsCardProps
  render(<Card {...props} />)
  return actions
}

/** The cards ship collapsed, as every card in this tab does. */
function expand(title: string) {
  fireEvent.click(screen.getByRole('button', { name: new RegExp(title) }))
}

afterEach(() => { cleanup() })

describe('the SOC platform card', () => {
  it('renders the platform domain and the sign-in', () => {
    renderCard(SocCredentialsCard, SOC_FIELDS)
    expand(en.socTitle)
    for (const { field } of SOC_FIELDS) {
      expect(screen.getByLabelText(en[`soc_${field}` as keyof typeof en]), field).toBeTruthy()
    }
  })

  it('carries the sign-in client id, which a public build cannot know', () => {
    renderCard(SocCredentialsCard, SOC_FIELDS)
    expand(en.socTitle)
    expect(screen.getByLabelText(en.soc_socClientId)).toBeTruthy()
  })

  it('carries no tenant: the account\'s own already covers what it may see', () => {
    renderCard(SocCredentialsCard, SOC_FIELDS)
    expand(en.socTitle)
    expect(SOC_FIELDS.map(entry => entry.field)).not.toContain('tenant')
  })

  it('stages the platform domain, which configures every system', () => {
    const actions = renderCard(SocCredentialsCard, SOC_FIELDS)
    expand(en.socTitle)
    fireEvent.change(screen.getByLabelText(en.soc_socDomain), { target: { value: 'soc.example.com' } })
    expect(actions.edit).toHaveBeenCalledWith('socDomain', 'soc.example.com')
  })

  it('badges only the secret, whose value it cannot show', () => {
    // A control that renders its value needs no badge saying it has one; the
    // password cannot be read back, so it is the one that does.
    renderCard(SocCredentialsCard, SOC_FIELDS, field => field === 'socPassword')
    expand(en.socTitle)
    expect(screen.getAllByText(en.socValueSet)).toHaveLength(1)
    expect(screen.queryByText(en.socValueUnset)).toBeNull()
  })
})

describe('the Threat Intelligence card', () => {
  it('is a card of its own, carrying that platform and its account', () => {
    renderCard(SocThreatIntelCard, TI_FIELDS)
    expand(en.tiTitle)
    for (const { field } of TI_FIELDS) {
      expect(screen.getByLabelText(en[`soc_${field}` as keyof typeof en]), field).toBeTruthy()
    }
    // the SOC sign-in belongs to the other card
    expect(screen.queryByLabelText(en.soc_socUsername)).toBeNull()
  })

  it('stages its API key under its own field', () => {
    const actions = renderCard(SocThreatIntelCard, TI_FIELDS)
    expand(en.tiTitle)
    fireEvent.change(screen.getByLabelText(en.soc_tiApiKey), { target: { value: 'KEY' } })
    expect(actions.edit).toHaveBeenCalledWith('tiApiKey', 'KEY')
  })
})

describe('masking', () => {
  it('masks the secrets and leaves the rest readable while typing', () => {
    renderCard(SocCredentialsCard, SOC_FIELDS)
    expand(en.socTitle)
    for (const { field, secret } of SOC_FIELDS) {
      const control = screen.getByLabelText(en[`soc_${field}` as keyof typeof en])
      expect(control.getAttribute('type'), field).toBe(secret === true ? 'password' : 'text')
    }
  })

  it('masks the API key but not the platform or the account name', () => {
    renderCard(SocThreatIntelCard, TI_FIELDS)
    expand(en.tiTitle)
    expect(screen.getByLabelText(en.soc_tiDomain).getAttribute('type')).toBe('text')
    expect(screen.getByLabelText(en.soc_tiUsername).getAttribute('type')).toBe('text')
    expect(screen.getByLabelText(en.soc_tiApiKey).getAttribute('type')).toBe('password')
  })
})

describe('the two cards together', () => {
  it('keep every reference distinct, so one card never writes the other\'s', () => {
    const refs = [...SOC_FIELDS, ...TI_FIELDS].map(entry => entry.ref)
    expect(new Set(refs).size).toBe(refs.length)
  })
})
