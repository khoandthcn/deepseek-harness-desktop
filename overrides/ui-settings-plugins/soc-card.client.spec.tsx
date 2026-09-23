// @vitest-environment jsdom

/**
 * Renders the SOC Cloud card itself.
 *
 * The card is the only place a user of a public build can point the tools at
 * their own systems, and a card that throws while rendering leaves the Plugins
 * tab showing every other card and no sign of this one — which is exactly how
 * a missing endpoint control would present. So this renders the real component
 * with a full snapshot and asserts every control is there.
 */
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { bindSnapshotSelector } from '@deepseek-ai/dsh-client-test-runtime'
import { createSnapshotStore } from '@deepseek-ai/dsh-client-store'
import { SocCredentialsCard } from '../src/client/SocCredentialsCard.tsx'
import type { SocCredentialsCardProps } from '../src/client/SocCredentialsCard.tsx'
import { ENDPOINT_FIELDS } from '../src/client/soc-credentials-card-controller.ts'
import type { SocCredentialsCardState } from '../src/client/soc-credentials-card-controller.ts'
import { en } from '../src/client/locales.ts'

const t = (key: keyof typeof en) => en[key]

const field = { text: '', initial: '', overridden: false, invalid: false }

function state(overrides: Partial<SocCredentialsCardState> = {}): SocCredentialsCardState {
  return {
    available: true,
    writable: true,
    dirty: false,
    invalid: false,
    saving: false,
    failed: false,
    username: { ...field },
    usernameConfigured: false,
    usernameWritable: true,
    password: { ...field },
    passwordConfigured: false,
    passwordWritable: true,
    endpoints: Object.fromEntries(ENDPOINT_FIELDS.map(name => [name, {
      ...field,
      configured: false,
      writable: true,
    }])) as unknown as SocCredentialsCardState['endpoints'],
    ...overrides,
  } as SocCredentialsCardState
}

function renderCard(overrides: Partial<SocCredentialsCardState> = {}) {
  const store = createSnapshotStore<SocCredentialsCardState>(state(overrides))
  const actions = { edit: vi.fn(), resetField: vi.fn(), save: vi.fn(), discard: vi.fn() }
  const props = {
    ...actions,
    t,
    useSocCredentialsCard: bindSnapshotSelector(store),
  } as unknown as SocCredentialsCardProps
  render(<SocCredentialsCard {...props} />)
  return actions
}

/** The card ships collapsed, as every card in this tab does. */
function expand() {
  fireEvent.click(screen.getByRole('button', { name: /SOC Cloud credentials/ }))
}

afterEach(() => { cleanup() })

describe('SocCredentialsCard', () => {
  it('renders the sign-in and every endpoint control', () => {
    renderCard()
    expand()
    expect(screen.getByLabelText(en.socUsername)).toBeTruthy()
    expect(screen.getByLabelText(en.socPassword)).toBeTruthy()
    for (const name of ENDPOINT_FIELDS) {
      expect(screen.getByLabelText(en[`soc_${name}` as keyof typeof en]), name).toBeTruthy()
    }
  })

  it('stages an endpoint edit under its own field', () => {
    const actions = renderCard()
    expand()
    fireEvent.change(screen.getByLabelText(en.soc_iamUrl), { target: { value: 'https://iam.example' } })
    expect(actions.edit).toHaveBeenCalledWith('iamUrl', 'https://iam.example')
  })

  it('reports which endpoints the Host already holds', () => {
    renderCard({
      endpoints: Object.fromEntries(ENDPOINT_FIELDS.map(name => [name, {
        ...field,
        configured: name === 'iamUrl',
        writable: true,
      }])) as unknown as SocCredentialsCardState['endpoints'],
    })
    expand()
    expect(screen.getAllByText(en.socValueSet)).toHaveLength(1)
    expect(screen.getAllByText(en.socValueUnset)).toHaveLength(ENDPOINT_FIELDS.length - 1)
  })
})
