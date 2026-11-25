import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { GatekeeperApp } from '../../app/GatekeeperApp'
import type * as Passkeys from '../../lib/passkeys'
import type { Account, Me } from '../../lib/types'

// Where sign-in lands without ?next= (a signed-out visit to bare "/"): at "/", so the shell's index route decides —
// an application's indexRoute, or the redirect to /connect.

let signedIn = false

vi.mock('../../lib/passkeys', async (importOriginal) => ({
  ...(await importOriginal<typeof Passkeys>()),
  webauthnSupported: () => true,
  // The browser's passkey prompt is out of reach in jsdom: signing in just opens the session.
  signIn: async () => {
    signedIn = true
  },
}))

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const me: Me = { person: { id: 'p_1', name: 'Алиса', role: 'owner', superadmin: false }, account: { id: 'a_1', name: 'Дом' } }
const account: Account = { id: 'a_1', name: 'Дом', members: [], invites: null }

describe('sign-in without next', () => {
  const fetchMock = vi.fn<typeof fetch>()
  beforeEach(() => {
    signedIn = false
    fetchMock.mockReset()
    fetchMock.mockImplementation(async (input) => {
      const u = String(input)
      if (u === '/api/me') return signedIn ? json(200, me) : json(401, { error: 'no_session', message: 'sign in first' })
      if (u === '/api/account') return json(200, account)
      if (u === '/api/account/connections' || u === '/api/me/passkeys') return json(200, [])
      return json(404, { error: 'not_found' })
    })
    vi.stubGlobal('fetch', fetchMock)
    window.history.replaceState(null, '', '/')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    window.history.replaceState(null, '', '/')
  })

  async function signInFromBareRoot() {
    // Bare "/" signed out: the shell sends the person to /login, with no next or with next=/ (the 401 listener's).
    expect(await screen.findByRole('button', { name: 'Войти' })).toBeInTheDocument()
    expect(window.location.pathname).toBe('/login')
    expect(['', '?next=%2F']).toContain(window.location.search)
    await userEvent.click(screen.getByRole('button', { name: 'Войти' }))
  }

  it('lands on the application’s index page', async () => {
    render(<GatekeeperApp indexRoute={{ element: <p>app home</p>, handle: { page: 'home', tab: 'home', depth: 0 } }} />)
    await signInFromBareRoot()
    expect(await screen.findByText('app home')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/')
  })

  it('without an indexRoute still ends on /connect', async () => {
    render(<GatekeeperApp />)
    await signInFromBareRoot()
    expect(await screen.findByRole('heading', { level: 1, name: 'Сервисы' })).toBeInTheDocument()
    expect(window.location.pathname).toBe('/connect')
  })
})
