import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type * as Passkeys from '../../lib/passkeys'
import { SignInPanel } from './SignIn'

// A guest whose term is over gets auth's 403 access_ended at sign-in: the panel says so in words. Every other refusal
// (a disabled person's 400 invalid, the CSRF 403 forbidden, even with the same words) keeps the passkey text.

vi.mock('../../lib/passkeys', async (importOriginal) => ({
  ...(await importOriginal<typeof Passkeys>()),
  webauthnSupported: () => true,
  // The browser's passkey prompt is out of reach in jsdom: the finish call goes out with a fixed credential.
  signIn: async () => {
    const { api } = await import('../../lib/api')
    await api.post('/auth/login/finish', { credential: { id: 'cred' } })
  },
}))

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('SignInPanel refusals', () => {
  const fetchMock = vi.fn<typeof fetch>()
  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => vi.unstubAllGlobals())

  it.each([
    ['an ended term', 403, { error: 'access_ended', message: 'your access has ended; ask the owner to extend it' }, 'Ваш доступ закончился. Попросите владельца продлить его.'],
    ['a disabled person', 400, { error: 'invalid', message: 'sign-in failed' }, 'Этот ключ не подходит. Попробуйте другой или попросите у семьи новую ссылку.'],
    ['a cross-site request', 403, { error: 'forbidden', message: 'cross-site request refused' }, 'Этот ключ не подходит. Попробуйте другой или попросите у семьи новую ссылку.'],
    ['a forbidden with the same words', 403, { error: 'forbidden', message: 'your access has ended; ask the owner to extend it' }, 'Этот ключ не подходит. Попробуйте другой или попросите у семьи новую ссылку.'],
  ])('%s', async (_, status, body, text) => {
    fetchMock.mockImplementation(async (input) =>
      String(input) === '/api/auth/login/begin' ? json(200, { options: { challenge: 'abc' } }) : json(status, body),
    )
    const onSignedIn = vi.fn()
    render(<SignInPanel title="Дом" onSignedIn={onSignedIn} />)
    await userEvent.click(screen.getByRole('button', { name: 'Войти' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(text)
    expect(onSignedIn).not.toHaveBeenCalled()
  })
})
