import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { GatekeeperApp } from '../../app/GatekeeperApp'
import type * as Passkeys from '../../lib/passkeys'

// A co-owner's invite (POST /api/auth/token says co_owner): the join page names the account they join as a co-owner
// and never asks for, nor sends, the account's name. (The first owner's screens are Family Hub's, unchanged.)

vi.mock('../../lib/passkeys', async (importOriginal) => ({
  ...(await importOriginal<typeof Passkeys>()),
  createCredential: vi.fn(async () => ({ id: 'cred', rawId: 'cred', type: 'public-key', response: {}, clientExtensionResults: {} })),
}))

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

describe('join as a co-owner', () => {
  const fetchMock = vi.fn<typeof fetch>()
  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    window.history.replaceState(null, '', '/')
  })

  it('skips the account name and says they join as a co-owner', async () => {
    const posts: { url: string; body: unknown }[] = []
    fetchMock.mockImplementation(async (input, init) => {
      const url = String(input)
      if (init?.method === 'POST') posts.push({ url, body: JSON.parse(String(init.body)) })
      if (url === '/api/auth/token') return json(200, { kind: 'owner', name: 'Борис', account_name: 'Дом', co_owner: true })
      if (url === '/api/auth/register/begin') return json(200, { options: { challenge: 'abc' } })
      if (url === '/api/auth/register/finish') return json(200, {})
      return json(401, { error: 'no_session' })
    })
    window.history.replaceState(null, '', '/join#t=tok-1')
    render(<GatekeeperApp />)

    expect(await screen.findByRole('heading', { name: 'Вас зовут в «Дом» совладельцем' })).toBeInTheDocument()
    expect(screen.getByRole('img', { name: 'Шаг 1 из 3' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Начать' }))
    expect(await screen.findByRole('textbox', { name: 'Ваше имя' })).toHaveValue('Борис')
    await userEvent.click(screen.getByRole('button', { name: 'Дальше' }))
    // Straight to the passkey: no step for the account's name.
    await userEvent.click(await screen.findByRole('button', { name: 'Создать ключ' }))
    expect(await screen.findByText('Вы совладелец «Дом». Осталось подключить ChatGPT или Claude.')).toBeInTheDocument()
    expect(screen.queryByText('Как назовём семью?')).toBeNull()
    expect(posts.find((p) => p.url === '/api/auth/register/begin')?.body).toEqual({ token: 'tok-1', name: 'Борис' })
  })
})
