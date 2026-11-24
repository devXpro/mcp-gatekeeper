import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from '../../lib/api'
import type * as Passkeys from '../../lib/passkeys'
import { StepUpProvider, useStepUp } from './stepup'

// The browser's passkey prompt is out of reach in jsdom: the assertion comes back at once.
vi.mock('../../lib/passkeys', async (importOriginal) => ({
  ...(await importOriginal<typeof Passkeys>()),
  getAssertion: vi.fn(async () => ({ id: 'cred', rawId: 'cred', type: 'public-key', response: {}, clientExtensionResults: {} })),
}))

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

/** Harness runs `action` through withStepUp when its button is pressed and prints what came back. */
function Harness({ action }: { action: () => Promise<string> }) {
  const { withStepUp } = useStepUp()
  const [out, setOut] = useState('—')
  return (
    <>
      <button type="button" onClick={() => void withStepUp(action, 'удалить всё').then((r) => setOut(r ?? 'cancelled'), () => setOut('error'))}>
        go
      </button>
      <output>{out}</output>
    </>
  )
}

function renderWith(action: () => Promise<string>) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <StepUpProvider>
        <Harness action={action} />
      </StepUpProvider>
    </QueryClientProvider>,
  )
}

describe('withStepUp', () => {
  const fetchMock = vi.fn<typeof fetch>()
  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => vi.unstubAllGlobals())

  it('passes through when no step-up is needed', async () => {
    const action = vi.fn(async () => 'done')
    renderWith(action)
    await userEvent.click(screen.getByRole('button', { name: 'go' }))
    expect(await screen.findByText('done')).toBeInTheDocument()
    expect(action).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('Подтвердите, что это вы')).not.toBeInTheDocument()
  })

  it('on step_up_required confirms with a passkey, then retries the action once', async () => {
    fetchMock.mockImplementation(async (url) =>
      String(url).endsWith('/stepup/begin') ? json(200, { options: { challenge: 'abc' } }) : json(200, { step_up_until: '2026-11-20T12:05:00Z' }),
    )
    let calls = 0
    const action = vi.fn(async () => {
      calls++
      if (calls === 1) throw new ApiError(403, 'step_up_required', 'fresh passkey needed')
      return 'done'
    })
    renderWith(action)
    await userEvent.click(screen.getByRole('button', { name: 'go' }))
    expect(await screen.findByText('Чтобы удалить всё, нужен Face ID или Touch ID.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Подтвердить' }))
    expect(await screen.findByText('done')).toBeInTheDocument()
    expect(action).toHaveBeenCalledTimes(2)
    const urls = fetchMock.mock.calls.map(([u]) => String(u))
    expect(urls).toEqual(['/api/auth/stepup/begin', '/api/auth/stepup/finish'])
    // The finish call carries the credential only.
    expect(JSON.parse(String(fetchMock.mock.calls[1][1]?.body))).toEqual({ credential: expect.objectContaining({ id: 'cred' }) })
  })

  it('drops the action without an error when the person cancels', async () => {
    const action = vi.fn(async () => {
      throw new ApiError(403, 'step_up_required', 'fresh passkey needed')
    })
    renderWith(action)
    await userEvent.click(screen.getByRole('button', { name: 'go' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Отмена' }))
    expect(await screen.findByText('cancelled')).toBeInTheDocument()
    expect(action).toHaveBeenCalledTimes(1)
  })

  it('lets every other error through to the caller', async () => {
    const action = vi.fn(async () => {
      throw new ApiError(403, 'forbidden', 'owner only')
    })
    renderWith(action)
    await userEvent.click(screen.getByRole('button', { name: 'go' }))
    expect(await screen.findByText('error')).toBeInTheDocument()
    expect(action).toHaveBeenCalledTimes(1)
  })
})
