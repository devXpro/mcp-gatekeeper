import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ShieldHalf, Smartphone } from 'lucide-react'
import { useEffect } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '../lib/api'
import type { Account, Me } from '../lib/types'
import { configure } from '../setup'
import { TEST_BRAND } from '../test/brand'
import { GatekeeperApp, type GatekeeperAppProps } from './GatekeeperApp'

// The application's options of GatekeeperApp and configure() beyond the slots (all off by default, Family Hub's
// screens as before): accountDelete, indexRoute, tabs by role, the Overlay layer, invites turned off with a reason,
// ApiError.details and the words of the /api/me error screen.

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const owner: Me = { person: { id: 'p_1', name: 'Алиса', role: 'owner', superadmin: false }, account: { id: 'a_1', name: 'Дом' } }
const member: Me = { person: { id: 'p_2', name: 'Борис', role: 'member', superadmin: false }, account: { id: 'a_1', name: 'Дом' } }
const account: Account = {
  id: 'a_1',
  name: 'Дом',
  members: [{ id: 'p_1', name: 'Алиса', role: 'owner', joined_at: '2026-11-01T10:00:00Z', you: true }],
  invites: null,
}

const fetchMock = vi.fn<typeof fetch>()

function serve(me: Me | Response) {
  fetchMock.mockImplementation(async (input) => {
    const u = String(input)
    if (u === '/api/me') return me instanceof Response ? me.clone() : json(200, me)
    if (u === '/api/account') return json(200, account)
    if (u === '/api/account/connections' || u === '/api/me/passkeys') return json(200, [])
    return json(404, { error: 'not_found' })
  })
}

function renderAt(path: string, props: GatekeeperAppProps = {}) {
  window.history.replaceState(null, '', path)
  return render(<GatekeeperApp {...props} />)
}

beforeEach(() => {
  fetchMock.mockReset()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  vi.unstubAllGlobals()
  configure({ brand: TEST_BRAND })
  window.history.replaceState(null, '', '/')
})

describe('configure({ accountDelete })', () => {
  it('shows «Удалить всё» to the owner by default', async () => {
    serve(owner)
    renderAt('/account')
    expect(await screen.findByRole('link', { name: 'Удалить всё' })).toHaveAttribute('href', '/account/delete')
  })

  it('false hides the section and the page', async () => {
    configure({ brand: TEST_BRAND, accountDelete: false })
    serve(owner)
    const { unmount } = renderAt('/account')
    expect(await screen.findByRole('heading', { level: 1, name: 'Дом' })).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: 'Пригласить в семью' })).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Удалить всё' })).toBeNull()
    unmount()

    renderAt('/account/delete')
    // The not-found page (its title is not a large heading).
    expect((await screen.findAllByText('Такой страницы нет')).length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: 'Удалить всё' })).toBeNull()
  })
})

describe('indexRoute', () => {
  it('without it, "/" goes to /connect', async () => {
    serve(owner)
    renderAt('/')
    expect(await screen.findByRole('heading', { level: 1, name: 'Сервисы' })).toBeInTheDocument()
    expect(window.location.pathname).toBe('/connect')
  })

  it('puts the application’s page at "/" inside the shell, whatever the other routes', async () => {
    serve(owner)
    renderAt('/', {
      indexRoute: { element: <p>app home</p>, handle: { page: 'home', tab: 'home', depth: 0 } },
      routes: [{ path: '*', element: <p>catch-all</p>, handle: { page: 'x', depth: 0 } }],
    })
    expect(await screen.findByText('app home')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/')
    expect(screen.getAllByRole('navigation', { name: 'Разделы' }).length).toBeGreaterThan(0)
  })
})

describe('tabs by role', () => {
  const tabs = [
    { id: 'connect', root: '/connect', icon: ShieldHalf, label: 'tab.connect' },
    { id: 'devices', root: '/devices', icon: Smartphone, label: 'tab.admin', owner: true },
    { id: 'gated', root: '/gated', icon: Smartphone, label: 'tab.account', visible: (me: Me) => me.person.name === 'Алиса' },
  ]
  const names = () => within(screen.getAllByRole('navigation', { name: 'Разделы' })[0]).getAllByRole('link').map((a) => a.textContent)

  it('shows an owner tab to owners, and a tab by the application’s rule', async () => {
    serve(owner)
    renderAt('/connect', { tabs })
    await screen.findByRole('heading', { level: 1, name: 'Сервисы' })
    expect(names()).toEqual(['Сервисы', 'Управление', 'Семья'])
  })

  it('hides both from a member they do not fit', async () => {
    serve(member)
    renderAt('/connect', { tabs })
    await screen.findByRole('heading', { level: 1, name: 'Сервисы' })
    expect(names()).toEqual(['Сервисы'])
  })
})

describe('Overlay', () => {
  it('is mounted once by the shell and stays across pages', async () => {
    let mounts = 0
    function Strip({ me }: { me: Me }) {
      useEffect(() => {
        mounts++
      }, [])
      return <div role="status">strip of {me.person.name}</div>
    }
    serve(owner)
    renderAt('/connect', { Overlay: Strip })
    expect(await screen.findByText('strip of Алиса')).toBeInTheDocument()
    const nav = screen.getAllByRole('navigation', { name: 'Разделы' })[0]
    await userEvent.click(within(nav).getByRole('link', { name: 'Семья' }))
    // The tab opens its last page (the shell remembers it), somewhere under /account.
    await waitFor(() => expect(window.location.pathname).toMatch(/^\/account/))
    expect(screen.getByText('strip of Алиса')).toBeInTheDocument()
    expect(mounts).toBe(1)
  })
})

describe('useInvitesDisabled', () => {
  it('replaces the invite button with the application’s reason', async () => {
    serve(owner)
    renderAt('/account', { useInvitesDisabled: () => 'Приглашения выключены в режиме для пробы' })
    expect(await screen.findByText('Приглашения выключены в режиме для пробы')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Пригласить в семью' })).toBeNull()
  })

  it('keeps the button when it returns nothing', async () => {
    serve(owner)
    renderAt('/account', { useInvitesDisabled: () => undefined })
    expect(await screen.findByRole('button', { name: 'Пригласить в семью' })).toBeInTheDocument()
  })
})

describe('ApiError.details', () => {
  it('keeps every key of the error body besides error and message', async () => {
    fetchMock.mockResolvedValue(json(409, { error: 'conflict', message: 'busy', callId: 'c_1', jobId: 'j_1', fields: { name: 'taken' } }))
    const err = await api.post('/home/thing', {}).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).details).toEqual({ callId: 'c_1', jobId: 'j_1', fields: { name: 'taken' } })
    expect((err as ApiError).message).toBe('busy')
  })

  it('is empty for a body with only error and message', async () => {
    fetchMock.mockResolvedValue(json(403, { error: 'forbidden', message: 'owner only' }))
    const err = (await api.get('/x').catch((e: unknown) => e)) as ApiError
    expect(err.details).toEqual({})
  })
})

describe('the /api/me error screen', () => {
  it('words the error’s code, from the application’s strings', async () => {
    configure({ brand: TEST_BRAND, strings: { ru: { 'error.misdirected': 'Откройте админку по её настоящему адресу.' } } })
    serve(json(421, { error: 'misdirected', message: 'wrong host' }))
    renderAt('/connect')
    expect(await screen.findByText('Откройте админку по её настоящему адресу.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Повторить' })).toBeInTheDocument()
  })

  it('falls back to the generic words for a code without any', async () => {
    serve(json(400, { error: 'odd', message: 'odd' }))
    renderAt('/connect')
    expect(await screen.findByText('Что-то пошло не так. Попробуйте ещё раз.')).toBeInTheDocument()
  })
})
