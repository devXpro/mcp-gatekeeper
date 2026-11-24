import { render, screen, within } from '@testing-library/react'
import { ShieldHalf } from 'lucide-react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Account, ConsentTxn, Me } from '../lib/types'
import type { CardSlotProps, Resource } from './context'
import { GatekeeperApp } from './GatekeeperApp'

// The application's wiring end to end: the router, the shell with an extra tab, and the connect page filled from the
// application's resources and slots; the consent page reads `resource`.

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const me: Me = { person: { id: 'p_1', name: 'Алиса', role: 'owner', superadmin: true }, account: { id: 'a_1', name: 'Наша семья' } }

interface AppModule extends Resource {
  configured: boolean
}

const account: Account & { modules: AppModule[] } = {
  id: 'a_1',
  name: 'Наша семья',
  members: [{ id: 'p_1', name: 'Алиса', role: 'owner', joined_at: '2026-11-01T10:00:00Z', you: true }],
  invites: null,
  modules: [
    { id: 'notes', name: 'Дневник', description: 'Школа', mcp_url: 'https://hub.example/mcp/notes', enabled: true, configured: false },
    { id: 'off', name: 'Выключен', mcp_url: 'https://hub.example/mcp/off', enabled: false, configured: true },
  ],
}

function Badge({ resource }: CardSlotProps) {
  return <span>badge:{resource.id}</span>
}

function BodyEnd({ resource, owner }: CardSlotProps) {
  return <span>{`body-end:${resource.id}:${owner}`}</span>
}

function End({ resource }: CardSlotProps) {
  return <span>end:{resource.id}</span>
}

function renderApp() {
  return render(
    <GatekeeperApp
      tabs={[
        { id: 'connect', root: '/connect', icon: ShieldHalf, label: 'tab.connect' },
        { id: 'account', root: '/account', icon: ShieldHalf, label: 'tab.account' },
        { id: 'admin', root: '/admin', icon: ShieldHalf, label: 'tab.admin', superadmin: true },
      ]}
      resources={(a) => (a as typeof account).modules}
      useBadges={() => ({ admin: true })}
      connect={{
        Badge,
        BodyEnd,
        End,
        hintKey: (r) => ((r as AppModule).configured ? undefined : 'connect.title'),
      }}
      routes={[{ path: 'admin', element: <p>admin page</p>, handle: { page: 'admin', tab: 'admin', depth: 0 } }]}
    />,
  )
}

describe('GatekeeperApp', () => {
  const fetchMock = vi.fn<typeof fetch>()
  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    window.history.replaceState(null, '', '/')
  })

  it('shows the connect page from the application’s resources and slots, with its tabs', async () => {
    fetchMock.mockImplementation(async (url) => {
      const u = String(url)
      if (u === '/api/me') return json(200, me)
      if (u === '/api/account') return json(200, account)
      if (u === '/api/account/connections') {
        // G7's rows name the resource in `resource`.
        return json(200, [
          { grant_id: 'g_1', resource: 'notes', assistant: 'chatgpt', client_name: 'ChatGPT', person: { id: 'p_1', name: 'Алиса' }, created_at: '2026-11-20T10:00:00Z', last_used_at: null },
        ])
      }
      if (u === '/api/me/passkeys') return json(200, [])
      return json(404, { error: 'not_found' })
    })
    renderApp()

    expect(await screen.findByRole('heading', { level: 1, name: 'Сервисы' })).toBeInTheDocument()
    const card = screen.getByRole('region', { name: 'Дневник' })
    expect(within(card).getByText('badge:notes')).toBeInTheDocument()
    expect(within(card).getByText('body-end:notes:true')).toBeInTheDocument()
    expect(within(card).getByText('end:notes')).toBeInTheDocument()
    expect(within(card).getByLabelText('Адрес для подключения')).toHaveTextContent('https://hub.example/mcp/notes')
    expect(await within(card).findByRole('button', { name: 'Отключить ChatGPT (Алиса)' })).toBeInTheDocument()
    // hintKey replaced the footnote of the unconfigured resource.
    expect(within(card).queryByText('Адрес скопируется сам: вставьте его в новый коннектор, потом подтвердите вход здесь.')).toBeNull()

    // The owner sees a resource that is off: its card, without the body, with the end slot.
    const off = screen.getByRole('region', { name: 'Выключен' })
    expect(within(off).queryByText(/body-end/)).toBeNull()
    expect(within(off).getByText('end:off')).toBeInTheDocument()

    // The superadmin's extra tab joins the gatekeeper's, with the application's badge.
    const nav = screen.getAllByRole('navigation', { name: 'Разделы' })[0]
    expect(within(nav).getByRole('link', { name: 'Управление' })).toHaveAttribute('href', '/admin')
  })

  it('reads the consent transaction’s resource', async () => {
    const txn: ConsentTxn = {
      assistant: 'chatgpt',
      client_name: 'ChatGPT',
      redirect_host: 'chatgpt.com',
      resource: { id: 'notes', name: 'Дневник', description: 'Оценки и расписание', tools: [{ name: 'grades', title: 'Оценки', access: 'read' }] },
      account: { id: 'a_1', name: 'Наша семья' },
      already_granted: false,
      started_from: 'assistant',
      client_kind: 'cimd',
    }
    fetchMock.mockImplementation(async (url) => {
      const u = String(url)
      if (u === '/api/me') return json(200, me)
      if (u === '/api/oauth/txn/txn_1') return json(200, txn)
      return json(404, { error: 'not_found' })
    })
    window.history.replaceState(null, '', '/consent?txn=txn_1')
    renderApp()

    expect(await screen.findByRole('heading', { level: 1, name: 'ChatGPT просит доступ к «Дневник»' })).toBeInTheDocument()
    expect(screen.getByText('Оценки и расписание')).toBeInTheDocument()
    expect(screen.getByText('Оценки')).toBeInTheDocument()
  })
})
