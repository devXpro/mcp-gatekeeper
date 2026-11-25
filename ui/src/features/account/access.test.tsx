import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AppProvider, GatekeeperApp } from '../../app/GatekeeperApp'
import { useLiveMode } from '../../app/context'
import { FamiliesSection } from '../admin/Families'
import type * as Passkeys from '../../lib/passkeys'
import type { Account, Connection, Me, PermissionInfo } from '../../lib/types'
import { configure } from '../../setup'
import { TEST_BRAND } from '../../test/brand'

// The access screens of ui/README.md (People's access): the invite sheet's pickers (only with the application's catalog), the
// co-owner choice (only for the superadmin, only with coOwners), expired people greyed with «Продлить», the member
// detail, and the step-up retry of a widening change. Without a catalog everything looks and sends as before.

// The browser's passkey prompt is out of reach in jsdom: the assertion comes back at once.
vi.mock('../../lib/passkeys', async (importOriginal) => ({
  ...(await importOriginal<typeof Passkeys>()),
  getAssertion: vi.fn(async () => ({ id: 'cred', rawId: 'cred', type: 'public-key', response: {}, clientExtensionResults: {} })),
}))

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

// 25 November 2026, 10:30 in the test's own time zone; terms end at the end of a local day.
const NOW = new Date(2026, 10, 25, 10, 30)
const endOf = (y: number, m: number, d: number) => new Date(y, m, d, 23, 59, 59).toISOString()

const catalog: PermissionInfo[] = [
  { id: 'res-a', title: { ru: 'Лампа', en: 'Lamp' }, group: { ru: 'Комната', en: 'Room' } },
  { id: 'res-b', title: { ru: 'Чайник', en: 'Kettle' }, group: { ru: 'Кухня', en: 'Kitchen' } },
]

const superMe: Me = { person: { id: 'p_1', name: 'Алиса', role: 'owner', superadmin: true }, account: { id: 'a_1', name: 'Дом' } }

function accountWith(members: Account['members']): Account {
  return {
    id: 'a_1',
    name: 'Дом',
    members: [{ id: 'p_1', name: 'Алиса', role: 'owner', joined_at: '2026-11-01T10:00:00Z', you: true, access_until: null, permissions: ['all'], active: true }, ...(members ?? [])],
    invites: null,
  }
}

const connections: Connection[] = [
  { grant_id: 'g_2', resource: 'home', assistant: 'claude', client_name: 'Claude', person: { id: 'p_2', name: 'Борис' }, created_at: '2026-11-20T10:00:00Z', last_used_at: null },
  { grant_id: 'g_1', resource: 'home', assistant: 'chatgpt', client_name: 'ChatGPT', person: { id: 'p_1', name: 'Алиса' }, created_at: '2026-11-20T10:00:00Z', last_used_at: null },
]

interface Call {
  method: string
  url: string
  body: unknown
}

/** serve answers the API from a table; `write` decides every non-GET call. Calls are recorded. */
function serve(fetchMock: ReturnType<typeof vi.fn<typeof fetch>>, me: Me, account: Account, write: (c: Call, n: number) => Response) {
  const calls: Call[] = []
  fetchMock.mockImplementation(async (input, init) => {
    const c: Call = { method: init?.method ?? 'GET', url: String(input), body: init?.body ? JSON.parse(String(init.body)) : undefined }
    calls.push(c)
    if (c.method === 'GET') {
      if (c.url === '/api/me') return json(200, me)
      if (c.url === '/api/account') return json(200, account)
      if (c.url === '/api/account/connections') return json(200, connections)
      if (c.url === '/api/me/passkeys') return json(200, [])
      return json(404, { error: 'not_found' })
    }
    if (c.url === '/api/auth/stepup/begin') return json(200, { options: { challenge: 'abc' } })
    if (c.url === '/api/auth/stepup/finish') return json(200, { step_up_until: '2026-11-25T10:35:00Z' })
    return write(c, calls.filter((x) => x.method === c.method && x.url === c.url).length)
  })
  return calls
}

const writes = (calls: Call[]) => calls.filter((c) => c.method !== 'GET' && !c.url.startsWith('/api/auth/stepup'))

function renderApp(withCatalog: boolean) {
  window.history.replaceState(null, '', '/account')
  return render(
    <GatekeeperApp
      resources={() => [{ id: 'home', name: 'Дом', mcp_url: 'https://home.example.com/mcp', enabled: true }]}
      usePermissions={withCatalog ? () => catalog : undefined}
    />,
  )
}

async function openInvite() {
  await userEvent.click(await screen.findByRole('button', { name: 'Пригласить в семью' }))
  return screen.findByRole('dialog', { name: 'Пригласить' })
}

describe('access screens', () => {
  const fetchMock = vi.fn<typeof fetch>()
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(NOW)
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    configure({ brand: TEST_BRAND })
    window.history.replaceState(null, '', '/')
  })

  it('without a catalog: no pickers, the invite sends the name only, a tap offers the removal', async () => {
    const member = { id: 'p_2', name: 'Борис', role: 'member' as const, joined_at: '2026-11-02T10:00:00Z', you: false }
    const calls = serve(fetchMock, superMe, { id: 'a_1', name: 'Дом', members: [{ id: 'p_1', name: 'Алиса', role: 'owner', joined_at: '2026-11-01T10:00:00Z', you: true }, member], invites: null }, () =>
      json(200, { id: 'i_1', url: 'https://home.example.com/join#t=x', expires_at: '2026-11-26T10:30:00Z' }),
    )
    renderApp(false)

    const row = await screen.findByRole('button', { name: /^Борис/ })
    expect(row).toHaveTextContent('Член семьи · с 2 ноября')
    expect(screen.getByText('Нажмите на человека или приглашение, чтобы удалить его.')).toBeInTheDocument()
    await userEvent.click(row)
    expect(await screen.findByRole('alertdialog', { name: 'Удалить Борис из семьи?' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Отмена' }))

    const sheet = await openInvite()
    expect(within(sheet).queryByRole('radiogroup', { name: 'Что доступно' })).toBeNull()
    expect(within(sheet).queryByRole('radiogroup', { name: 'Срок' })).toBeNull()
    expect(within(sheet).queryByRole('radiogroup', { name: 'Роль' })).toBeNull()
    await userEvent.type(within(sheet).getByLabelText('Как зовут?'), 'Карл')
    await userEvent.click(within(sheet).getByRole('button', { name: 'Создать приглашение' }))
    await screen.findByText('Отправьте ссылку: Карл откроет её на телефоне. Или покажите QR-код.')
    expect(writes(calls)).toEqual([{ method: 'POST', url: '/api/account/invites', body: { name: 'Карл' } }])
  })

  it('with a catalog: the invite sends the ticked permissions and the end of the chosen term', async () => {
    const calls = serve(fetchMock, superMe, accountWith([]), () => json(200, { id: 'i_1', url: 'https://home.example.com/join#t=x', expires_at: '2026-11-26T10:30:00Z' }))
    renderApp(true)

    const sheet = await openInvite()
    await userEvent.type(within(sheet).getByLabelText('Как зовут?'), 'Карл')
    // Everything is the default; ticks appear only for "only what you tick", by group.
    expect(within(sheet).getByRole('radio', { name: /^Всё/ })).toHaveAttribute('aria-checked', 'true')
    expect(within(sheet).queryByRole('checkbox', { name: 'Лампа' })).toBeNull()
    await userEvent.click(within(sheet).getByRole('radio', { name: 'Только выбранное' }))
    expect(within(sheet).getByRole('heading', { name: 'Комната' })).toBeInTheDocument()
    expect(within(sheet).getByRole('heading', { name: 'Кухня' })).toBeInTheDocument()

    // Nothing ticked is refused before any call.
    await userEvent.click(within(sheet).getByRole('button', { name: 'Создать приглашение' }))
    expect(within(sheet).getByText('Отметьте хотя бы что-нибудь')).toBeInTheDocument()
    expect(writes(calls)).toEqual([])

    await userEvent.click(within(sheet).getByRole('checkbox', { name: 'Лампа' }))
    await userEvent.click(within(sheet).getByRole('radio', { name: 'Неделя' }))
    expect(within(sheet).getByText('Доступ закончится 2 декабря в 23:59.')).toBeInTheDocument()
    await userEvent.click(within(sheet).getByRole('button', { name: 'Создать приглашение' }))
    await screen.findByText('Отправьте ссылку: Карл откроет её на телефоне. Или покажите QR-код.')
    expect(writes(calls)).toEqual([
      { method: 'POST', url: '/api/account/invites', body: { name: 'Карл', permissions: ['res-a'], access_until: endOf(2026, 11, 2) } },
    ])
  })

  it('with a catalog: "forever" and everything send "all" and no end; a last day ends that day', async () => {
    const calls = serve(fetchMock, superMe, accountWith([]), () => json(200, { id: 'i_1', url: 'https://home.example.com/join#t=x', expires_at: '2026-11-26T10:30:00Z' }))
    renderApp(true)

    let sheet = await openInvite()
    await userEvent.type(within(sheet).getByLabelText('Как зовут?'), 'Карл')
    await userEvent.click(within(sheet).getByRole('button', { name: 'Создать приглашение' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Готово' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Пригласить' })).toBeNull())

    sheet = await openInvite()
    await userEvent.type(within(sheet).getByLabelText('Как зовут?'), 'Борис')
    await userEvent.click(within(sheet).getByRole('radio', { name: 'До даты…' }))
    const day = within(sheet).getByLabelText('Последний день')
    expect(day).toHaveAttribute('min', '2026-11-25')
    expect(day).toHaveAttribute('max', '2027-11-24')
    await userEvent.clear(day)
    await userEvent.type(day, '2026-12-31')
    await userEvent.click(within(sheet).getByRole('button', { name: 'Создать приглашение' }))
    await screen.findByText('Отправьте ссылку: Борис откроет её на телефоне. Или покажите QR-код.')
    expect(writes(calls).map((c) => c.body)).toEqual([
      { name: 'Карл', permissions: ['all'] },
      { name: 'Борис', permissions: ['all'], access_until: endOf(2026, 11, 31) },
    ])
  })

  it('with coOwners: the superadmin may invite a co-owner, who gets no pickers', async () => {
    configure({ brand: TEST_BRAND, coOwners: true })
    const calls = serve(fetchMock, superMe, accountWith([]), () => json(200, { id: 'i_1', url: 'https://home.example.com/join#t=x', expires_at: '2026-11-26T10:30:00Z' }))
    renderApp(true)

    const sheet = await openInvite()
    await userEvent.type(within(sheet).getByLabelText('Как зовут?'), 'Борис')
    expect(within(sheet).getByRole('radio', { name: 'Участник' })).toHaveAttribute('aria-checked', 'true')
    await userEvent.click(within(sheet).getByRole('radio', { name: 'Совладелец' }))
    expect(within(sheet).queryByRole('radiogroup', { name: 'Что доступно' })).toBeNull()
    expect(within(sheet).queryByRole('radiogroup', { name: 'Срок' })).toBeNull()
    await userEvent.click(within(sheet).getByRole('button', { name: 'Создать приглашение' }))
    await screen.findByText('Отправьте ссылку: Борис откроет её на телефоне. Или покажите QR-код.')
    expect(writes(calls).map((c) => c.body)).toEqual([{ name: 'Борис', role: 'owner' }])
  })

  it('with coOwners: an owner who is not the superadmin is offered no co-owner', async () => {
    configure({ brand: TEST_BRAND, coOwners: true })
    serve(fetchMock, { ...superMe, person: { ...superMe.person, superadmin: false } }, accountWith([]), () => json(500, { error: 'internal' }))
    renderApp(true)

    const sheet = await openInvite()
    expect(within(sheet).queryByRole('radiogroup', { name: 'Роль' })).toBeNull()
    expect(within(sheet).getByRole('radiogroup', { name: 'Что доступно' })).toBeInTheDocument()
  })

  it('greys an expired person; «Продлить» is a widening PATCH retried after step-up', async () => {
    const expired = { id: 'p_2', name: 'Борис', role: 'member' as const, joined_at: '2026-11-02T10:00:00Z', you: false, access_until: endOf(2026, 10, 20), permissions: ['res-a'], active: false }
    const calls = serve(fetchMock, superMe, accountWith([expired]), (c, n) =>
      c.method === 'PATCH' && n === 1 ? json(403, { error: 'step_up_required', message: 'fresh passkey needed' }) : json(200, {}),
    )
    renderApp(true)

    const row = await screen.findByRole('button', { name: /^Борис/ })
    expect(row).toHaveTextContent('доступ закончился 20 ноября')
    expect(within(row).getByText('Борис')).toHaveClass('text-label-2')
    await userEvent.click(screen.getByRole('button', { name: 'Продлить доступ: Борис' }))

    const sheet = await screen.findByRole('dialog', { name: 'Борис' })
    expect(await within(sheet).findByRole('radio', { name: 'Неделя' })).toHaveAttribute('aria-checked', 'true')
    await userEvent.click(within(sheet).getByRole('button', { name: 'Продлить' }))

    // The server wants a fresh passkey: the step-up sheet asks, then the same PATCH goes again.
    expect(await screen.findByText('Чтобы изменить доступ для Борис, нужен Face ID или Touch ID.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Подтвердить' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Борис' })).toBeNull())

    const patch = { method: 'PATCH', url: '/api/account/members/p_2', body: { access_until: endOf(2026, 11, 2) } }
    expect(writes(calls)).toEqual([patch, patch])
    expect(calls.filter((c) => c.url.startsWith('/api/auth/stepup')).map((c) => c.url)).toEqual(['/api/auth/stepup/begin', '/api/auth/stepup/finish'])
  })

  it('the member detail shows access, term and connections, and ends the access now', async () => {
    const guest = { id: 'p_2', name: 'Борис', role: 'member' as const, joined_at: '2026-11-02T10:00:00Z', you: false, access_until: endOf(2026, 11, 3), permissions: ['res-a', 'res-b'], active: true }
    const calls = serve(fetchMock, superMe, accountWith([guest]), () => json(200, {}))
    renderApp(true)

    const row = await screen.findByRole('button', { name: /^Борис/ })
    expect(row).toHaveTextContent('Член семьи · до 3 декабря')
    expect(screen.getByText('Нажмите на человека, чтобы изменить доступ или удалить его, на приглашение — чтобы отозвать.')).toBeInTheDocument()
    await userEvent.click(row)

    const sheet = await screen.findByRole('dialog', { name: 'Борис' })
    expect(within(sheet).getByText('Лампа, Чайник')).toBeInTheDocument()
    expect(within(sheet).getByText('До 3 декабря')).toBeInTheDocument()
    // Only this person's connections, each with its own button.
    expect(await within(sheet).findByRole('button', { name: 'Отключить Claude (Борис)' })).toBeInTheDocument()
    expect(within(sheet).queryByRole('button', { name: /ChatGPT/ })).toBeNull()

    await userEvent.click(within(sheet).getByRole('button', { name: 'Закрыть доступ сейчас' }))
    const confirm = await screen.findByRole('alertdialog', { name: 'Закрыть доступ для Борис?' })
    await userEvent.click(within(confirm).getByRole('button', { name: 'Закрыть доступ сейчас' }))
    await waitFor(() => expect(writes(calls)).toEqual([{ method: 'PATCH', url: '/api/account/members/p_2', body: { access_until: NOW.toISOString() } }]))
  })

  it('the member detail changes the permissions only, when only they were touched', async () => {
    const guest = { id: 'p_2', name: 'Борис', role: 'member' as const, joined_at: '2026-11-02T10:00:00Z', you: false, access_until: null, permissions: ['res-a'], active: true }
    const calls = serve(fetchMock, superMe, accountWith([guest]), () => json(200, {}))
    renderApp(true)

    await userEvent.click(await screen.findByRole('button', { name: /^Борис/ }))
    const sheet = await screen.findByRole('dialog', { name: 'Борис' })
    await userEvent.click(within(sheet).getByRole('button', { name: 'Изменить доступ' }))
    expect(await within(sheet).findByRole('radio', { name: 'Навсегда' })).toHaveAttribute('aria-checked', 'true')
    expect(within(sheet).getByRole('button', { name: 'Сохранить' })).toBeDisabled()
    await userEvent.click(within(sheet).getByRole('checkbox', { name: 'Чайник' }))
    await userEvent.click(within(sheet).getByRole('button', { name: 'Сохранить' }))
    await waitFor(() => expect(writes(calls)).toEqual([{ method: 'PATCH', url: '/api/account/members/p_2', body: { permissions: ['res-a', 'res-b'] } }]))
  })

  it('with coOwners: another owner is not the co-owner’s to change', async () => {
    configure({ brand: TEST_BRAND, coOwners: true })
    const coOwner: Me = { person: { id: 'p_2', name: 'Борис', role: 'owner', superadmin: false }, account: { id: 'a_1', name: 'Дом' } }
    const account = accountWith([])
    account.members = (account.members ?? []).map((m) => ({ ...m, you: false }))
    account.members.push({ id: 'p_2', name: 'Борис', role: 'owner', joined_at: '2026-11-02T10:00:00Z', you: true, access_until: null, permissions: ['all'], active: true })
    serve(fetchMock, coOwner, account, () => json(403, { error: 'forbidden' }))
    renderApp(true)

    await userEvent.click(await screen.findByRole('button', { name: /^Алиса/ }))
    const sheet = await screen.findByRole('dialog', { name: 'Алиса' })
    expect(within(sheet).getByText('Владельцу доступно всё и без срока.')).toBeInTheDocument()
    expect(within(sheet).queryByRole('button', { name: 'Изменить доступ' })).toBeNull()
    expect(within(sheet).queryByRole('button', { name: 'Удалить из семьи' })).toBeNull()
  })
})

describe('configure and options', () => {
  const fetchMock = vi.fn<typeof fetch>()
  beforeEach(() => {
    fetchMock.mockReset()
    fetchMock.mockImplementation(async () => json(200, []))
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    configure({ brand: TEST_BRAND })
  })

  const withQuery = (ui: React.ReactNode) => render(<QueryClientProvider client={new QueryClient()}>{ui}</QueryClientProvider>)

  it('singleAccount hides the families section and asks for nothing', () => {
    configure({ brand: TEST_BRAND, singleAccount: true })
    const { container } = withQuery(<FamiliesSection />)
    expect(container).toBeEmptyDOMElement()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('without singleAccount the families section is there', async () => {
    withQuery(<FamiliesSection />)
    expect(await screen.findByRole('heading', { name: 'Семьи' })).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledWith('/api/admin/accounts', expect.anything())
  })

  it('live defaults to sse and follows the prop', () => {
    function Mode() {
      return <output>{useLiveMode()}</output>
    }
    const { rerender } = render(
      <AppProvider>
        <Mode />
      </AppProvider>,
    )
    expect(screen.getByRole('status')).toHaveTextContent('sse')
    rerender(
      <AppProvider live="poll">
        <Mode />
      </AppProvider>,
    )
    expect(screen.getByRole('status')).toHaveTextContent('poll')
  })
})
