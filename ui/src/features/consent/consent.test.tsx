import { render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { GatekeeperApp } from '../../app/GatekeeperApp'
import type { ConsentTxn, Me } from '../../lib/types'

// The consent screen of a native app (review SR M1): the loopback address the answer goes to is said next to Allow,
// and the red warning stays for every request that was not opened by the app itself (started_from other than "app").

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

const me: Me = { person: { id: 'p_1', name: 'Алиса', role: 'owner', superadmin: false }, account: { id: 'a_1', name: 'Наша семья' } }

const nativeTxn = (startedFrom: ConsentTxn['started_from']): ConsentTxn => ({
  assistant: 'app:desk',
  client_name: 'Work laptop',
  client_kind: 'dcr',
  redirect_host: '127.0.0.1:8742',
  started_from: startedFrom,
  resource: { id: 'notes', name: 'Дневник', description: '', tools: [{ name: 'grades', title: 'Оценки', access: 'read' }] },
  account: { id: 'a_1', name: 'Наша семья' },
  already_granted: false,
  app: { id: 'desk', name: 'Desk' },
})

const RETURN = 'Ответ уйдёт на 127.0.0.1:8742 на этом компьютере'

describe('the consent screen of a native app', () => {
  const fetchMock = vi.fn<typeof fetch>()
  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    window.history.replaceState(null, '', '/consent?txn=txn_1')
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    window.history.replaceState(null, '', '/')
  })

  function serve(txn: ConsentTxn) {
    fetchMock.mockImplementation(async (url) => {
      const u = String(url)
      if (u === '/api/me') return json(200, me)
      if (u === '/api/oauth/txn/txn_1') return json(200, txn)
      return json(404, { error: 'not_found' })
    })
    render(<GatekeeperApp resources={() => [{ id: 'notes', name: 'Дневник', mcp_url: 'https://hub.example/mcp/notes', enabled: true }]} />)
  }

  it('opened by the app: no warning, the return address next to Allow', async () => {
    serve(nativeTxn('app'))
    expect(await screen.findByRole('heading', { level: 1, name: 'Desk на вашем компьютере просит доступ к «Дневник»' })).toBeInTheDocument()
    expect(screen.getByText(RETURN)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Разрешить' })).toHaveAccessibleDescription(expect.stringContaining(RETURN))
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('opened from a page or a sent link: the red warning and the return address', async () => {
    serve(nativeTxn('elsewhere'))
    expect(await screen.findByRole('alert')).toHaveTextContent('Запрос открыт не из Desk на вашем компьютере')
    expect(screen.getByText(RETURN)).toBeInTheDocument()
  })

  it('an assistant: no loopback line', async () => {
    serve({ ...nativeTxn('assistant'), assistant: 'chatgpt', client_name: 'ChatGPT', client_kind: 'cimd', redirect_host: 'chatgpt.com', app: undefined })
    expect(await screen.findByRole('heading', { level: 1, name: 'ChatGPT просит доступ к «Дневник»' })).toBeInTheDocument()
    expect(screen.queryByText(/на этом компьютере/)).toBeNull()
  })
})
