import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { TEST_BRAND } from '../test/brand'
import { api, ApiError, connectivity, isApiError, isOffline, OfflineError, onNoSession } from './api'

function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })
}

describe('api', () => {
  const fetchMock = vi.fn<typeof fetch>()
  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    connectivity.reportOnline()
  })

  it("sends the brand's CSRF header and JSON on writes, and not on reads", async () => {
    fetchMock.mockResolvedValue(json(200, { ok: true }))
    await api.post('/account/invites', { name: 'Бабушка' })
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/account/invites')
    expect(init?.method).toBe('POST')
    expect((init?.headers as Record<string, string>)[TEST_BRAND.csrfHeader]).toBe('1')
    expect((init?.headers as Record<string, string>)['X-Family-Hub']).toBeUndefined()
    expect((init?.headers as Record<string, string>)['Content-Type']).toBe('application/json')
    expect(init?.body).toBe(JSON.stringify({ name: 'Бабушка' }))
    expect(init?.credentials).toBe('same-origin')

    fetchMock.mockResolvedValue(json(200, {}))
    await api.get('/account/audit', { query: { before: 'abc', limit: 50, empty: '' } })
    const [getUrl, getInit] = fetchMock.mock.calls[1]
    expect(getUrl).toBe('/api/account/audit?before=abc&limit=50')
    expect((getInit?.headers as Record<string, string>)[TEST_BRAND.csrfHeader]).toBeUndefined()
  })

  it('DELETE carries a JSON body when given one (the typed confirmation)', async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }))
    await expect(api.del('/account', { confirm: 'Наша семья' })).resolves.toBeUndefined()
    expect(fetchMock.mock.calls[0][1]?.body).toBe(JSON.stringify({ confirm: 'Наша семья' }))
  })

  it.each([
    [401, { error: 'no_session', message: 'no session' }, 'no_session'],
    [403, { error: 'step_up_required', message: 'x' }, 'step_up_required'],
    [403, { error: 'forbidden' }, 'forbidden'],
    [404, { error: 'not_found' }, 'not_found'],
    [409, { error: 'conflict' }, 'conflict'],
    [400, { error: 'invalid' }, 'invalid'],
    [500, { error: 'internal' }, 'internal'],
    [418, { message: 'no code' }, 'generic'],
  ])('maps %i %j to the code %s', async (status, body, code) => {
    fetchMock.mockResolvedValue(json(status, body))
    const err = await api.get('/me').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(isApiError(err, code)).toBe(true)
    expect((err as ApiError).status).toBe(status)
  })

  it('keeps the failing module of a 502 upstream and the Retry-After of a 429', async () => {
    fetchMock.mockResolvedValue(json(502, { error: 'upstream', module: 'notes' }))
    const upstream = (await api.del('/account', { confirm: 'x' }).catch((e: unknown) => e)) as ApiError
    expect(upstream.code).toBe('upstream')
    expect(upstream.module).toBe('notes')
    expect(upstream.reason).toBeUndefined()

    fetchMock.mockResolvedValue(json(502, { error: 'upstream', module: 'weather', reason: 'not_deployed' }))
    const kept = (await api.del('/account', { confirm: 'x' }).catch((e: unknown) => e)) as ApiError
    expect(kept.reason).toBe('not_deployed')

    fetchMock.mockResolvedValue(json(429, { error: 'rate_limited' }, { 'Retry-After': '42' }))
    const limited = (await api.post('/auth/login/begin').catch((e: unknown) => e)) as ApiError
    expect(limited.code).toBe('rate_limited')
    expect(limited.retryAfter).toBe(42)
  })

  it('treats a network error and a proxy page as an unreachable hub, and a plain 404 as not found', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    expect(isOffline(await api.get('/me').catch((e: unknown) => e))).toBe(true)
    expect(connectivity.getSnapshot()).toBe(true)
    connectivity.reportOnline()

    fetchMock.mockResolvedValue(new Response('<html>524</html>', { status: 524, headers: { 'Content-Type': 'text/html' } }))
    expect(await api.get('/me').catch((e: unknown) => e)).toBeInstanceOf(OfflineError)
    connectivity.reportOnline()

    fetchMock.mockResolvedValue(new Response('404 page not found', { status: 404, headers: { 'Content-Type': 'text/plain' } }))
    expect(isApiError(await api.get('/nowhere').catch((e: unknown) => e), 'not_found')).toBe(true)
  })

  it('tells the signed-in shell about no_session, and only about it', async () => {
    const seen = vi.fn()
    const off = onNoSession(seen)
    fetchMock.mockResolvedValue(json(400, { error: 'invalid' }))
    await api.post('/auth/login/finish', { credential: {} }).catch(() => undefined)
    expect(seen).not.toHaveBeenCalled()
    fetchMock.mockResolvedValue(json(401, { error: 'no_session' }))
    await api.get('/account').catch(() => undefined)
    expect(seen).toHaveBeenCalledTimes(1)
    off()
  })
})
