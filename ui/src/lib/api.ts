import { brand } from '../config'

// The gatekeeper's JSON API client (Family Hub docs/PLAN.md §5.2): JSON both ways, the brand's CSRF header on every
// write, errors `{"error":"<code>","message":"…"}` as ApiError, and "the hub is unreachable" (a network error, or a
// proxy's non-JSON 5xx page) as OfflineError.

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  /** the module that failed, on 502 upstream from "delete everything" */
  readonly module?: string
  /** why a 502 upstream failed, e.g. "not_deployed": the module is not installed but may hold the family's data */
  readonly reason?: string
  readonly retryAfter?: number

  constructor(status: number, code: string, message: string, extra: { module?: string; reason?: string; retryAfter?: number } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.module = extra.module
    this.reason = extra.reason
    this.retryAfter = extra.retryAfter
  }
}

export class OfflineError extends Error {
  constructor() {
    super('the hub is unreachable')
    this.name = 'OfflineError'
  }
}

export function isApiError(err: unknown, code?: string): err is ApiError {
  return err instanceof ApiError && (code === undefined || err.code === code)
}

export function isOffline(err: unknown): err is OfflineError {
  return err instanceof OfflineError
}

type Listener = () => void

/** Connectivity tracks whether the hub answers, and retries with backoff while it does not (DESIGN.md §8.10). */
class Connectivity {
  private offline = false
  private attempt = 0
  private timer: ReturnType<typeof setTimeout> | undefined
  private readonly listeners = new Set<Listener>()
  private readonly backListeners = new Set<Listener>()
  probeUrl = '/api/me'

  subscribe = (listener: Listener) => {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  getSnapshot = () => this.offline

  /** onBack runs every time the hub answers again after being unreachable. */
  onBack(listener: Listener) {
    this.backListeners.add(listener)
    return () => {
      this.backListeners.delete(listener)
    }
  }

  reportOffline() {
    if (this.offline) return
    this.offline = true
    this.attempt = 0
    this.emit()
    this.schedule()
  }

  reportOnline() {
    if (!this.offline) return
    this.offline = false
    clearTimeout(this.timer)
    this.emit()
    for (const l of this.backListeners) l()
  }

  /** retryNow probes at once: the Retry button, `online` and `visibilitychange`. */
  retryNow = () => {
    if (!this.offline) return
    clearTimeout(this.timer)
    void this.probe()
  }

  private schedule() {
    const delays = [2000, 5000, 10000]
    const delay = delays[this.attempt] ?? 30000
    this.attempt++
    clearTimeout(this.timer)
    this.timer = setTimeout(() => void this.probe(), delay)
  }

  private async probe() {
    try {
      const res = await fetch(this.probeUrl, { cache: 'no-store', credentials: 'same-origin' })
      if ((res.headers.get('content-type') ?? '').includes('application/json')) {
        this.reportOnline()
        return
      }
    } catch {
      // still unreachable
    }
    if (this.offline) this.schedule()
  }

  private emit() {
    for (const l of this.listeners) l()
  }
}

export const connectivity = new Connectivity()

if (typeof window !== 'undefined') {
  window.addEventListener('online', connectivity.retryNow)
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') connectivity.retryNow()
  })
}

const noSessionListeners = new Set<Listener>()

/** onNoSession runs when any request answers 401 no_session (the signed-in shell sends the person to sign in). */
export function onNoSession(listener: Listener) {
  noSessionListeners.add(listener)
  return () => {
    noSessionListeners.delete(listener)
  }
}

export type Method = 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE'

export interface RequestOptions {
  query?: Record<string, string | number | boolean | undefined>
  signal?: AbortSignal
}

/** A proxy in front of a stopped hub (cloudflared, Caddy) answers these with its own HTML page. */
const UNREACHABLE = new Set([502, 503, 504, 520, 521, 522, 523, 524, 530])

export async function request<T>(method: Method, path: string, body?: unknown, opts: RequestOptions = {}): Promise<T> {
  let url = '/api' + path
  if (opts.query) {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined && v !== '') q.set(k, String(v))
    }
    const s = q.toString()
    if (s) url += (url.includes('?') ? '&' : '?') + s
  }
  const headers: Record<string, string> = { Accept: 'application/json' }
  let payload: string | undefined
  if (method !== 'GET') {
    // The CSRF header (core.Brand.CSRFHeader); the browser adds Origin and Sec-Fetch-Site by itself.
    headers[brand().csrfHeader] = '1'
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json'
      payload = JSON.stringify(body)
    }
  }

  let res: Response
  try {
    res = await fetch(url, {
      method,
      headers,
      body: payload,
      credentials: 'same-origin',
      cache: 'no-store',
      signal: opts.signal,
    })
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err
    connectivity.reportOffline()
    throw new OfflineError()
  }

  const json = (res.headers.get('content-type') ?? '').includes('application/json')
  if (res.ok) {
    connectivity.reportOnline()
    if (res.status === 204 || !json) return undefined as T
    return (await res.json()) as T
  }
  if (!json) {
    if (UNREACHABLE.has(res.status)) {
      connectivity.reportOffline()
      throw new OfflineError()
    }
    throw new ApiError(res.status, res.status === 404 ? 'not_found' : 'generic', res.statusText)
  }
  connectivity.reportOnline()
  const data = (await res.json().catch(() => null)) as { error?: unknown; message?: unknown; module?: unknown; reason?: unknown } | null
  const code = typeof data?.error === 'string' && data.error ? data.error : 'generic'
  const retry = Number(res.headers.get('Retry-After'))
  const err = new ApiError(res.status, code, typeof data?.message === 'string' ? data.message : res.statusText, {
    module: typeof data?.module === 'string' ? data.module : undefined,
    reason: typeof data?.reason === 'string' ? data.reason : undefined,
    retryAfter: Number.isFinite(retry) && retry > 0 ? retry : undefined,
  })
  if (err.code === 'no_session') {
    for (const l of noSessionListeners) l()
  }
  throw err
}

export const api = {
  get: <T>(path: string, opts?: RequestOptions) => request<T>('GET', path, undefined, opts),
  post: <T>(path: string, body: unknown = {}, opts?: RequestOptions) => request<T>('POST', path, body, opts),
  patch: <T>(path: string, body: unknown, opts?: RequestOptions) => request<T>('PATCH', path, body, opts),
  put: <T>(path: string, body: unknown, opts?: RequestOptions) => request<T>('PUT', path, body, opts),
  del: <T>(path: string, body?: unknown, opts?: RequestOptions) => request<T>('DELETE', path, body, opts),
}

/** seg encodes one path segment (an id from the API or a URL). */
export const seg = (s: string) => encodeURIComponent(s)
