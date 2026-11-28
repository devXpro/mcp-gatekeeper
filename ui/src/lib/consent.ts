// The consent page's reading of the hub's refusals (docs/PLAN.md §5.5, docs/reviews/T2.R.md H1).

import { isApiError } from './api'
import type { ConsentTxn } from './types'

/**
 * isForeignTxn tells a transaction started in another browser from a service that is off. The hub binds a
 * transaction to the browser that opened `/oauth/authorize` with a cookie and refuses any other browser with
 * 403 `other_browser` (T2.F1); a service that is off stays 403 `forbidden`.
 */
export function isForeignTxn(err: unknown): boolean {
  return isApiError(err, 'other_browser')
}

/**
 * returnable keeps the answer's redirect a plain https URL or, for a native app, its loopback callback on this
 * computer or its own private-use scheme callback `<scheme>:/oauth/callback` (RFC 8252): the window is never sent to
 * anything else.
 */
export function returnable(url: string, app: ConsentTxn['app']) {
  try {
    const u = new URL(url)
    if (u.protocol === 'https:') return true
    if (!app) return false
    if (u.protocol === 'http:') return u.hostname === '127.0.0.1' || u.hostname === '[::1]'
    return !!app.scheme && u.protocol === `${app.scheme}:` && u.host === '' && u.pathname === '/oauth/callback' && !url.startsWith(`${app.scheme}://`)
  } catch {
    return false
  }
}
