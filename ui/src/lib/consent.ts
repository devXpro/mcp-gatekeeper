// The consent page's reading of the hub's refusals (docs/PLAN.md §5.5, docs/reviews/T2.R.md H1).

import { isApiError } from './api'

/**
 * isForeignTxn tells a transaction started in another browser from a service that is off. The hub binds a
 * transaction to the browser that opened `/oauth/authorize` with a cookie and refuses any other browser with
 * 403 `other_browser` (T2.F1); a service that is off stays 403 `forbidden`.
 */
export function isForeignTxn(err: unknown): boolean {
  return isApiError(err, 'other_browser')
}
