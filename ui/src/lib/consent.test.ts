import { describe, expect, it } from 'vitest'
import { ApiError } from './api'
import { isForeignTxn } from './consent'

describe('isForeignTxn', () => {
  it('reads the browser-binding refusal of T2.F1 by its code', () => {
    expect(isForeignTxn(new ApiError(403, 'other_browser', 'this connection was started in another browser; start connecting from the assistant again'))).toBe(true)
    expect(isForeignTxn(new ApiError(403, 'other_browser', ''))).toBe(true)
  })

  it('keeps the other 403s apart: the service is off, the CSRF check, step-up', () => {
    expect(isForeignTxn(new ApiError(403, 'forbidden', 'the module is not on for your account'))).toBe(false)
    expect(isForeignTxn(new ApiError(403, 'forbidden', 'start connecting from the assistant again'))).toBe(false)
    expect(isForeignTxn(new ApiError(403, 'step_up_required', 'approving a new connection needs a fresh passkey'))).toBe(false)
    expect(isForeignTxn(new Error('other_browser'))).toBe(false)
  })
})
