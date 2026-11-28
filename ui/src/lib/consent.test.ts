import { describe, expect, it } from 'vitest'
import { ApiError } from './api'
import { isForeignTxn, returnable } from './consent'

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

describe('returnable', () => {
  const desk = { id: 'desk', name: 'Desk' }
  const phone = { ...desk, scheme: 'com.example.desk' }
  const answer = '?code=c&state=s&iss=https%3A%2F%2Fhub.example'

  it('keeps https for everyone', () => {
    expect(returnable('https://claude.ai/api/mcp/auth_callback' + answer, undefined)).toBe(true)
    expect(returnable('https://claude.ai/api/mcp/auth_callback' + answer, phone)).toBe(true)
  })

  it('lets a native app return to its loopback callback only', () => {
    expect(returnable('http://127.0.0.1:8742/oauth/callback' + answer, desk)).toBe(true)
    expect(returnable('http://[::1]:8742/oauth/callback' + answer, desk)).toBe(true)
    expect(returnable('http://127.0.0.1:8742/oauth/callback' + answer, undefined)).toBe(false)
    expect(returnable('http://evil.example/oauth/callback' + answer, desk)).toBe(false)
  })

  it("lets a native app with a scheme return to that scheme's callback only", () => {
    expect(returnable('com.example.desk:/oauth/callback' + answer, phone)).toBe(true)
    expect(returnable('com.example.desk:/oauth/callback' + answer, desk)).toBe(false)
    expect(returnable('com.example.desk:/oauth/callback' + answer, undefined)).toBe(false)
    expect(returnable('org.example.other:/oauth/callback' + answer, phone)).toBe(false)
    expect(returnable('com.example.desk://oauth/callback' + answer, phone)).toBe(false)
    expect(returnable('com.example.desk://evil/oauth/callback' + answer, phone)).toBe(false)
    expect(returnable('com.example.desk:/other' + answer, phone)).toBe(false)
    expect(returnable('javascript:alert(1)', phone)).toBe(false)
    expect(returnable('javascript:alert(1)', { ...desk, scheme: 'javascript' })).toBe(false)
    expect(returnable('not a url', phone)).toBe(false)
  })
})
