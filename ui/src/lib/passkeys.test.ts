import { WebAuthnError } from '@simplewebauthn/browser'
import { describe, expect, it } from 'vitest'
import { ceremonyError, publicKeyOf } from './passkeys'

describe('publicKeyOf', () => {
  it('takes the publicKey part of a whole CredentialCreation, or the options as they are', () => {
    const inner = { challenge: 'abc', rpId: 'hub.example' }
    expect(publicKeyOf({ publicKey: inner })).toBe(inner)
    expect(publicKeyOf(inner)).toBe(inner)
  })
})

describe('ceremonyError', () => {
  it('tells a cancel from a passkey that exists and from a failure', () => {
    expect(ceremonyError(new DOMException('x', 'NotAllowedError'))).toBe('cancelled')
    expect(ceremonyError(new DOMException('x', 'AbortError'))).toBe('cancelled')
    expect(ceremonyError(new DOMException('x', 'InvalidStateError'))).toBe('exists')
    expect(ceremonyError(new WebAuthnError({ message: 'x', code: 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED', cause: new Error('x') }))).toBe('exists')
    expect(ceremonyError(new Error('boom'))).toBe('failed')
    expect(ceremonyError('weird')).toBe('failed')
  })
})
