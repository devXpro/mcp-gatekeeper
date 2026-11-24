// Passkey ceremonies in the browser (docs/PLAN.md §5.9): a "begin" call answers {options}, the options go to
// @simplewebauthn/browser, and its JSON answer goes back unchanged as {credential}.

import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  WebAuthnError,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/browser'
import { storageKey } from '../config'
import { api } from './api'
import type { Begin } from './types'

/** What went wrong in a ceremony, in the words the screens use. */
export type CeremonyError = 'cancelled' | 'exists' | 'failed'

export function ceremonyError(err: unknown): CeremonyError {
  const name = err instanceof WebAuthnError || err instanceof DOMException || err instanceof Error ? err.name : ''
  if (err instanceof WebAuthnError) {
    if (err.code === 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED') return 'exists'
    if (err.code === 'ERROR_CEREMONY_ABORTED') return 'cancelled'
  }
  if (name === 'NotAllowedError' || name === 'AbortError') return 'cancelled'
  if (name === 'InvalidStateError') return 'exists'
  return 'failed'
}

/**
 * publicKeyOf accepts both shapes go-webauthn can send as `options`: the whole CredentialCreation/CredentialAssertion
 * ({publicKey: {...}}) or only its publicKey part.
 */
export function publicKeyOf<T>(options: unknown): T {
  if (options && typeof options === 'object' && 'publicKey' in options) {
    return (options as { publicKey: T }).publicKey
  }
  return options as T
}

// An application's mock API (Family Hub: npm run dev:mock) answers with options no real authenticator should keep a
// passkey for, so mock mode fakes the browser prompt unless localStorage "<prefix>.mock.webauthn" is "real" (the
// Playwright tests use Chrome's virtual authenticator with it). Production builds drop these branches: MODE is a
// build-time constant.
function fakeMode(): 'off' | 'ok' | 'cancel' {
  if (import.meta.env.MODE !== 'mock') return 'off'
  const v = localStorage.getItem(storageKey('mock.webauthn'))
  if (v === 'real') return 'off'
  return v === 'cancel' ? 'cancel' : 'ok'
}

async function fakePrompt<T>(value: T): Promise<T> {
  await new Promise((r) => setTimeout(r, 700))
  if (fakeMode() === 'cancel') throw new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError')
  return value
}

const b64 = (s: string) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

export function webauthnSupported() {
  if (import.meta.env.MODE === 'mock' && fakeMode() !== 'off') return true
  return browserSupportsWebAuthn()
}

export async function getAssertion(options: unknown): Promise<AuthenticationResponseJSON> {
  if (import.meta.env.MODE === 'mock' && fakeMode() !== 'off') {
    return fakePrompt({
      id: b64('mock-credential'),
      rawId: b64('mock-credential'),
      type: 'public-key',
      response: { clientDataJSON: b64('{}'), authenticatorData: b64('a'), signature: b64('s'), userHandle: b64('u') },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    })
  }
  return startAuthentication({ optionsJSON: publicKeyOf<PublicKeyCredentialRequestOptionsJSON>(options) })
}

export async function createCredential(options: unknown): Promise<RegistrationResponseJSON> {
  if (import.meta.env.MODE === 'mock' && fakeMode() !== 'off') {
    return fakePrompt({
      id: b64('mock-credential'),
      rawId: b64('mock-credential'),
      type: 'public-key',
      response: { clientDataJSON: b64('{}'), attestationObject: b64('o'), transports: ['internal', 'hybrid'] },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    })
  }
  return startRegistration({ optionsJSON: publicKeyOf<PublicKeyCredentialCreationOptionsJSON>(options) })
}

/** signIn runs the login ceremony: begin, the browser prompt, finish (which sets the session cookie). */
export async function signIn(): Promise<void> {
  const begin = await api.post<Begin>('/auth/login/begin', {})
  const credential = await getAssertion(begin.options)
  await api.post('/auth/login/finish', { credential })
}
