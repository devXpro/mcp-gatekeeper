import { describe, expect, it } from 'vitest'
import { safeNext } from './links'

describe('safeNext', () => {
  it('keeps paths inside the SPA', () => {
    expect(safeNext('/consent?txn=txn_1')).toBe('/consent?txn=txn_1')
    expect(safeNext('/admin/modules/notes')).toBe('/admin/modules/notes')
  })

  it('refuses anything that could leave the hub, and the login page itself', () => {
    for (const v of [null, '', 'https://evil.example', '//evil.example', '/\\evil.example', 'javascript:alert(1)', '/login', '/login?next=/x']) {
      expect(safeNext(v)).toBe('/')
    }
  })
})
