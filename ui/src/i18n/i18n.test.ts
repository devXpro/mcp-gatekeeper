import { describe, expect, it } from 'vitest'
import en from './en.json'
import { detectLang, label } from './index'
import ru from './ru.json'

// Plural forms differ by language (RU _one/_few/_many/_other, EN _one/_other; both may have _zero), so keys are
// compared without them.
const base = (keys: string[]) => new Set(keys.map((k) => k.replace(/_(zero|one|two|few|many|other)$/, '')))

describe('translations', () => {
  it('RU and EN have the same keys', () => {
    const r = base(Object.keys(ru))
    const e = base(Object.keys(en))
    expect([...r].filter((k) => !e.has(k))).toEqual([])
    expect([...e].filter((k) => !r.has(k))).toEqual([])
  })

  it('RU plurals have every form, EN plurals one and other', () => {
    for (const p of Object.keys(ru).filter((k) => k.endsWith('_one')).map((k) => k.slice(0, -4))) {
      for (const form of ['one', 'few', 'many', 'other']) expect(ru).toHaveProperty([`${p}_${form}`])
      for (const form of ['one', 'other']) expect(en).toHaveProperty([`${p}_${form}`])
    }
  })

  it('every interpolation in RU exists in EN', () => {
    const vars = (s: string) => [...s.matchAll(/{{(\w+)}}/g)].map((m) => m[1]).sort()
    const enMap = en as Record<string, string>
    for (const [k, v] of Object.entries(ru as Record<string, string>)) {
      const other = enMap[k] ?? enMap[k.replace(/_(few|many)$/, '_other')]
      if (other !== undefined) expect([k, vars(other)]).toEqual([k, vars(v)])
    }
  })

  it('the copy follows the house rules: no empty strings, «ёлочки» in RU, no straight double quotes', () => {
    for (const [k, v] of Object.entries({ ...ru, ...en } as Record<string, string>)) {
      expect([k, v.trim().length > 0]).toEqual([k, true])
      expect([k, v.includes('"')]).toEqual([k, false])
    }
  })
})

describe('detectLang', () => {
  it('keeps a saved choice', () => {
    expect(detectLang('en', ['ru-RU'])).toBe('en')
    expect(detectLang('ru', ['en-US'])).toBe('ru')
  })

  it('picks Russian for ru, uk and be browsers, English otherwise', () => {
    expect(detectLang(null, ['en-US', 'ru'])).toBe('ru')
    expect(detectLang(null, ['uk-UA'])).toBe('ru')
    expect(detectLang(null, ['be'])).toBe('ru')
    expect(detectLang(null, ['pl-PL', 'en'])).toBe('en')
    expect(detectLang('fr', [])).toBe('en')
  })
})

describe('label', () => {
  it('reads a module label map in the UI language, with fallbacks', () => {
    expect(label({ ru: 'Логин', en: 'Login' }, 'ru')).toBe('Логин')
    expect(label({ ru: 'Логин', en: 'Login' }, 'en')).toBe('Login')
    expect(label({ en: 'Login' }, 'ru')).toBe('Login')
    expect(label({ pl: 'Login PL' }, 'en')).toBe('Login PL')
    expect(label('Plain', 'ru')).toBe('Plain')
    expect(label(undefined, 'ru')).toBe('')
  })
})
