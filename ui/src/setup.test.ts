import { afterEach, describe, expect, it } from 'vitest'
import { brand, storageKey } from './config'
import i18n, { setLanguage } from './i18n'
import { getThemePref, setThemePref } from './lib/theme'
import { configure } from './setup'
import { TEST_BRAND } from './test/brand'

describe('configure', () => {
  afterEach(() => {
    configure({ brand: TEST_BRAND })
    void i18n.changeLanguage('ru')
    localStorage.clear()
  })

  it('keeps the settings under the brand prefix', () => {
    expect(brand().csrfHeader).toBe('X-Gatekeeper-Test')
    expect(storageKey('theme')).toBe('gk-test.theme')

    setThemePref('light')
    expect(localStorage.getItem('gk-test.theme')).toBe('light')
    expect(localStorage.getItem('fh.theme')).toBeNull()
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(getThemePref()).toBe('light')

    setLanguage('en')
    expect(localStorage.getItem('gk-test.lang')).toBe('en')
    expect(document.documentElement.lang).toBe('en')
  })

  it("lets an application add strings and override the package's", () => {
    configure({
      brand: { ...TEST_BRAND, storagePrefix: 'other' },
      strings: { ru: { 'app.name': 'Хоми', 'tab.plugins': 'Плагины' }, en: { 'app.name': 'Homie' } },
    })
    expect(storageKey('lang')).toBe('other.lang')
    expect(i18n.t('app.name', { lng: 'ru' })).toBe('Хоми')
    expect(i18n.t('app.name', { lng: 'en' })).toBe('Homie')
    expect(i18n.t('tab.plugins', { lng: 'ru' })).toBe('Плагины')
    // The package's own strings stay.
    expect(i18n.t('login.button', { lng: 'ru' })).toBe('Войти')
  })
})
