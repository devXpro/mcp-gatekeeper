import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'
import i18n from '../i18n'
import { configure } from '../setup'
import { TEST_BRAND } from './brand'

// jsdom has no matchMedia; tests run in the desktop layout (native selects, dialogs instead of drawers).
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: query.includes('min-width'),
    media: query,
    onchange: null,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    addListener: () => undefined,
    removeListener: () => undefined,
    dispatchEvent: () => false,
  }),
})

configure({ brand: TEST_BRAND })

// jsdom's browser speaks English; the copy under test is the Russian one (the default for the family).
void i18n.changeLanguage('ru')

afterEach(() => cleanup())

// jsdom does not scroll.
window.scrollTo = () => undefined
