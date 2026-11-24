import i18n from 'i18next'
import { useSyncExternalStore } from 'react'
import { initReactI18next } from 'react-i18next'
import { storageKey } from '../config'
import type { Lang } from '../lib/types'
import en from './en.json'
import ru from './ru.json'

// The language is the person's choice in this browser (localStorage "<prefix>.lang"); without one, Russian for
// anyone whose browser speaks Russian, Ukrainian or Belarusian, English otherwise. The application's pre-paint script
// (Family Hub: public/theme.js) applies the same rule to <html lang> before the first paint.

/** Strings are flat key → text maps per language; an application's strings extend and override the package's. */
export type Strings = Partial<Record<Lang, Record<string, string>>>

/** The package's own strings, for an application that checks its merged copy (e.g. RU and EN have the same keys). */
export const packageStrings: Record<Lang, Record<string, string>> = { ru, en }

export function detectLang(saved: string | null, languages: readonly string[]): Lang {
  if (saved === 'ru' || saved === 'en') return saved
  return languages.some((l) => /^(ru|uk|be)\b/i.test(l)) ? 'ru' : 'en'
}

function initialLang(): Lang {
  let saved: string | null = null
  try {
    saved = localStorage.getItem(storageKey('lang'))
  } catch {
    // storage blocked: detect
  }
  const nav = typeof navigator === 'undefined' ? ['ru'] : navigator.languages?.length ? navigator.languages : [navigator.language]
  return detectLang(saved, nav)
}

/** initI18n starts i18next with the package's strings and the application's on top (configure() calls it). */
export function initI18n(extra: Strings = {}) {
  const bundles = { ru: { ...ru, ...extra.ru }, en: { ...en, ...extra.en } }
  if (i18n.isInitialized) {
    // configure() ran before (tests, hot reload): replace the strings, keep the language.
    for (const lang of ['ru', 'en'] as const) i18n.addResourceBundle(lang, 'translation', bundles[lang], true, true)
    return
  }
  // Keys are flat ("connect.chatgpt" and "connect.chatgpt.hint" both exist), so the key separator is off.
  void i18n.use(initReactI18next).init({
    resources: { ru: { translation: bundles.ru }, en: { translation: bundles.en } },
    lng: initialLang(),
    fallbackLng: 'ru',
    supportedLngs: ['ru', 'en'],
    keySeparator: false,
    nsSeparator: false,
    interpolation: { escapeValue: false },
    returnNull: false,
    initAsync: false,
  })
}

export function currentLang(): Lang {
  return i18n.language === 'en' ? 'en' : 'ru'
}

/** useLang re-renders on a language switch. */
export function useLang(): Lang {
  return useSyncExternalStore(
    (l) => {
      i18n.on('languageChanged', l)
      return () => i18n.off('languageChanged', l)
    },
    currentLang,
    currentLang,
  )
}

/** setLanguage switches the UI at once, without a reload (DESIGN.md §11), keeps <html lang> in step and remembers it. */
export function setLanguage(lang: Lang) {
  try {
    localStorage.setItem(storageKey('lang'), lang)
  } catch {
    // storage blocked: the choice lasts for this page only
  }
  if (i18n.language !== lang) void i18n.changeLanguage(lang)
  document.documentElement.lang = lang
}

/** label picks the text of a label map ({"ru": …, "en": …}) in the UI language; a string is used as is. */
export function label(v: string | Record<string, string> | undefined, lang: Lang): string {
  if (!v) return ''
  if (typeof v === 'string') return v
  return v[lang] ?? v.en ?? v.ru ?? Object.values(v)[0] ?? ''
}

export default i18n
