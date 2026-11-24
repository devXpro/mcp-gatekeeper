// Appearance (DESIGN.md §8.6): dark by default, light, or the system's. The application's pre-paint script (Family
// Hub: public/theme.js) applies the same rule before the first paint; this module keeps it applied while the app runs.

import { useSyncExternalStore } from 'react'
import { storageKey } from '../config'

export type ThemePref = 'dark' | 'light' | 'system'

const listeners = new Set<() => void>()
const media = typeof window !== 'undefined' && window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null

export function getThemePref(): ThemePref {
  try {
    const v = localStorage.getItem(storageKey('theme'))
    if (v === 'light' || v === 'system' || v === 'dark') return v
  } catch {
    // storage blocked (or no brand yet): fall back to the default
  }
  return 'dark'
}

function effective(pref: ThemePref): 'dark' | 'light' {
  if (pref === 'system') return media?.matches === false ? 'light' : 'dark'
  return pref
}

export function applyTheme(pref = getThemePref()) {
  const theme = effective(pref)
  document.documentElement.setAttribute('data-theme', theme)
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'dark' ? '#000000' : '#F2F2F7')
}

export function setThemePref(pref: ThemePref) {
  try {
    localStorage.setItem(storageKey('theme'), pref)
  } catch {
    // storage blocked: the choice lasts for this page only
  }
  applyTheme(pref)
  for (const l of listeners) l()
}

media?.addEventListener('change', () => {
  if (getThemePref() === 'system') applyTheme('system')
})

export function useThemePref(): ThemePref {
  return useSyncExternalStore(
    (l) => {
      listeners.add(l)
      return () => {
        listeners.delete(l)
      }
    },
    getThemePref,
    () => 'dark',
  )
}
