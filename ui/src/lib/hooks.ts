import { useEffect, useState, useSyncExternalStore } from 'react'

/** useMediaQuery follows a CSS media query. */
export function useMediaQuery(query: string) {
  return useSyncExternalStore(
    (onChange) => {
      const m = window.matchMedia(query)
      m.addEventListener('change', onChange)
      return () => m.removeEventListener('change', onChange)
    },
    () => window.matchMedia(query).matches,
    () => false,
  )
}

/** useIsPhone is true below 768 px: bottom drawers instead of dialogs (DESIGN.md §5.1). */
export function useIsPhone() {
  return !useMediaQuery('(min-width: 768px)')
}

/** useIsDesktop is true from 1024 px: the sidebar shell (DESIGN.md §5.1). */
export function useIsDesktop() {
  return useMediaQuery('(min-width: 1024px)')
}

/** useNow re-renders every interval and returns the current time, for relative times and timers. */
export function useNow(intervalMs = 30_000) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs)
    return () => clearInterval(id)
  }, [intervalMs])
  return now
}

/** useDelayed turns true only after `ms` of `on`, so skeletons never flicker for fast answers (DESIGN.md §7). */
export function useDelayed(on: boolean, ms = 150) {
  const [shown, setShown] = useState(false)
  useEffect(() => {
    if (!on) return
    const id = setTimeout(() => setShown(true), ms)
    return () => {
      clearTimeout(id)
      setShown(false)
    }
  }, [on, ms])
  return on && shown
}

/** useSticky keeps the last defined value, so a closing sheet still shows its content while it animates out. */
export function useSticky<T>(value: T | undefined | null): T | undefined {
  const [last, setLast] = useState<T | undefined>(value ?? undefined)
  if (value !== undefined && value !== null && value !== last) setLast(value)
  return value ?? last
}
