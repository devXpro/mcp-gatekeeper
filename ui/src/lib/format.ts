// Dates, times and quotes (DESIGN.md §11): Intl in the UI language, 24 h times in both languages.

import type { Lang } from './types'

const LOCALE: Record<Lang, string> = { ru: 'ru-RU', en: 'en-GB' }

export function fmtTime(iso: string, lang: Lang) {
  return new Intl.DateTimeFormat(LOCALE[lang], { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(
    new Date(iso),
  )
}

/** fmtDate is "15 ноября" / "15 November", with the year only when it is not the current one. */
export function fmtDate(iso: string, lang: Lang, now = new Date()) {
  const d = new Date(iso)
  const opts: Intl.DateTimeFormatOptions = { day: 'numeric', month: 'long' }
  if (d.getFullYear() !== now.getFullYear()) opts.year = 'numeric'
  return new Intl.DateTimeFormat(LOCALE[lang], opts).format(d)
}

export function fmtDateTime(iso: string, lang: Lang) {
  return new Intl.DateTimeFormat(LOCALE[lang], {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).format(new Date(iso))
}

/** fmtRelative is "сейчас", "2 мин. назад", "вчера", "через 20 ч" within 7 days, then the date. */
export function fmtRelative(iso: string, lang: Lang, now = Date.now()) {
  const diff = (new Date(iso).getTime() - now) / 1000
  const abs = Math.abs(diff)
  const rtf = new Intl.RelativeTimeFormat(LOCALE[lang], { numeric: 'auto', style: 'short' })
  if (abs < 45) return rtf.format(0, 'second')
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour')
  if (abs < 7 * 86400) return rtf.format(dayDiff(new Date(iso), new Date(now)), 'day')
  return fmtDate(iso, lang, new Date(now))
}

/** dayDiff counts calendar days from now to d (negative in the past). */
export function dayDiff(d: Date, now: Date) {
  const a = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime()
  const b = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime()
  return Math.round((a - b) / 86400000)
}

/** quote wraps a name the way the language does: «ёлочки» or “curly”. */
export function quote(text: string, lang: Lang) {
  return lang === 'ru' ? `«${text}»` : `“${text}”`
}

/** count turns "a count or the list itself" (some admin fields) into a number. */
export function count(v: number | unknown[] | null | undefined) {
  if (typeof v === 'number') return v
  return Array.isArray(v) ? v.length : 0
}
