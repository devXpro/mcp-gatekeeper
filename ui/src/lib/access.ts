// A person's access (ui/README.md, People's access): what they may use (the application's permission ids, "all" for everything) and
// until when. Terms end at the end of a day in this browser's time zone and never more than a year away.

import { label } from '../i18n'
import type { Lang, Member, PermissionInfo } from './types'

/** PERMISSION_ALL is core.PermissionAll: every permission of the application, now and later. */
export const PERMISSION_ALL = 'all'

/** The term presets of the invite sheet and the member detail, then "until a date…". */
export type TermPreset = 'forever' | 'day' | '3days' | 'week' | 'month' | 'date'

export const TERM_PRESETS: TermPreset[] = ['forever', 'day', '3days', 'week', 'month', 'date']

/** A term as the pickers hold it: a preset, and the last day (YYYY-MM-DD) for "date". */
export interface TermChoice {
  preset: TermPreset
  date: string
}

/** A permission choice as the pickers hold it: everything, or the ticked ids. */
export interface PermissionChoice {
  all: boolean
  ids: string[]
}

/** The furthest last day a term may have: the end of that day stays inside a year (the server's limit). */
export const MAX_TERM_DAYS = 364

function addDays(d: Date, n: number) {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() + n)
}

/** addMonth is the same day a month later, or that month's last day (31 January → 28 or 29 February). */
function addMonth(d: Date) {
  const last = new Date(d.getFullYear(), d.getMonth() + 2, 0).getDate()
  return new Date(d.getFullYear(), d.getMonth() + 1, Math.min(d.getDate(), last))
}

/** endOfDay is 23:59:59 of d's day in this browser's time zone. */
export function endOfDay(d: Date) {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate(), 23, 59, 59)
}

/** dayValue is d's day as an <input type="date"> value (local, YYYY-MM-DD). */
export function dayValue(d: Date) {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`
}

/** parseDay reads a YYYY-MM-DD value as a local day; undefined when it is not one. */
export function parseDay(v: string): Date | undefined {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(v)
  if (!m) return undefined
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]))
  return dayValue(d) === v ? d : undefined
}

/** termBounds are the first and the last day "until a date…" accepts. */
export function termBounds(now: Date) {
  return { min: dayValue(now), max: dayValue(addDays(now, MAX_TERM_DAYS)) }
}

/**
 * termEnd is the instant a term ends: null for "forever", undefined for a date that is missing, past or more than
 * a year away. "1 day" is the end of tomorrow, "a month" the end of the same day next month.
 */
export function termEnd(term: TermChoice, now: Date): Date | null | undefined {
  switch (term.preset) {
    case 'forever':
      return null
    case 'day':
      return endOfDay(addDays(now, 1))
    case '3days':
      return endOfDay(addDays(now, 3))
    case 'week':
      return endOfDay(addDays(now, 7))
    case 'month':
      return endOfDay(addMonth(now))
    case 'date': {
      const d = parseDay(term.date)
      const { min, max } = termBounds(now)
      if (!d || term.date < min || term.date > max) return undefined
      return endOfDay(d)
    }
  }
}

/** termOf is the choice that shows an existing end: "forever", or its day when that day is still ahead. */
export function termOf(until: string | null | undefined, now: Date, fallback: TermPreset): TermChoice {
  if (!until) return { preset: 'forever', date: '' }
  const d = new Date(until)
  return d.getTime() > now.getTime() ? { preset: 'date', date: dayValue(d) } : { preset: fallback, date: '' }
}

/** permissionsOf turns the wire ids into a choice; none means nothing ticked. */
export function permissionsOf(ids: string[] | null | undefined): PermissionChoice {
  const list = ids ?? []
  return list.includes(PERMISSION_ALL) ? { all: true, ids: [] } : { all: false, ids: list }
}

/** permissionIds is what the API takes for a choice. */
export function permissionIds(c: PermissionChoice): string[] {
  return c.all ? [PERMISSION_ALL] : c.ids
}

/** hasEnded: the member's term is over (by the clock, even when the list is a little old). */
export function hasEnded(m: Pick<Member, 'access_until'>, now: number) {
  return !!m.access_until && new Date(m.access_until).getTime() <= now
}

/** isInactive: the member may not sign in any more (the term is over, or the server says so). */
export function isInactive(m: Pick<Member, 'access_until' | 'active'>, now: number) {
  return m.active === false || hasEnded(m, now)
}

export interface PermissionGroup {
  /** the group's title in the UI language; empty for permissions without a group */
  title: string
  items: PermissionInfo[]
}

/** groupPermissions keeps the catalog's order: groups by first appearance, items as listed. */
export function groupPermissions(catalog: PermissionInfo[], lang: Lang): PermissionGroup[] {
  const groups: PermissionGroup[] = []
  for (const p of catalog) {
    const title = label(p.group, lang)
    let g = groups.find((x) => x.title === title)
    if (!g) {
      g = { title, items: [] }
      groups.push(g)
    }
    g.items.push(p)
  }
  return groups
}

/** permissionTitles names the ids from the catalog; an id it does not know is shown as is. */
export function permissionTitles(ids: string[], catalog: PermissionInfo[] | undefined, lang: Lang): string[] {
  return ids.map((id) => {
    const p = catalog?.find((x) => x.id === id)
    return p ? label(p.title, lang) : id
  })
}
