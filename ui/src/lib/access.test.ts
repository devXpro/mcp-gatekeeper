import { describe, expect, it } from 'vitest'
import {
  dayValue,
  endOfDay,
  groupPermissions,
  isInactive,
  parseDay,
  permissionIds,
  permissionsOf,
  permissionTitles,
  termBounds,
  termEnd,
  termOf,
  type TermChoice,
} from './access'

// Terms end at the end of a local day, never more than a year away (the server's one-year limit, ui/README.md); permissions are ids or "all".

const now = new Date(2026, 10, 25, 10, 30) // 25 November 2026, 10:30 local
const at = (preset: TermChoice['preset'], date = '') => termEnd({ preset, date }, now)

describe('termEnd', () => {
  it('ends every preset at the end of its day', () => {
    expect(at('forever')).toBeNull()
    expect(at('day')).toEqual(new Date(2026, 10, 26, 23, 59, 59))
    expect(at('3days')).toEqual(new Date(2026, 10, 28, 23, 59, 59))
    expect(at('week')).toEqual(new Date(2026, 11, 2, 23, 59, 59))
    expect(at('month')).toEqual(new Date(2026, 11, 25, 23, 59, 59))
    expect(at('date', '2026-12-31')).toEqual(new Date(2026, 11, 31, 23, 59, 59))
  })

  it('keeps "a month" inside the next month', () => {
    expect(termEnd({ preset: 'month', date: '' }, new Date(2027, 0, 31, 9))).toEqual(new Date(2027, 1, 28, 23, 59, 59))
    expect(termEnd({ preset: 'month', date: '' }, new Date(2028, 0, 31, 9))).toEqual(new Date(2028, 1, 29, 23, 59, 59))
  })

  it('takes a last day from today up to the bound, inside a year', () => {
    const { min, max } = termBounds(now)
    expect(min).toBe('2026-11-25')
    expect(at('date', min)).toEqual(endOfDay(now))
    expect(at('date', max)).toBeInstanceOf(Date)
    // The end of the last allowed day is still less than a year away.
    const yearAway = new Date(now.getTime() + 365 * 86_400_000)
    expect((at('date', max) as Date).getTime()).toBeLessThan(yearAway.getTime())
  })

  it('refuses a missing, malformed, past or too-far day', () => {
    expect(at('date', '')).toBeUndefined()
    expect(at('date', '2026-02-30')).toBeUndefined()
    expect(at('date', 'tomorrow')).toBeUndefined()
    expect(at('date', '2026-11-24')).toBeUndefined()
    expect(at('date', '2027-11-25')).toBeUndefined()
  })
})

describe('days', () => {
  it('reads and writes local YYYY-MM-DD days', () => {
    expect(dayValue(new Date(2026, 0, 5))).toBe('2026-01-05')
    expect(parseDay('2026-01-05')).toEqual(new Date(2026, 0, 5))
    expect(parseDay('2026-13-01')).toBeUndefined()
  })

  it('shows an existing end as its day, a past or no end as the fallback or forever', () => {
    expect(termOf(null, now, 'week')).toEqual({ preset: 'forever', date: '' })
    expect(termOf(new Date(2026, 11, 3, 23, 59, 59).toISOString(), now, 'week')).toEqual({ preset: 'date', date: '2026-12-03' })
    expect(termOf(new Date(2026, 10, 1).toISOString(), now, 'week')).toEqual({ preset: 'week', date: '' })
  })
})

describe('permissions', () => {
  it('maps "all" and ticked ids both ways', () => {
    expect(permissionsOf(['all'])).toEqual({ all: true, ids: [] })
    expect(permissionsOf(['res-a'])).toEqual({ all: false, ids: ['res-a'] })
    expect(permissionsOf(null)).toEqual({ all: false, ids: [] })
    expect(permissionIds({ all: true, ids: ['res-a'] })).toEqual(['all'])
    expect(permissionIds({ all: false, ids: ['res-a', 'res-b'] })).toEqual(['res-a', 'res-b'])
  })

  it('groups the catalog in its own order and names ids in the UI language', () => {
    const catalog = [
      { id: 'res-a', title: { ru: 'Лампа', en: 'Lamp' }, group: { ru: 'Комната', en: 'Room' } },
      { id: 'res-b', title: 'Kettle' },
      { id: 'res-c', title: 'Fan', group: { ru: 'Комната', en: 'Room' } },
    ]
    expect(groupPermissions(catalog, 'en').map((g) => [g.title, g.items.map((p) => p.id)])).toEqual([
      ['Room', ['res-a', 'res-c']],
      ['', ['res-b']],
    ])
    expect(permissionTitles(['res-a', 'gone'], catalog, 'ru')).toEqual(['Лампа', 'gone'])
  })

  it('tells an inactive member by the server or by the clock', () => {
    const t = now.getTime()
    expect(isInactive({ access_until: null, active: true }, t)).toBe(false)
    expect(isInactive({ access_until: new Date(t + 1000).toISOString(), active: true }, t)).toBe(false)
    expect(isInactive({ access_until: new Date(t - 1000).toISOString(), active: true }, t)).toBe(true)
    expect(isInactive({ access_until: null, active: false }, t)).toBe(true)
    expect(isInactive({}, t)).toBe(false)
  })
})
