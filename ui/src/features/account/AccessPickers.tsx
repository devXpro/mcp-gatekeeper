import { useTranslation } from 'react-i18next'
import { CheckList, TextField } from '../../components/ui/controls'
import { SkeletonRows } from '../../components/ui/feedback'
import { Section } from '../../components/ui/list'
import { label, useLang } from '../../i18n'
import { groupPermissions, TERM_PRESETS, termBounds, termEnd, type PermissionChoice, type TermChoice, type TermPreset } from '../../lib/access'
import { fmtDate, fmtTime } from '../../lib/format'
import type { PermissionInfo } from '../../lib/types'

// The pickers of a person's access (ui/README.md, People's access): what they may use — everything, or ticks from the
// application's catalog by group — and for how long (presets, or a last day). The wording is generic; an
// application names its own things by overriding access.* (e.g. "access.what": "Devices").

/** PermissionPicker: everything (also what appears later), or only the ticked permissions of the catalog. */
export function PermissionPicker({
  catalog,
  value,
  onChange,
  error,
}: {
  /** undefined while the catalog loads */
  catalog: PermissionInfo[] | undefined
  value: PermissionChoice
  onChange: (v: PermissionChoice) => void
  error?: string
}) {
  const { t } = useTranslation()
  const lang = useLang()
  const groups = catalog ? groupPermissions(catalog, lang) : []
  const toggle = (id: string) => onChange({ all: false, ids: value.ids.includes(id) ? value.ids.filter((x) => x !== id) : [...value.ids, id] })
  return (
    <>
      <Section header={t('access.what')} id="access-what">
        <CheckList<'all' | 'some'>
          label={t('access.what')}
          options={[
            { value: 'all', label: t('access.all'), description: t('access.all.hint') },
            { value: 'some', label: t('access.some') },
          ]}
          selected={[value.all ? 'all' : 'some']}
          onToggle={(v) => onChange({ all: v === 'all', ids: value.ids })}
        />
      </Section>
      {!value.all &&
        (!catalog ? (
          <Section className="mt-4">
            <SkeletonRows rows={2} bare />
          </Section>
        ) : groups.length === 0 ? (
          <p className="mt-3 px-4 type-footnote text-label-2">{t('access.some.empty')}</p>
        ) : (
          groups.map((g, i) => (
            <Section key={g.title || i} className={g.title ? 'mt-6' : 'mt-4'} header={g.title || undefined} label={g.title || t('access.what')}>
              <CheckList<string>
                multiple
                label={g.title || t('access.what')}
                options={g.items.map((p) => ({ value: p.id, label: label(p.title, lang) }))}
                selected={value.ids}
                onToggle={toggle}
              />
            </Section>
          ))
        ))}
      {error && (
        <p role="alert" className="mt-2 px-4 type-footnote text-danger-text">
          {error}
        </p>
      )}
    </>
  )
}

/** TermPicker: forever, a preset, or a last day; the footer says when the access ends. */
export function TermPicker({
  value,
  onChange,
  now,
  error,
}: {
  value: TermChoice
  onChange: (v: TermChoice) => void
  now: Date
  error?: string
}) {
  const { t } = useTranslation()
  const lang = useLang()
  const end = termEnd(value, now)
  const bounds = termBounds(now)
  const footer = end === null ? t('access.term.forever.hint') : end ? t('access.term.until', { date: fmtDate(end.toISOString(), lang, now), time: fmtTime(end.toISOString(), lang) }) : undefined
  return (
    <>
      <Section header={t('access.term')} id="access-term" className="mt-8" footer={value.preset === 'date' ? undefined : footer}>
        <CheckList<TermPreset>
          label={t('access.term')}
          options={TERM_PRESETS.map((p) => ({ value: p, label: t(`access.term.${p}`) }))}
          selected={[value.preset]}
          onToggle={(p) => onChange({ preset: p, date: p === 'date' && !value.date ? bounds.min : value.date })}
        />
      </Section>
      {value.preset === 'date' && (
        <div className="mt-4">
          <TextField
            type="date"
            label={t('access.term.date.label')}
            value={value.date}
            min={bounds.min}
            max={bounds.max}
            onChange={(e) => onChange({ preset: 'date', date: e.target.value })}
            error={error}
            hint={footer}
          />
        </div>
      )}
    </>
  )
}
