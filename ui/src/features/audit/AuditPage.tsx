import { Blocks, History, KeyRound, Link2, ShieldHalf, Users, type LucideIcon } from 'lucide-react'
import { Fragment, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Page } from '../../components/page'
import { Button } from '../../components/ui/button'
import { EmptyState, ErrorState, SkeletonRows } from '../../components/ui/feedback'
import { Row, Section } from '../../components/ui/list'
import { Sheet } from '../../components/ui/sheet'
import { IconTile, type TileColor } from '../../components/ui/tile'
import { useLang } from '../../i18n'
import { errorText } from '../../lib/errors'
import { dayDiff, fmtDate, fmtDateTime, fmtTime } from '../../lib/format'
import { useDelayed, useSticky } from '../../lib/hooks'
import { useAccount, useAudit, useMe } from '../../lib/queries'
import type { AuditEntry, Lang } from '../../lib/types'

// The audit log (docs/PLAN.md §5.9): the family's own (/account/audit) and, for the superadmin, the system's
// (/admin/audit). Entries are grouped by local day; a tap shows the whole entry. Details never hold secrets. A member
// gets only their own entries, without other people's addresses (docs/reviews/T2.R.md L4, filtered by the hub): the
// page says so and is titled «Мой журнал».

const LOOK: [string, LucideIcon, TileColor][] = [
  ['auth.', KeyRound, 'gray'],
  ['oauth.', Link2, 'green'],
  ['module.', Blocks, 'blue'],
  ['account.', Users, 'indigo'],
  ['admin.', ShieldHalf, 'orange'],
]

function lookOf(action: string): { icon: LucideIcon; color: TileColor } {
  const hit = LOOK.find(([prefix]) => action.startsWith(prefix))
  return hit ? { icon: hit[1], color: hit[2] } : { icon: History, color: 'gray' }
}

function dayLabel(iso: string, lang: Lang, t: (k: string) => string) {
  const d = dayDiff(new Date(iso), new Date())
  if (d === 0) return t('audit.today')
  if (d === -1) return t('audit.yesterday')
  return fmtDate(iso, lang)
}

export function AuditPage({ scope }: { scope: 'account' | 'admin' }) {
  const { t } = useTranslation()
  const lang = useLang()
  const audit = useAudit(scope)
  const people = useAccount().data?.members ?? []
  const me = useMe().data
  const mine = scope === 'account' && me?.person.role === 'member'
  const showSkeleton = useDelayed(audit.isPending)
  const [open, setOpen] = useState<AuditEntry | null>(null)
  const entries = audit.data?.pages.flat() ?? []

  const who = (e: AuditEntry) => {
    if (e.actor_name) return e.actor_name
    if (e.actor && typeof e.actor === 'object') return e.actor.name ?? e.actor.id
    if (typeof e.actor === 'string' && e.actor) return people.find((p) => p.id === e.actor)?.name ?? e.actor
    return t('audit.system')
  }
  const words = (e: AuditEntry) => t(`audit.action.${e.action}`, { defaultValue: e.action })

  const groups: { day: string; items: AuditEntry[] }[] = []
  for (const e of entries) {
    const day = dayLabel(e.at, lang, t)
    const last = groups[groups.length - 1]
    if (last?.day === day) last.items.push(e)
    else groups.push({ day, items: [e] })
  }

  const back = scope === 'account' ? { to: '/account', label: t('tab.account') } : { to: '/admin', label: t('tab.admin') }
  return (
    <Page title={t(mine ? 'audit.mine.title' : scope === 'account' ? 'audit.account.title' : 'audit.admin.title')} back={back}>
      {mine && <p className="-mt-3 mb-6 px-1 type-subheadline text-label-2">{t('audit.mine.intro')}</p>}
      {audit.error && !audit.data ? (
        <ErrorState text={errorText(audit.error, t)} onRetry={() => void audit.refetch()} />
      ) : !audit.data ? (
        showSkeleton && <SkeletonRows rows={6} />
      ) : entries.length === 0 ? (
        <EmptyState icon={History} title={t('audit.empty.title')} text={t(mine ? 'audit.empty.mine' : `audit.empty.${scope}`)} />
      ) : (
        <>
          {groups.map((g) => (
            <Fragment key={g.day}>
              <Section header={g.day}>
                {g.items.map((e) => {
                  const look = lookOf(e.action)
                  return (
                    <Row
                      key={e.id}
                      onClick={() => setOpen(e)}
                      iconInset
                      leading={<IconTile icon={look.icon} color={look.color} />}
                      title={words(e)}
                      subtitle={[who(e), fmtTime(e.at, lang), e.target].filter(Boolean).join(' · ')}
                      subtitleLines={1}
                      chevron
                    />
                  )
                })}
              </Section>
            </Fragment>
          ))}
          {audit.hasNextPage && (
            <Button className="mt-6 w-full" variant="tinted" size="md" loading={audit.isFetchingNextPage} onClick={() => void audit.fetchNextPage()}>
              {t('audit.more')}
            </Button>
          )}
        </>
      )}
      <EntrySheet entry={open} who={open ? who(open) : ''} words={open ? words(open) : ''} onClose={() => setOpen(null)} />
    </Page>
  )
}

/** AccountAuditPage is /account/audit: the family's log, or a member's own entries. */
export function AccountAuditPage() {
  return <AuditPage scope="account" />
}

function EntrySheet({ entry, who, words, onClose }: { entry: AuditEntry | null; who: string; words: string; onClose: () => void }) {
  const { t } = useTranslation()
  const lang = useLang()
  const shown = useSticky(entry)
  const detail = Object.entries(shown?.detail ?? {})
  return (
    <Sheet open={!!entry} onClose={onClose} title={words}>
      {shown && (
        <>
          <Section>
            <Row title={t('audit.who')} trailing={<span className="truncate">{who}</span>} />
            <Row title={t('audit.when')} trailing={<span className="truncate tabular-nums">{fmtDateTime(shown.at, lang)}</span>} />
            {shown.target && <Row title={t('audit.target')} trailing={<span className="truncate font-mono text-[15px]">{shown.target}</span>} />}
            {shown.ip && <Row title={t('audit.ip')} trailing={<span className="truncate font-mono text-[15px]">{shown.ip}</span>} />}
            <Row title={t('audit.action')} trailing={<span className="truncate font-mono text-[15px]">{shown.action}</span>} />
          </Section>
          {detail.length > 0 && (
            <Section header={t('audit.detail')}>
              {detail.map(([k, v]) => (
                <Row key={k} title={k} titleClassName="font-mono text-[15px]" trailing={<span className="truncate">{v}</span>} />
              ))}
            </Section>
          )}
        </>
      )}
    </Sheet>
  )
}
