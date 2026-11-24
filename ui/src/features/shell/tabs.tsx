import { LogOut } from 'lucide-react'
import { motion } from 'motion/react'
import type { MouseEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { Link, useNavigate } from 'react-router'
import { AppIcon, Avatar } from '../../components/ui/tile'
import { cn } from '../../lib/cn'
import { fade } from '../../lib/motion'
import { tabPath, type TabId } from './navstack'
import type { TabDef } from './tabdefs'

/** useTabClick: another tab → its last path; the current tab again → its root and the top (iOS). */
function useTabClick(current: TabId | undefined) {
  const navigate = useNavigate()
  return (e: MouseEvent, tab: TabDef) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return
    e.preventDefault()
    if (tab.id === current) {
      navigate(tab.root)
      window.scrollTo({ top: 0, behavior: 'smooth' })
    } else {
      navigate(tabPath(tab.id, tab.root))
    }
  }
}

function Dot() {
  return <span aria-hidden className="absolute -top-0.5 -right-1 size-2 rounded-full bg-danger ring-2 ring-[var(--bg)]" />
}

/** TabBar: the phone and tablet navigation, fixed at the bottom over the content (DESIGN.md §5.2). */
export function TabBar({ tabs, current, badges }: { tabs: TabDef[]; current?: TabId; badges: Partial<Record<TabId, boolean>> }) {
  const { t } = useTranslation()
  const onClick = useTabClick(current)
  return (
    <div className="fixed inset-x-0 bottom-0 z-30 lg:hidden">
      <nav aria-label={t('nav.sections')} className="material hairline-t pb-[env(safe-area-inset-bottom)]">
        <ul className="mx-auto flex h-[49px] max-w-[600px] items-stretch">
          {tabs.map((tab) => {
            const active = tab.id === current
            const Icon = tab.icon
            return (
              <li key={tab.id} className="flex flex-1">
                <Link
                  to={tab.root}
                  onClick={(e) => onClick(e, tab)}
                  aria-current={active ? 'page' : undefined}
                  className={cn(
                    'flex flex-1 flex-col items-center justify-center gap-0.5 pt-1 outline-offset-[-2px]',
                    active ? 'text-accent' : 'text-tab-inactive',
                  )}
                >
                  <span className="relative">
                    <Icon aria-hidden className="size-6" strokeWidth={active ? 2.2 : 1.9} />
                    {badges[tab.id] && <Dot />}
                  </span>
                  <span className="type-caption-2">{t(tab.label)}</span>
                </Link>
              </li>
            )
          })}
        </ul>
      </nav>
    </div>
  )
}

/** Sidebar: the desktop navigation (DESIGN.md §5.3). */
export function Sidebar({
  tabs,
  current,
  badges,
  familyName,
  person,
  onLogout,
}: {
  tabs: TabDef[]
  current?: TabId
  badges: Partial<Record<TabId, boolean>>
  familyName: string
  person: { id: string; name: string }
  onLogout: () => void
}) {
  const { t } = useTranslation()
  const onClick = useTabClick(current)
  return (
    <aside className="material hairline-r fixed inset-y-0 left-0 z-30 hidden w-[var(--sidebar-w)] flex-col px-3 pt-5 pb-4 lg:flex">
      <div className="flex items-center gap-2.5 px-2 pb-6">
        <AppIcon size={30} />
        <span className="truncate type-headline">{familyName}</span>
      </div>
      <nav aria-label={t('nav.sections')}>
        <ul className="flex flex-col gap-0.5">
          {tabs.map((tab) => {
            const active = tab.id === current
            const Icon = tab.icon
            return (
              <li key={tab.id}>
                <Link
                  to={tab.root}
                  onClick={(e) => onClick(e, tab)}
                  aria-current={active ? 'page' : undefined}
                  className={cn(
                    'relative flex h-9 items-center gap-3 rounded-sm px-2.5 text-[15px] leading-5 transition-colors',
                    active ? 'bg-accent-tint font-semibold text-accent-tinted' : 'text-label hover:bg-fill',
                  )}
                >
                  <Icon aria-hidden className={cn('size-[18px]', active ? 'text-accent' : 'text-label-2')} strokeWidth={2} />
                  <span className="flex-1 truncate">{t(tab.label)}</span>
                  {badges[tab.id] && <span aria-hidden className="size-2 rounded-full bg-danger" />}
                </Link>
              </li>
            )
          })}
        </ul>
      </nav>
      <div className="mt-auto flex items-center gap-2 rounded-md px-2 py-1.5">
        <Avatar id={person.id} name={person.name} size={32} />
        <span className="min-w-0 flex-1 truncate text-[14px] leading-5 font-medium">{person.name}</span>
        <motion.button
          type="button"
          onClick={onLogout}
          whileTap={{ scale: 0.94 }}
          transition={fade.fast}
          className="inline-flex h-8 items-center gap-1.5 rounded-full px-2.5 text-[13px] font-semibold text-label-2 hover:bg-fill hover:text-label"
        >
          <LogOut aria-hidden className="size-4" />
          {t('account.logout')}
        </motion.button>
      </div>
    </aside>
  )
}
