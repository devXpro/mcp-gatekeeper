import { useQueryClient } from '@tanstack/react-query'
import { CloudOff } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { Navigate, ScrollRestoration, useLocation, useMatches, useNavigate, useNavigationType, useOutlet } from 'react-router'
import { useApp } from '../../app/context'
import { Page } from '../../components/page'
import { Button, ButtonLink } from '../../components/ui/button'
import { EmptyState, ErrorState } from '../../components/ui/feedback'
import { StepUpProvider } from '../auth/stepup'
import { api, connectivity, isApiError, isOffline, onNoSession } from '../../lib/api'
import { fade, spring, type Direction } from '../../lib/motion'
import { useAccount, useMe } from '../../lib/queries'
import { toast } from '../../lib/toast'
import type { Me } from '../../lib/types'
import { DirectionContext } from './direction'
import { recordNavigation, rememberTabPath, type TabId } from './navstack'
import { Sidebar, TabBar } from './tabs'

/** PageHandle is the `handle` of every signed-in route: which page it shows, in which tab, how deep. */
export interface PageHandle {
  page: string
  tab?: TabId
  depth: number
}

function usePageInfo() {
  const matches = useMatches()
  const leaf = matches[matches.length - 1]
  const handle = leaf?.handle as PageHandle | undefined
  const key = `${handle?.page ?? leaf?.pathname ?? ''}:${leaf?.params.id ?? ''}`
  return { key, handle }
}

/** useLogout signs out, forgets every cached answer and goes to the sign-in page. */
export function useLogout() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  return async () => {
    try {
      await api.post('/auth/logout', {})
    } catch {
      // signed out locally anyway
    }
    qc.clear()
    navigate('/login', { replace: true })
  }
}

/** AppShell is the signed-in frame: tab bar or sidebar, the offline banner and the page transitions. */
export function AppShell() {
  const { t } = useTranslation()
  const me = useMe()
  const location = useLocation()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const hadSession = useRef(false)
  useEffect(() => {
    if (me.data) hadSession.current = true
  }, [me.data])

  // 401 anywhere: back to sign-in, with a toast when a session was there before (DESIGN.md §7).
  useEffect(
    () =>
      onNoSession(() => {
        const next = window.location.pathname + window.location.search
        if (hadSession.current) toast(t('session.expired'), 'info')
        hadSession.current = false
        qc.clear()
        navigate(`/login?next=${encodeURIComponent(next)}`, { replace: true })
      }),
    [navigate, qc, t],
  )

  // Back online: refetch what is on screen.
  useEffect(() => connectivity.onBack(() => void qc.invalidateQueries()), [qc])

  if (me.isPending) return <Splash />
  if (me.error) {
    if (isApiError(me.error, 'no_session')) {
      const next = location.pathname + location.search
      return <Navigate to={next === '/' ? '/login' : `/login?next=${encodeURIComponent(next)}`} replace />
    }
    if (isOffline(me.error)) return <OfflineScreen onRetry={() => void me.refetch()} />
    return (
      <main className="flex min-h-dvh items-center justify-center">
        <ErrorState onRetry={() => void me.refetch()} />
      </main>
    )
  }
  return (
    <StepUpProvider>
      <Frame me={me.data} />
    </StepUpProvider>
  )
}

export function Splash() {
  return <div aria-busy="true" className="min-h-dvh bg-canvas" />
}

export function OfflineScreen({ onRetry }: { onRetry: () => void }) {
  const { t } = useTranslation()
  return (
    <main className="flex min-h-dvh items-center justify-center px-6">
      <EmptyState
        icon={CloudOff}
        iconClassName="text-warning"
        title={t('offline.title')}
        text={t('offline.text')}
        action={
          <Button variant="tinted" size="lg" onClick={onRetry}>
            {t('offline.retry')}
          </Button>
        }
      />
    </main>
  )
}

function Frame({ me }: { me: Me }) {
  const { t } = useTranslation()
  const location = useLocation()
  const navType = useNavigationType()
  const { handle } = usePageInfo()
  const offline = useSyncExternalStore(connectivity.subscribe, connectivity.getSnapshot, () => false)
  const logout = useLogout()
  const account = useAccount()
  const app = useApp()
  // The application's badges (Family Hub: a service that needs the owner, a module that failed).
  const badges = app.useBadges(me)
  const tab = handle?.tab
  const tabs = app.tabs.filter((x) => !x.superadmin || me.person.superadmin)

  useEffect(() => {
    recordNavigation(navType, location.key, location.pathname)
    if (tab) rememberTabPath(tab, location.pathname)
  }, [navType, location.key, location.pathname, tab])

  return (
    <div className="min-h-dvh lg:pl-[var(--sidebar-w)]">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-md focus:bg-dialog focus:px-3 focus:py-2"
      >
        {t('nav.skip')}
      </a>
      <Sidebar
        tabs={tabs}
        current={tab}
        badges={badges}
        familyName={account.data?.name ?? me.account.name}
        person={me.person}
        onLogout={() => void logout()}
      />
      <OfflineBanner offline={offline} />
      <div inert={offline} className={offline ? 'opacity-60 transition-opacity duration-150' : 'transition-opacity duration-150'}>
        <AnimatedOutlet />
      </div>
      <TabBar tabs={tabs} current={tab} badges={badges} />
      <ScrollRestoration
        getKey={(loc, matches) => {
          const h = matches[matches.length - 1]?.handle as PageHandle | undefined
          return h ? `${h.page}:${matches[matches.length - 1]?.params.id ?? ''}` : loc.pathname
        }}
      />
    </div>
  )
}

/**
 * AnimatedOutlet animates page changes (DESIGN.md §4): push and pop slide 24 px and fade, tab switches only
 * cross-fade. The wrapper animates opacity only, so a page's fixed nav bar keeps the viewport as its containing
 * block; the page's <main> carries the slide. Pages share one grid cell while they cross, so nothing shifts.
 */
function AnimatedOutlet() {
  const outlet = useOutlet()
  const { key, handle } = usePageInfo()
  const [prev, setPrev] = useState({ key, tab: handle?.tab, depth: handle?.depth ?? 0, dir: 'tab' as Direction })
  let dir = prev.dir
  if (prev.key !== key) {
    const depth = handle?.depth ?? 0
    dir = handle?.tab && handle.tab === prev.tab ? (depth > prev.depth ? 'push' : depth < prev.depth ? 'pop' : 'tab') : 'tab'
    setPrev({ key, tab: handle?.tab, depth, dir })
  }
  return (
    <DirectionContext.Provider value={dir}>
      <div className="grid">
        <AnimatePresence initial={false} custom={dir}>
          <motion.div
            key={key}
            custom={dir}
            className="col-start-1 row-start-1 min-w-0"
            variants={{
              enter: { opacity: 0 },
              center: { opacity: 1, transition: spring.smooth },
              exit: { opacity: 0, transition: fade.fast },
            }}
            initial="enter"
            animate="center"
            exit="exit"
          >
            {outlet}
          </motion.div>
        </AnimatePresence>
      </div>
    </DirectionContext.Provider>
  )
}

function OfflineBanner({ offline }: { offline: boolean }) {
  const { t } = useTranslation()
  return (
    <AnimatePresence>
      {offline && (
        <motion.div
          role="status"
          initial={{ y: -16, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          exit={{ y: -16, opacity: 0 }}
          transition={fade.fast}
          className="fixed inset-x-0 top-[calc(44px+env(safe-area-inset-top))] z-20 gutter-x pt-2 lg:left-[var(--sidebar-w)]"
        >
          <div className="mx-auto flex max-w-[720px] items-start gap-3 rounded-lg bg-surface-2 p-3.5 shadow-[var(--shadow-toast)] ring-[0.5px] ring-separator">
            <CloudOff aria-hidden className="mt-0.5 size-5 shrink-0 text-warning" />
            <div className="min-w-0 flex-1">
              <p className="type-headline">{t('offline.title')}</p>
              <p className="type-subheadline text-label-2">{t('offline.text')}</p>
            </div>
            <Button variant="plain" size="sm" onClick={connectivity.retryNow}>
              {t('offline.retry')}
            </Button>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

/** AdminOnly keeps the superadmin's pages from everyone else (the API refuses them too). */
export function AdminOnly({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const me = useMe().data
  if (me && !me.person.superadmin) {
    return (
      <Page title={t('noaccess.title')} largeTitle={false}>
        <ErrorState
          title={t('noaccess.title')}
          text={t('noaccess.text')}
          action={
            <ButtonLink to="/connect" variant="tinted" size="lg">
              {t('common.home')}
            </ButtonLink>
          }
        />
      </Page>
    )
  }
  return children
}
