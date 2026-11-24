import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Navigate, useNavigate, useSearchParams } from 'react-router'
import { OfflineScreen } from '../shell/AppShell'
import { api, isOffline } from '../../lib/api'
import { safeNext } from '../../lib/links'
import { qk, useMe } from '../../lib/queries'
import type { Me } from '../../lib/types'
import { SignInPanel } from './SignIn'

// Sign in (DESIGN.md §8.1): the app's name and one button. After it, back to where the person was going.

export function LoginPage() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [search] = useSearchParams()
  const next = safeNext(search.get('next'))
  const me = useMe()

  if (me.data) return <Navigate to={next} replace />
  if (me.error && isOffline(me.error)) return <OfflineScreen onRetry={() => void me.refetch()} />

  return (
    <main className="flex min-h-dvh flex-col items-center justify-center px-6 pt-[env(safe-area-inset-top)] pb-[max(12vh,env(safe-area-inset-bottom))]">
      <SignInPanel
        title={t('app.name')}
        footnote={t('login.footnote')}
        onSignedIn={async () => {
          await qc.fetchQuery({ queryKey: qk.me, queryFn: () => api.get<Me>('/me'), staleTime: 0 })
          navigate(next, { replace: true })
        }}
      />
    </main>
  )
}
