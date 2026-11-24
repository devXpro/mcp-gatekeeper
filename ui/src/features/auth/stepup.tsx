import { useQueryClient } from '@tanstack/react-query'
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { PasskeyButton, PasskeyGlyph } from '../../components/passkey'
import { Button } from '../../components/ui/button'
import { Sheet } from '../../components/ui/sheet'
import { api, isApiError } from '../../lib/api'
import { cn } from '../../lib/cn'
import { ceremonyError, getAssertion } from '../../lib/passkeys'
import { qk } from '../../lib/queries'
import type { Begin, Me } from '../../lib/types'

// Step-up (docs/PLAN.md §5.9, DESIGN.md §8.10.3): a dangerous action answers 403 step_up_required; the sheet asks for
// Face ID / Touch ID once, then the action is retried once. Cancel drops the action without an error.

interface StepUpApi {
  /** withStepUp runs fn; on step_up_required it confirms the person and runs fn again. undefined = cancelled. */
  withStepUp: <T>(fn: () => Promise<T>, action: string) => Promise<T | undefined>
}

const StepUpContext = createContext<StepUpApi | null>(null)

export function useStepUp() {
  const ctx = useContext(StepUpContext)
  if (!ctx) throw new Error('useStepUp outside StepUpProvider')
  return ctx
}

interface Pending {
  open: boolean
  /** kept after closing, so the words stay while the sheet animates out */
  action: string
}

export function StepUpProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const [pending, setPending] = useState<Pending>({ open: false, action: '' })
  const resolver = useRef<((ok: boolean) => void) | undefined>(undefined)

  const withStepUp = useCallback(async <T,>(fn: () => Promise<T>, action: string) => {
    try {
      return await fn()
    } catch (err) {
      if (!isApiError(err, 'step_up_required')) throw err
      const ok = await new Promise<boolean>((resolve) => {
        resolver.current = resolve
        setPending({ open: true, action })
      })
      if (!ok) return undefined
      return await fn()
    }
  }, [])

  const value = useMemo(() => ({ withStepUp }), [withStepUp])
  const finish = (ok: boolean) => {
    resolver.current?.(ok)
    resolver.current = undefined
    setPending((p) => ({ ...p, open: false }))
  }

  return (
    <StepUpContext.Provider value={value}>
      {children}
      <Sheet open={pending.open} onClose={() => finish(false)} title={t('stepup.title')} hiddenTitle size="alert" titleVariant="small">
        <StepUpBody action={pending.action} onDone={finish} />
      </Sheet>
    </StepUpContext.Provider>
  )
}

function StepUpBody({ action, onDone }: { action: string; onDone: (ok: boolean) => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<'cancelled' | 'failed' | null>(null)

  const confirm = async () => {
    setBusy(true)
    setError(null)
    try {
      const begin = await api.post<Begin>('/auth/stepup/begin', {})
      const credential = await getAssertion(begin.options)
      const res = await api.post<{ step_up_until?: string } | undefined>('/auth/stepup/finish', { credential })
      qc.setQueryData<Me>(qk.me, (m) => m && { ...m, step_up_until: res?.step_up_until ?? m.step_up_until })
      onDone(true)
    } catch (err) {
      setError(!isApiError(err) && ceremonyError(err) === 'cancelled' ? 'cancelled' : 'failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col items-center px-2 pt-2 text-center">
      <PasskeyGlyph className="size-12 text-accent" />
      <p aria-hidden className="mt-3 type-title-3">
        {t('stepup.title')}
      </p>
      <p className="mt-1.5 type-subheadline text-label-2">{t('stepup.text', { action })}</p>
      <div className="mt-6 flex w-full flex-col gap-2">
        <PasskeyButton onClick={() => void confirm()} loading={busy} autoFocus>
          {t('stepup.button')}
        </PasskeyButton>
        <Button variant="plain" size="lg" onClick={() => onDone(false)} disabled={busy}>
          {t('common.cancel')}
        </Button>
      </div>
      {error && (
        <p role="alert" className={cn('mt-3 type-footnote', error === 'failed' ? 'text-danger-text' : 'text-label-2')}>
          {t('stepup.failed')}
        </p>
      )}
    </div>
  )
}
