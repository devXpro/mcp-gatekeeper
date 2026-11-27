import { useQueryClient } from '@tanstack/react-query'
import { Check, Clock, Eye, Link2, MonitorSmartphone, PencilLine, ShieldAlert, ShieldOff, X } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router'
import { useApp } from '../../app/context'
import { AssistantTile } from '../../components/assistant'
import { Button, ButtonLink } from '../../components/ui/button'
import { EmptyState, ErrorState, Skeleton } from '../../components/ui/feedback'
import { Row, Section } from '../../components/ui/list'
import { Spinner } from '../../components/ui/spinner'
import { Halo, Rise, SignInPanel } from '../auth/SignIn'
import { StepUpProvider, useStepUp } from '../auth/stepup'
import { OfflineScreen } from '../shell/AppShell'
import { useLang } from '../../i18n'
import { assistantName } from '../../lib/assistant'
import { api, isApiError, isOffline, seg } from '../../lib/api'
import { cn } from '../../lib/cn'
import { isForeignTxn } from '../../lib/consent'
import { errorText } from '../../lib/errors'
import { quote } from '../../lib/format'
import { spring } from '../../lib/motion'
import { qk, useMe, useTxn } from '../../lib/queries'
import type { ConsentTool, ConsentTxn, Redirect } from '../../lib/types'

// Consent (docs/PLAN.md §3.2, §5.5; DESIGN.md §8.3). An assistant sent the person here from its connector window:
// /oauth/authorize kept a transaction and redirected to /consent?txn=…. Without a session the page signs the person in
// first (in place, so the window never leaves this page); then it shows who asks for what, and Allow or Deny sends
// the window back to the assistant with the answer.
//
// Consent phishing (docs/reviews/T2.R.md H1, M4): the screen always says to allow only a connection the person just
// started, warns in red when the request was not opened from the assistant, marks a self-registered client's name as
// unverified, and approving a NEW connection asks for Face ID (403 step_up_required, the StepUpProvider here; the
// first minutes after signing in count, so a connector added right after sign-in is still one tap).

interface Outcome {
  kind: 'approved' | 'denied'
  url: string
}

type Gone = 'expired' | 'foreign'

export function ConsentPage() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const [search] = useSearchParams()
  const txnId = search.get('txn') ?? ''
  const txn = useTxn(txnId)
  const [outcome, setOutcome] = useState<Outcome>()
  const [gone, setGone] = useState<Gone>()

  let body
  if (!txnId || gone === 'expired' || isApiError(txn.error, 'not_found')) {
    body = <Expired />
  } else if (gone === 'foreign' || isForeignTxn(txn.error)) {
    body = <Foreign />
  } else if (isApiError(txn.error, 'forbidden')) {
    body = <NotEnabled />
  } else if (isApiError(txn.error, 'no_session')) {
    body = (
      <Centered>
        <SignInPanel
          title={t('consent.signin.title')}
          subtitle={t('consent.signin.text')}
          footnote={t('consent.signin.footnote')}
          onSignedIn={async () => {
            await qc.invalidateQueries({ queryKey: qk.me })
            await qc.resetQueries({ queryKey: qk.txn(txnId) })
          }}
        />
      </Centered>
    )
  } else if (txn.error && isOffline(txn.error)) {
    return <OfflineScreen onRetry={() => void txn.refetch()} />
  } else if (txn.error) {
    body = (
      <Centered>
        <ErrorState text={errorText(txn.error, t)} onRetry={() => void txn.refetch()} />
      </Centered>
    )
  } else if (!txn.data) {
    body = <Loading />
  } else {
    body = (
      <Consent
        txnId={txnId}
        txn={txn.data}
        outcome={outcome}
        onOutcome={setOutcome}
        onGone={setGone}
        onSignedOut={() => void qc.resetQueries({ queryKey: qk.txn(txnId) })}
      />
    )
  }
  // The page is outside the signed-in shell, so it brings its own step-up sheet.
  return (
    <StepUpProvider>
      <div className="min-h-dvh">{body}</div>
    </StepUpProvider>
  )
}

function Centered({ children }: { children: ReactNode }) {
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center px-6 pt-[env(safe-area-inset-top)] pb-[max(12vh,env(safe-area-inset-bottom))]">
      {children}
    </main>
  )
}

function Loading() {
  return (
    <main aria-busy="true" className="mx-auto flex max-w-[480px] flex-col items-center px-6 pt-[calc(56px+env(safe-area-inset-top))]">
      <div className="flex items-center gap-4">
        <Skeleton className="size-16 rounded-lg" />
        <Skeleton className="size-7 rounded-full" />
        <Skeleton className="size-16 rounded-lg" />
      </div>
      <Skeleton className="mt-8 h-7 w-64" />
      <Skeleton className="mt-3 h-4 w-48" />
      <Skeleton className="mt-10 h-40 w-full rounded-lg" />
    </main>
  )
}

function Expired() {
  const { t } = useTranslation()
  return (
    <Centered>
      <EmptyState icon={Clock} iconClassName="text-warning" title={t('consent.expired.title')} text={t('consent.expired.text')} />
    </Centered>
  )
}

/** Foreign is a request that this browser did not start: a link someone sent, or one copied from another device. */
function Foreign() {
  const { t } = useTranslation()
  return (
    <Centered>
      <EmptyState icon={MonitorSmartphone} iconClassName="text-warning" title={t('consent.foreign.title')} text={t('consent.foreign.text')} />
    </Centered>
  )
}

function NotEnabled() {
  const { t } = useTranslation()
  const me = useMe().data
  const owner = me?.person.role === 'owner'
  return (
    <Centered>
      <EmptyState
        icon={ShieldOff}
        iconClassName="text-warning"
        title={t('consent.disabled.title')}
        text={t(owner ? 'consent.disabled.owner' : 'consent.disabled.member')}
        action={
          owner ? (
            <ButtonLink to="/connect" variant="tinted" size="lg">
              {t('consent.disabled.open')}
            </ButtonLink>
          ) : undefined
        }
      />
    </Centered>
  )
}

/**
 * returnable keeps the answer's redirect a plain https URL or, for a native app, its loopback callback on this
 * computer (RFC 8252): the window is never sent to anything else.
 */
function returnable(url: string, native: boolean) {
  try {
    const u = new URL(url)
    return u.protocol === 'https:' || (native && u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === '[::1]'))
  } catch {
    return false
  }
}

function Consent({
  txnId,
  txn,
  outcome,
  onOutcome,
  onGone,
  onSignedOut,
}: {
  txnId: string
  txn: ConsentTxn
  outcome?: Outcome
  onOutcome: (o: Outcome) => void
  onGone: (g: Gone) => void
  onSignedOut: () => void
}) {
  const { t } = useTranslation()
  const lang = useLang()
  const me = useMe().data
  const { withStepUp } = useStepUp()
  const [busy, setBusy] = useState<'approve' | 'deny'>()
  const [error, setError] = useState<string>()
  // A native app is named with where it runs ("Desk on your computer"); the client's own name is in the App row.
  const who = txn.app ? t('consent.native', { app: txn.app.name }) : assistantName(txn.assistant, txn.client_name)
  const tools = txn.resource.tools ?? []
  const reads = tools.filter((x) => x.access !== 'write')
  const writes = tools.filter((x) => x.access === 'write')
  const elsewhere = txn.started_from === 'elsewhere'
  // A self-registered client (DCR) names itself: its name is shown as unverified (docs/reviews/T2.R.md H1 fix 2).
  const selfNamed = txn.client_kind === 'dcr'

  const answer = async (kind: 'approve' | 'deny') => {
    setBusy(kind)
    setError(undefined)
    try {
      const call = () => api.post<Redirect>(`/oauth/txn/${seg(txnId)}/${kind}`, {})
      // A new connection answers 403 step_up_required (FH_CONSENT_STEPUP): Face ID, then Allow runs once more.
      const res = kind === 'approve' ? await withStepUp(call, t('stepup.action.consent', { assistant: who, module: quote(txn.resource.name, lang) })) : await call()
      if (res === undefined) {
        // The person cancelled Face ID: nothing was answered, both buttons stay.
        setBusy(undefined)
        return
      }
      if (!res?.redirect_url || !returnable(res.redirect_url, !!txn.app)) throw new Error('no redirect')
      onOutcome({ kind: kind === 'approve' ? 'approved' : 'denied', url: res.redirect_url })
      // A moment for the check to land, so the person sees the answer before the window goes back.
      await new Promise((r) => setTimeout(r, 450))
      window.location.assign(res.redirect_url)
    } catch (err) {
      setBusy(undefined)
      // 404: expired, already answered or the module is gone. A 403 that is not the browser binding is the CSRF or
      // Origin check (the module was on a moment ago, when the transaction loaded), so it is said in place.
      if (isApiError(err, 'not_found')) onGone('expired')
      else if (isForeignTxn(err)) onGone('foreign')
      else if (isApiError(err, 'no_session')) onSignedOut()
      else setError(errorText(err, t))
    }
  }

  const done = !!outcome
  return (
    <>
      <main className="mx-auto flex max-w-[480px] flex-col px-4 pt-[calc(40px+env(safe-area-inset-top))] pb-6">
        <div className="flex flex-col items-center text-center">
          <Hero assistant={txn.assistant} resourceId={txn.resource.id} state={outcome?.kind ?? 'ask'} />
          <AnimatePresence mode="wait" initial={false}>
            {done ? (
              <motion.div key="done" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring.smooth} className="mt-7">
                <h1 className="type-title-2 text-balance">
                  {outcome.kind === 'approved' ? t('consent.approved.title') : t('consent.denied.title')}
                </h1>
                <p className="mt-2 inline-flex items-center gap-2 type-subheadline text-label-2" role="status">
                  <Spinner size="sm" />
                  {t('consent.returning', { assistant: who })}
                </p>
              </motion.div>
            ) : (
              <motion.div key="ask" exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.12 }} className="mt-7">
                <Rise delay={0.1}>
                  <h1 className="type-title-2 text-balance">{t('consent.title', { assistant: who, module: quote(txn.resource.name, lang) })}</h1>
                </Rise>
                <Rise delay={0.16}>
                  <p className="mt-2 type-subheadline text-balance text-label-2">
                    {me
                      ? t('consent.subtitle', { family: quote(txn.account.name, lang), name: me.person.name })
                      : t('consent.subtitle.family', { family: quote(txn.account.name, lang) })}
                  </p>
                </Rise>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        <div className={cn('transition-opacity duration-200', done && 'pointer-events-none opacity-40')} aria-hidden={done || undefined}>
          {elsewhere && (
            <Rise delay={0.2}>
              <div role="alert" className="mt-6 flex gap-3 rounded-lg bg-danger/12 px-4 py-3.5 text-left ring-1 ring-danger/40 ring-inset">
                <span aria-hidden className="mt-0.5 inline-flex size-[30px] shrink-0 items-center justify-center rounded-sm bg-danger text-white">
                  <ShieldAlert className="size-[18px]" strokeWidth={2.2} />
                </span>
                <div className="min-w-0">
                  <p className="type-headline text-danger-text">{t('consent.elsewhere.title', { assistant: who })}</p>
                  <p className="mt-0.5 type-footnote text-label">{t('consent.elsewhere.text')}</p>
                </div>
              </div>
            </Rise>
          )}
          {txn.resource.description && (
            <Rise delay={0.22}>
              <p className="mt-6 px-4 text-center type-footnote text-balance text-label-2">{txn.resource.description}</p>
            </Rise>
          )}
          {reads.length > 0 && (
            <Rise delay={0.26} className="mt-7">
              <Section header={t('consent.reads', { assistant: who })} className="mt-0" id="consent-reads">
                {reads.map((tool) => (
                  <ToolRow key={tool.name} tool={tool} />
                ))}
              </Section>
            </Rise>
          )}
          {writes.length > 0 && (
            <Rise delay={0.3} className="mt-7">
              <Section header={t('consent.writes', { assistant: who })} footer={t('consent.writes.footer')} className="mt-0" id="consent-writes">
                {writes.map((tool) => (
                  <ToolRow key={tool.name} tool={tool} />
                ))}
              </Section>
            </Rise>
          )}
          <Rise delay={0.34} className="mt-7">
            <Section className="mt-0" footer={txn.already_granted ? t('consent.already') : t('consent.revoke_hint')}>
              <Row
                title={t('consent.app')}
                subtitle={selfNamed ? <span className="text-warning-text">{t('consent.app.self_named')}</span> : undefined}
                trailing={<span className="truncate">{txn.client_name || who}</span>}
              />
              <Row title={t('consent.family')} trailing={<span className="truncate">{txn.account.name}</span>} />
              <Row title={t('consent.return_to')} trailing={<span className="truncate font-mono text-[15px]">{txn.redirect_host}</span>} />
            </Section>
          </Rise>
        </div>
      </main>
      <footer
        className={cn(
          'sticky bottom-0 bg-canvas px-4 pt-3 pb-[max(20px,env(safe-area-inset-bottom))] transition-opacity duration-200',
          done && 'pointer-events-none opacity-0',
        )}
        aria-hidden={done || undefined}
      >
        <div className="mx-auto flex max-w-[448px] flex-col gap-1">
          {/* Always said, right where the finger is: a phished link is the one Allow that was not asked for (H1). */}
          <p id="consent-only-yours" className={cn('px-2 pb-2 text-center type-footnote text-balance', elsewhere ? 'text-danger-text' : 'text-label-2')}>
            {txn.app ? t('consent.only_yours.native', { app: txn.app.name }) : t('consent.only_yours')}
          </p>
          {error && (
            <p role="alert" className="pb-2 text-center type-footnote text-danger-text">
              {error}
            </p>
          )}
          <Button
            variant="filled"
            size="lg"
            loading={busy === 'approve'}
            disabled={!!busy || done}
            onClick={() => void answer('approve')}
            aria-describedby="consent-only-yours"
          >
            {t('consent.allow')}
          </Button>
          <Button variant="plain" size="lg" loading={busy === 'deny'} disabled={!!busy || done} onClick={() => void answer('deny')}>
            {t('consent.deny')}
          </Button>
        </div>
      </footer>
    </>
  )
}

function ToolRow({ tool }: { tool: ConsentTool }) {
  const { t } = useTranslation()
  const write = tool.access === 'write'
  return (
    <Row
      iconInset
      wrap
      leading={
        <span
          aria-hidden
          className={cn(
            'inline-flex size-[30px] items-center justify-center rounded-sm',
            write ? 'bg-warning/20 text-warning-text' : 'bg-accent-tint text-accent-tinted',
          )}
        >
          {write ? <PencilLine className="size-[17px]" strokeWidth={2} /> : <Eye className="size-[17px]" strokeWidth={2} />}
        </span>
      }
      title={tool.title || tool.name}
      trailing={
        <span className={cn('rounded-xs px-1.5 py-px text-[12px] leading-4 font-semibold', write ? 'bg-fill text-warning-text' : 'bg-fill text-label-2')}>
          {write ? t('consent.access.write') : t('consent.access.read')}
        </span>
      }
    />
  )
}

/**
 * Hero is the assistant and the resource side by side: they spring in from the sides while the link between them
 * draws; Allow turns the link into a green check, Deny into a gray cross (DESIGN.md §4: one-shot, nothing loops).
 */
function Hero({ assistant, resourceId, state }: { assistant: string; resourceId: string; state: 'ask' | 'approved' | 'denied' }) {
  const { ResourceTile } = useApp()
  return (
    <Halo tone={state === 'approved' ? 'success' : 'accent'}>
      <span className="flex items-center">
        <motion.span initial={{ x: 18, opacity: 0, scale: 0.9 }} animate={{ x: 0, opacity: 1, scale: 1 }} transition={spring.success}>
          <AssistantTile assistant={assistant} size="lg" />
        </motion.span>
        <span className="relative mx-1 inline-flex h-16 w-[76px] items-center justify-center">
          <svg aria-hidden viewBox="0 0 76 4" className="absolute inset-x-0 top-1/2 h-1 w-full -translate-y-1/2 overflow-visible">
            <motion.path
              d="M4 2 H72"
              stroke="currentColor"
              strokeWidth={2.5}
              strokeLinecap="round"
              strokeDasharray="1 7"
              className={state === 'approved' ? 'text-success' : 'text-label-3'}
              initial={{ pathLength: 0 }}
              animate={{ pathLength: 1 }}
              transition={{ duration: 0.5, ease: 'easeOut', delay: 0.15 }}
            />
          </svg>
          {/* Plain AnimatePresence: "popLayout" would inject a <style> element, which the CSP refuses. */}
          <span className="relative size-8">
          <AnimatePresence initial={false}>
            <motion.span
              key={state}
              aria-hidden
              className={cn(
                'absolute inset-0 inline-flex items-center justify-center rounded-full ring-4 ring-[var(--bg)]',
                state === 'approved' ? 'bg-success text-white' : state === 'denied' ? 'bg-gray text-white' : 'bg-surface-2 text-accent',
              )}
              initial={{ scale: 0.4, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.4, opacity: 0 }}
              transition={{ ...spring.success, delay: state === 'ask' ? 0.35 : 0 }}
            >
              {state === 'approved' ? (
                <Check className="size-[18px]" strokeWidth={3} />
              ) : state === 'denied' ? (
                <X className="size-[18px]" strokeWidth={3} />
              ) : (
                <Link2 className="size-[18px]" strokeWidth={2.4} />
              )}
            </motion.span>
          </AnimatePresence>
          </span>
        </span>
        <motion.span initial={{ x: -18, opacity: 0, scale: 0.9 }} animate={{ x: 0, opacity: 1, scale: 1 }} transition={spring.success}>
          <ResourceTile id={resourceId} size="lg" />
        </motion.span>
      </span>
    </Halo>
  )
}
