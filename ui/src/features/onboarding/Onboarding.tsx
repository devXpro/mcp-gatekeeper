import { useQueryClient } from '@tanstack/react-query'
import { ChevronLeft, Link2Off } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useEffect, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router'
import { useApp } from '../../app/context'
import { PasskeyButton, PasskeyGlyph } from '../../components/passkey'
import { Button } from '../../components/ui/button'
import { TextField } from '../../components/ui/controls'
import { EmptyState, SuccessCheck } from '../../components/ui/feedback'
import { Spinner } from '../../components/ui/spinner'
import { AppIcon } from '../../components/ui/tile'
import { Halo, Rise } from '../auth/SignIn'
import { OfflineScreen } from '../shell/AppShell'
import { useLang } from '../../i18n'
import { api, isApiError, isOffline } from '../../lib/api'
import { cn } from '../../lib/cn'
import { errorText } from '../../lib/errors'
import { quote } from '../../lib/format'
import { spring } from '../../lib/motion'
import { ceremonyError, createCredential } from '../../lib/passkeys'
import { passkeyKind } from '../../lib/platform'
import { qk } from '../../lib/queries'
import type { Begin, InviteKind, TokenInfo } from '../../lib/types'

// The first run (/setup) and invites (/join), DESIGN.md §8.2: open the one-time link, read what it is for, name
// yourself (and the family, for a new one), create the passkey. One step per screen; both routes take any kind of
// link, since the server says what the token is.

let captured: string | null | undefined

/** takeToken reads `#t=` once, keeps it in memory and removes it from the address bar. */
function takeToken(): string | null {
  if (captured !== undefined) return captured
  const m = /(?:^#|[#&])t=([^&]+)/.exec(window.location.hash)
  captured = m ? decodeURIComponent(m[1]) : null
  if (window.location.hash) window.history.replaceState(window.history.state, '', window.location.pathname + window.location.search)
  return captured
}

type Step = 'checking' | 'problem' | 'welcome' | 'name' | 'family' | 'passkey' | 'done'
type Problem = 'invalid' | 'offline' | 'error'

/** The steps a kind of link walks, after the check. */
function stepsFor(kind: InviteKind): Step[] {
  return kind === 'member' ? ['welcome', 'name', 'passkey', 'done'] : ['welcome', 'name', 'family', 'passkey', 'done']
}

export function Onboarding({ route }: { route: 'setup' | 'join' }) {
  const { t } = useTranslation()
  const lang = useLang()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const { setupDoneTo } = useApp()
  const [token] = useState(takeToken)
  const [info, setInfo] = useState<TokenInfo>()
  const [problem, setProblem] = useState<Problem | undefined>(() => (token ? undefined : 'invalid'))
  const [step, setStep] = useState<Step>(() => (token ? 'checking' : 'problem'))
  const [dir, setDir] = useState(1)
  const [name, setName] = useState('')
  const [family, setFamily] = useState('')
  const [fieldError, setFieldError] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [note, setNote] = useState<{ text: string; danger?: boolean }>()

  useEffect(() => {
    if (!token) return
    let live = true
    api
      .post<TokenInfo>('/auth/token', { token })
      .then((res) => {
        if (!live) return
        setInfo(res)
        setName(res.kind === 'setup' ? '' : (res.name ?? ''))
        setFamily(res.account_name ?? '')
        setStep('welcome')
      })
      .catch((err: unknown) => {
        if (!live) return
        setProblem(isOffline(err) ? 'offline' : isApiError(err) && err.status < 500 ? 'invalid' : 'error')
        setStep('problem')
      })
    return () => {
      live = false
    }
  }, [token])

  const order = info ? stepsFor(info.kind) : []
  const go = (to: Step) => {
    setDir(order.indexOf(to) >= order.indexOf(step) ? 1 : -1)
    setFieldError(undefined)
    setNote(undefined)
    setStep(to)
  }
  const nextOf = (s: Step) => order[order.indexOf(s) + 1] ?? 'done'
  const prevOf = (s: Step) => order[order.indexOf(s) - 1]
  const checkName = (v: string) => {
    const n = v.trim()
    if (n.length < 1) return t('form.required')
    if (n.length > 40) return t('form.maxLength', { max: 40 })
    return undefined
  }

  const create = async () => {
    if (!token || !info) return
    setBusy(true)
    setNote(undefined)
    let phase: 'begin' | 'ceremony' | 'finish' = 'begin'
    try {
      const body: Record<string, string> = { token, name: name.trim() }
      if (info.kind !== 'member') body.account_name = family.trim()
      const begin = await api.post<Begin>('/auth/register/begin', body)
      phase = 'ceremony'
      const credential = await createCredential(begin.options)
      phase = 'finish'
      await api.post('/auth/register/finish', { credential })
      await qc.invalidateQueries({ queryKey: qk.me })
      go('done')
    } catch (err) {
      if (isApiError(err, 'not_found')) {
        setProblem('invalid')
        setStep('problem')
      } else if (isApiError(err, 'conflict') || (!isApiError(err) && ceremonyError(err) === 'exists')) {
        setNote({ text: t('onboarding.passkey.exists') })
      } else if (!isApiError(err) && !isOffline(err) && ceremonyError(err) === 'cancelled') {
        setNote({ text: t('onboarding.passkey.cancelled') })
      } else if (phase === 'finish' && isApiError(err, 'invalid')) {
        setNote({ text: t('onboarding.passkey.failed'), danger: true })
      } else {
        setNote({ text: errorText(err, t), danger: true })
      }
    } finally {
      setBusy(false)
    }
  }

  if (step === 'problem' && problem === 'offline') return <OfflineScreen onRetry={() => window.location.reload()} />

  const kind = info?.kind ?? (route === 'setup' ? 'setup' : 'member')
  const glyph = <PasskeyGlyph className="size-16 text-accent" />
  let content: ReactNode
  let action: ReactNode
  switch (step) {
    case 'checking':
      content = (
        <div className="flex flex-1 flex-col items-center justify-center gap-4 pb-24" role="status">
          <Spinner size="lg" />
          <p className="type-callout text-label-2">{t('onboarding.checking')}</p>
        </div>
      )
      break
    case 'problem':
      content = (
        <div className="flex flex-1 items-center justify-center pb-16">
          <EmptyState
            icon={Link2Off}
            iconClassName="text-warning"
            title={problem === 'error' ? t('error.generic') : t('onboarding.invalid')}
            text={t(route === 'setup' ? 'onboarding.invalid.setup' : 'onboarding.invalid.join')}
          />
        </div>
      )
      break
    case 'welcome':
      content = (
        <div className="flex flex-1 flex-col items-center pt-12 text-center">
          <Halo>
            <AppIcon size={88} />
          </Halo>
          <Rise delay={0.08}>
            <h1 className="mt-8 type-title-1 text-balance">
              {kind === 'setup'
                ? t('onboarding.welcome.setup.title')
                : kind === 'owner'
                  ? t('onboarding.welcome.owner.title', { family: quote(info?.account_name ?? '', lang) })
                  : t('onboarding.welcome.member.title', { family: quote(info?.account_name ?? '', lang) })}
            </h1>
          </Rise>
          <Rise delay={0.16}>
            <p className="prose-ru mt-3 type-callout text-balance text-label-2">{t(`onboarding.welcome.${kind}.text`)}</p>
          </Rise>
        </div>
      )
      action = (
        <Button type="submit" variant="filled" size="lg" onClick={() => go(nextOf('welcome'))}>
          {t('onboarding.start')}
        </Button>
      )
      break
    case 'name':
      content = (
        <StepText title={t('onboarding.name.title')} text={t(kind === 'setup' ? 'onboarding.name.text.setup' : 'onboarding.name.text')}>
          <TextField
            label={t('onboarding.name.label')}
            hideLabel
            value={name}
            placeholder={t('onboarding.name.placeholder')}
            onChange={(e) => setName(e.target.value)}
            error={fieldError}
            maxLength={40}
            enterKeyHint="next"
            autoComplete="given-name"
            autoFocus
          />
        </StepText>
      )
      action = (
        <Button
          type="submit"
          variant="filled"
          size="lg"
          onClick={() => {
            const e = checkName(name)
            if (e) setFieldError(e)
            else go(nextOf('name'))
          }}
        >
          {t('common.next')}
        </Button>
      )
      break
    case 'family':
      content = (
        <StepText title={t('onboarding.family.title')} text={t('onboarding.family.text')}>
          <TextField
            label={t('onboarding.family.label')}
            hideLabel
            value={family}
            placeholder={t('onboarding.family.placeholder')}
            onChange={(e) => setFamily(e.target.value)}
            error={fieldError}
            hint={family.trim() ? t('onboarding.family.preview', { name: quote(family.trim(), lang) }) : undefined}
            maxLength={40}
            enterKeyHint="next"
            autoComplete="off"
            autoFocus
          />
        </StepText>
      )
      action = (
        <Button
          type="submit"
          variant="filled"
          size="lg"
          onClick={() => {
            const e = checkName(family)
            if (e) setFieldError(e)
            else go(nextOf('family'))
          }}
        >
          {t('common.next')}
        </Button>
      )
      break
    case 'passkey':
      content = (
        <div className="flex flex-1 flex-col items-center pt-12 text-center">
          <Halo>{glyph}</Halo>
          <Rise delay={0.08}>
            <h1 className="mt-8 type-title-1">{t(`onboarding.passkey.title.${passkeyKind()}`)}</h1>
          </Rise>
          <Rise delay={0.14}>
            <p className="prose-ru mt-3 type-callout text-balance text-label-2">{t('onboarding.passkey.text')}</p>
          </Rise>
          {note && (
            <p role="alert" className={cn('mt-6 type-footnote text-balance', note.danger ? 'text-danger-text' : 'text-label-2')}>
              {note.text}
            </p>
          )}
        </div>
      )
      action = (
        <PasskeyButton onClick={() => void create()} loading={busy}>
          {t('onboarding.passkey.button')}
        </PasskeyButton>
      )
      break
    case 'done':
      content = (
        <div className="flex flex-1 flex-col items-center pt-16 text-center">
          <Halo tone="success">
            <SuccessCheck size={72} />
          </Halo>
          <Rise delay={0.2}>
            <h1 className="mt-8 type-title-1">{t('onboarding.done.title', { name: name.trim() })}</h1>
          </Rise>
          <Rise delay={0.28}>
            <p className="prose-ru mt-3 type-callout text-balance text-label-2">
              {t(`onboarding.done.${kind}`, { family: quote(family.trim() || (info?.account_name ?? ''), lang) })}
            </p>
          </Rise>
        </div>
      )
      action = (
        <Button variant="filled" size="lg" onClick={() => navigate(kind === 'setup' ? setupDoneTo : '/connect', { replace: true })}>
          {t(kind === 'setup' ? 'onboarding.done.button.setup' : 'onboarding.done.button')}
        </Button>
      )
      break
  }

  const dots: Step[] = order.filter((s) => s !== 'done')
  const index = dots.indexOf(step)
  const back = step === 'name' || step === 'family' || step === 'passkey' ? prevOf(step) : undefined
  return (
    <form className="flex min-h-dvh flex-col pt-[env(safe-area-inset-top)]" noValidate onSubmit={(e) => e.preventDefault()}>
      <header className="relative flex h-11 items-center px-2">
        {back && (
          <button
            type="button"
            onClick={() => go(back)}
            aria-label={t('nav.back')}
            className="inline-flex size-11 items-center justify-center rounded-full text-accent-text"
          >
            <ChevronLeft aria-hidden className="size-7" strokeWidth={2.2} />
          </button>
        )}
        {index >= 0 && (
          <div
            className="absolute left-1/2 flex -translate-x-1/2 gap-2"
            role="img"
            aria-label={t('onboarding.step', { n: index + 1, total: dots.length })}
          >
            {dots.map((s, i) => (
              <motion.span
                key={s}
                aria-hidden
                className={cn('h-2 rounded-full transition-colors duration-300', i <= index ? 'bg-accent' : 'bg-fill')}
                initial={false}
                animate={{ width: i === index ? 20 : 8 }}
                transition={spring.snappy}
              />
            ))}
          </div>
        )}
      </header>
      <main className="flex flex-1 flex-col items-center px-6">
        <div className="flex w-full max-w-[420px] flex-1 flex-col">
          <AnimatePresence mode="wait" initial={false} custom={dir}>
            <motion.div
              key={step}
              custom={dir}
              className="flex flex-1 flex-col"
              variants={{
                enter: (d: number) => ({ x: 24 * d, opacity: 0 }),
                center: { x: 0, opacity: 1, transition: spring.smooth },
                exit: { opacity: 0, transition: { duration: 0.12 } },
              }}
              initial="enter"
              animate="center"
              exit="exit"
            >
              {content}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>
      {action && (
        <footer className="sticky bottom-0 flex justify-center bg-canvas px-6 pt-3 pb-[max(20px,env(safe-area-inset-bottom))]">
          <div className="w-full max-w-[420px]">{action}</div>
        </footer>
      )}
    </form>
  )
}

function StepText({ title, text, children }: { title: string; text: string; children: ReactNode }) {
  return (
    <div className="flex flex-col pt-10">
      <h1 className="type-title-1">{title}</h1>
      <p className="prose-ru mt-2 mb-8 type-callout text-label-2">{text}</p>
      {children}
    </div>
  )
}
