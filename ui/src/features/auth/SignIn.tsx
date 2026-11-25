import { motion } from 'motion/react'
import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { PasskeyButton } from '../../components/passkey'
import { AppIcon } from '../../components/ui/tile'
import { isApiError, isOffline } from '../../lib/api'
import { cn } from '../../lib/cn'
import { errorText } from '../../lib/errors'
import { useNow } from '../../lib/hooks'
import { spring } from '../../lib/motion'
import { ceremonyError, signIn, webauthnSupported } from '../../lib/passkeys'
import { passkeyKind } from '../../lib/platform'

// The sign-in panel (DESIGN.md §8.1): the app icon in its halo, a title, one passkey button and a footnote. The login
// page and the consent page (when there is no session yet) both use it. Passkeys only: discoverable credentials, so
// nobody types a user name.

type State = 'idle' | 'waiting' | 'cancelled' | 'failed' | 'ended' | 'limited' | 'error'

/** Codes a refused login can come back with: the passkey does not belong to anyone here. */
const REFUSED = ['invalid', 'forbidden', 'not_found', 'no_session']

/** accessEnded tells the one refusal that is not about the passkey: its holder's access term is over (403 access_ended). */
const accessEnded = (err: unknown) => isApiError(err, 'access_ended')

export function SignInPanel({ title, subtitle, onSignedIn, footnote }: { title: ReactNode; subtitle?: ReactNode; onSignedIn: () => void | Promise<void>; footnote?: string }) {
  const { t } = useTranslation()
  const [state, setState] = useState<State>('idle')
  const [error, setError] = useState('')
  const [retryAt, setRetryAt] = useState(0)
  const now = useNow(1000)
  const kind = passkeyKind()
  const limited = state === 'limited' && now < retryAt

  const login = async () => {
    setState('waiting')
    try {
      await signIn()
      await onSignedIn()
    } catch (err) {
      if (accessEnded(err)) setState('ended')
      else if (isApiError(err) && REFUSED.includes(err.code)) setState('failed')
      else if (isApiError(err, 'rate_limited')) {
        setRetryAt(Date.now() + (err.retryAfter ?? 60) * 1000)
        setState('limited')
      } else if (!isApiError(err) && !isOffline(err) && ceremonyError(err) === 'cancelled') setState('cancelled')
      else {
        setError(errorText(err, t))
        setState('error')
      }
    }
  }

  const note: { text: string; tone: 'muted' | 'danger' } =
    state === 'cancelled'
      ? { text: t('login.cancelled'), tone: 'muted' }
      : state === 'failed'
        ? { text: t('login.failed'), tone: 'danger' }
        : state === 'ended'
          ? { text: t('login.ended'), tone: 'danger' }
          : limited
            ? { text: t('error.rate_limited'), tone: 'danger' }
            : state === 'error'
              ? { text: error, tone: 'danger' }
              : { text: footnote ?? t('login.footnote'), tone: 'muted' }

  return (
    <div className="flex w-full max-w-[360px] flex-col items-center text-center">
      <Halo>
        <AppIcon size={72} />
      </Halo>
      <Rise delay={0.06}>
        <h1 className="mt-6 type-title-1 text-balance">{title}</h1>
      </Rise>
      <Rise delay={0.12}>
        <p className="mt-1.5 type-callout text-balance text-label-2">{subtitle ?? t(`login.subtitle.${kind}`)}</p>
      </Rise>
      <Rise delay={0.18} className="mt-10 flex w-full flex-col items-center">
        {webauthnSupported() ? (
          <>
            <PasskeyButton onClick={() => void login()} loading={state === 'waiting'} disabled={limited} autoFocus>
              {state === 'waiting' ? t('login.waiting') : t('login.button')}
            </PasskeyButton>
            <p
              role={note.tone === 'danger' ? 'alert' : undefined}
              className={cn('mt-4 min-h-[36px] text-center type-footnote text-balance', note.tone === 'danger' ? 'text-danger-text' : 'text-label-2')}
            >
              {note.text}
            </p>
          </>
        ) : (
          <p className="type-body text-label-2">{t('login.unsupported')}</p>
        )}
      </Rise>
    </div>
  )
}

/** Halo springs its child in over a soft accent glow, like the hero of an iOS setup screen. */
export function Halo({ children, tone = 'accent' }: { children: ReactNode; tone?: 'accent' | 'success' | 'warning' }) {
  return (
    <span className="relative inline-flex items-center justify-center">
      <motion.span
        aria-hidden
        className={cn('fh-halo pointer-events-none absolute size-[220px] rounded-full', `fh-halo-${tone}`)}
        initial={{ opacity: 0, scale: 0.6 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.9, ease: 'easeOut' }}
      />
      <motion.span className="relative inline-flex" initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} transition={spring.success}>
        {children}
      </motion.span>
    </span>
  )
}

/** Rise fades its content up a few pixels after a short delay: titles and buttons arrive in sequence. */
export function Rise({ children, delay = 0, className }: { children: ReactNode; delay?: number; className?: string }) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ ...spring.smooth, delay }}
    >
      {children}
    </motion.div>
  )
}
