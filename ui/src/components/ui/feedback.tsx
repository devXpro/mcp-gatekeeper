import { CheckCircle2, Circle, TriangleAlert, XCircle, type LucideIcon } from 'lucide-react'
import { motion } from 'motion/react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '../../lib/cn'
import { spring } from '../../lib/motion'
import { Button } from './button'
import { Spinner } from './spinner'

/** Skeleton is a --fill block the exact size of the content it stands for (no layout shift). */
export function Skeleton({ className }: { className?: string }) {
  return <span aria-hidden className={cn('fh-skeleton block rounded-xs', className)} />
}

/**
 * SkeletonRows stands in for a grouped list while it loads. Each line is a real line box of the row's type (a
 * no-break space sets its height), so the rows are exactly as tall as the ones that replace them: no layout shift.
 */
export function SkeletonRows({
  rows = 3,
  subtitle = true,
  icon = true,
  bare,
}: {
  rows?: number
  subtitle?: boolean
  icon?: boolean
  /** without the card, for use inside an existing Section */
  bare?: boolean
}) {
  return (
    <div aria-hidden className={cn(!bare && 'overflow-hidden rounded-lg bg-surface-1')}>
      {Array.from({ length: rows }, (_, i) => (
        <div
          key={i}
          className={cn('fh-row flex items-center gap-3 px-4', subtitle ? 'min-h-[60px] py-2.5' : 'min-h-11 py-[11px]', icon && '[--row-inset:60px]')}
        >
          {icon && <Skeleton className="size-[30px] rounded-sm" />}
          <span className="flex flex-1 flex-col">
            <span className="flex items-center type-body">
              <Skeleton className="h-3.5 w-2/5" />
              {' '}
            </span>
            {subtitle && (
              <span className="flex items-center type-subheadline">
                <Skeleton className="h-3 w-3/5" />
                {' '}
              </span>
            )}
          </span>
        </div>
      ))}
    </div>
  )
}

export function EmptyState({
  icon: Icon,
  iconClassName,
  title,
  text,
  action,
  compact,
  className,
}: {
  icon: LucideIcon
  iconClassName?: string
  title: ReactNode
  text?: ReactNode
  action?: ReactNode
  compact?: boolean
  className?: string
}) {
  return (
    <div className={cn('flex flex-col items-center text-center', compact ? 'px-6 py-8' : 'px-6 py-14', className)}>
      <span aria-hidden className="mb-4 inline-flex size-[72px] items-center justify-center rounded-full bg-fill">
        <Icon className={cn('size-8 text-label-2', iconClassName)} strokeWidth={1.75} />
      </span>
      <h2 className="type-title-3 text-balance">{title}</h2>
      {text && <p className="mt-1.5 max-w-sm type-subheadline text-balance text-label-2">{text}</p>}
      {action && <div className="mt-6 w-full max-w-xs">{action}</div>}
    </div>
  )
}

/** ErrorState is an EmptyState with the warning triangle, the error words and "Повторить" (DESIGN.md §6). */
export function ErrorState({
  title,
  text,
  onRetry,
  action,
  compact,
}: {
  title?: ReactNode
  text?: ReactNode
  onRetry?: () => void
  action?: ReactNode
  compact?: boolean
}) {
  const { t } = useTranslation()
  return (
    <EmptyState
      icon={TriangleAlert}
      iconClassName="text-warning"
      title={title ?? t('error.title')}
      text={text}
      compact={compact}
      action={
        action ??
        (onRetry && (
          <Button variant="tinted" size="lg" onClick={onRetry}>
            {t('common.retry')}
          </Button>
        ))
      }
    />
  )
}

/** ProgressBar is a 4 px pill whose value springs to its width. */
export function ProgressBar({ value, label, className }: { value: number; label?: string; className?: string }) {
  const pct = Math.max(0, Math.min(1, value)) * 100
  return (
    <div
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(pct)}
      aria-label={label}
      className={cn('h-1 w-full overflow-hidden rounded-full bg-fill', className)}
    >
      <motion.div className="h-full rounded-full bg-accent" initial={false} animate={{ width: `${pct}%` }} transition={spring.smooth} />
    </div>
  )
}

export type StepState = 'pending' | 'running' | 'done' | 'failed'

export interface StepItem {
  key: string
  label: ReactNode
  state: StepState
  detail?: ReactNode
}

/** StepList shows the steps of a job: pending, running, done, failed (DESIGN.md §6). */
export function StepList({ steps }: { steps: StepItem[] }) {
  return (
    <ol className="flex flex-col gap-4">
      {steps.map((s) => (
        <li key={s.key} className="flex gap-3" aria-current={s.state === 'running' ? 'step' : undefined}>
          <span className="mt-px flex size-[22px] shrink-0 items-center justify-center">
            {s.state === 'pending' && <Circle aria-hidden className="size-[22px] text-label-3" strokeWidth={1.75} />}
            {s.state === 'running' && <Spinner size="md" />}
            {s.state === 'done' && <CheckCircle2 aria-hidden className="size-[22px] text-success" strokeWidth={2} />}
            {s.state === 'failed' && <XCircle aria-hidden className="size-[22px] text-danger" strokeWidth={2} />}
          </span>
          <span className="flex min-w-0 flex-1 flex-col gap-2">
            <span
              className={cn(
                'type-body',
                s.state === 'pending' && 'text-label-2',
                s.state === 'failed' && 'text-danger-text',
                s.state === 'running' && 'font-semibold',
              )}
            >
              {s.label}
            </span>
            {s.detail}
          </span>
        </li>
      ))}
    </ol>
  )
}

/** SuccessCheck: a 56 px --success circle springs in, then the check draws (DESIGN.md §4). */
export function SuccessCheck({ size = 56 }: { size?: number }) {
  return (
    <motion.span
      aria-hidden
      className="inline-flex shrink-0 items-center justify-center rounded-full bg-success text-white"
      style={{ width: size, height: size }}
      initial={{ scale: 0.4, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={spring.success}
    >
      <svg viewBox="0 0 24 24" width={size * 0.5} height={size * 0.5} fill="none">
        <motion.path
          d="M5 12.5l4.5 4.5L19 7.5"
          stroke="currentColor"
          strokeWidth={2.6}
          strokeLinecap="round"
          strokeLinejoin="round"
          initial={{ pathLength: 0 }}
          animate={{ pathLength: 1 }}
          transition={{ duration: 0.3, ease: 'easeOut', delay: 0.18 }}
        />
      </svg>
    </motion.span>
  )
}
