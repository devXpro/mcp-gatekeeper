import type { ReactNode } from 'react'
import { cn } from '../../lib/cn'
import { TONE_BG, type Tone } from '../../lib/status'

/** StatusDot is an 8 px circle in a status colour; always next to words, so it is hidden from screen readers. */
export function StatusDot({ tone, className }: { tone: Tone; className?: string }) {
  return <span aria-hidden className={cn('inline-block size-2 shrink-0 rounded-full', TONE_BG[tone], className)} />
}

/** StatusPill is a capsule with a dot and a word (DESIGN.md §6). */
export function StatusPill({ tone, children, className }: { tone: Tone; children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full bg-fill px-2 py-1 text-[12px] leading-4 font-semibold whitespace-nowrap text-label',
        className,
      )}
    >
      <StatusDot tone={tone} />
      {children}
    </span>
  )
}
