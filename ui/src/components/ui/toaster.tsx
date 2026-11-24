import { CheckCircle2, Info, TriangleAlert } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useLayoutEffect, useRef, useSyncExternalStore } from 'react'
import { cn } from '../../lib/cn'
import { useIsDesktop } from '../../lib/hooks'
import { spring } from '../../lib/motion'
import { toastStore, type ToastTone } from '../../lib/toast'

const ICON: Record<ToastTone, { Icon: typeof Info; className: string }> = {
  success: { Icon: CheckCircle2, className: 'text-success' },
  info: { Icon: Info, className: 'text-accent' },
  warning: { Icon: TriangleAlert, className: 'text-warning' },
}

/**
 * Toaster shows toasts top-centre on phones and bottom-right on desktop. It lives in a manual popover, so it sits in
 * the top layer above open sheets; it is re-shown on every new toast to stay on top.
 */
export function Toaster() {
  const items = useSyncExternalStore(toastStore.subscribe, toastStore.getSnapshot, toastStore.getSnapshot)
  const desktop = useIsDesktop()
  const ref = useRef<HTMLDivElement>(null)
  const last = items[items.length - 1]

  useLayoutEffect(() => {
    const el = ref.current
    if (!el || !('showPopover' in el)) return
    try {
      if (el.matches(':popover-open')) el.hidePopover()
      if (items.length > 0) el.showPopover()
    } catch {
      // popover unsupported or not connected: the fixed position still works
    }
  }, [items])

  return (
    <>
      <div className="sr-only" role="status" aria-live="polite">
        {last?.text}
      </div>
      <div
        ref={ref}
        popover="manual"
        aria-hidden
        className={cn(
          'pointer-events-none fixed m-0 flex w-max max-w-[calc(100vw-32px)] flex-col gap-2 overflow-visible border-0 bg-transparent p-0',
          desktop ? 'top-auto right-6 bottom-6 left-auto items-end' : 'inset-x-0 top-[max(12px,env(safe-area-inset-top))] mx-auto items-center',
        )}
      >
        <AnimatePresence initial={false}>
          {items.map((t) => {
            const { Icon, className } = ICON[t.tone]
            return (
              <motion.div
                key={t.id}
                layout
                initial={{ opacity: 0, y: desktop ? 12 : -12, scale: 0.98 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, scale: 0.98 }}
                transition={spring.snappy}
                className="flex items-center gap-2 rounded-full bg-dialog py-2.5 pr-4 pl-3 shadow-[var(--shadow-toast)] ring-[0.5px] ring-separator"
              >
                <Icon aria-hidden className={cn('size-5 shrink-0', className)} />
                <span className="truncate type-subheadline font-medium text-label">{t.text}</span>
              </motion.div>
            )
          })}
        </AnimatePresence>
      </div>
    </>
  )
}
