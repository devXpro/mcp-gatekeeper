import { X } from 'lucide-react'
import {
  AnimatePresence,
  motion,
  useDragControls,
  useIsPresent,
  useMotionValue,
  type MotionValue,
} from 'motion/react'
import { createContext, useContext, useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode, type RefObject } from 'react'
import { createPortal } from 'react-dom'
import { useTranslation } from 'react-i18next'
import { cn } from '../../lib/cn'
import { useIsPhone } from '../../lib/hooks'
import { fade, spring } from '../../lib/motion'
import { SurfaceContext } from './surface'

const FooterContext = createContext<HTMLDivElement | null>(null)

/** SheetFooter puts its buttons in the sheet's bottom bar (sticky, above the safe area), from anywhere inside. */
export function SheetFooter({ children }: { children: ReactNode }) {
  const el = useContext(FooterContext)
  return el ? createPortal(children, el) : null
}

// Sheets and dialogs (DESIGN.md §4, §6) are built on the native <dialog> shown with showModal(): the browser puts it
// in the top layer, makes the page behind it inert, traps focus and sends Escape as "cancel". Nothing injects a
// <style> element, so the strict CSP holds (vaul and Radix Dialog would). Motion animates the panel and the scrim.

/** useModalDialog opens the dialog on mount, moves focus in, and gives it back on unmount. */
function useModalDialog(ref: RefObject<HTMLDialogElement | null>, focusRoot: RefObject<HTMLElement | null>) {
  useLayoutEffect(() => {
    const dialog = ref.current
    if (!dialog) return
    const before = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const show = () => {
      if (!dialog.isConnected) return
      if (!dialog.open) {
        try {
          dialog.showModal()
        } catch {
          dialog.setAttribute('open', '')
        }
      }
      const target = focusRoot.current?.querySelector<HTMLElement>('[data-autofocus]') ?? focusRoot.current
      target?.focus({ preventScroll: true })
    }
    // Children's layout effects run before their parent's: a dialog nested in a sheet that opens in the same commit
    // (a confirmation shown at once) waits for the sheet, so it lands above it in the top layer.
    const parent = dialog.parentElement?.closest('dialog')
    if (parent && !parent.open) queueMicrotask(show)
    else show()
    return () => {
      // Browsers without <dialog> (old Safari, jsdom) got the attribute instead of showModal(): undo it the same way.
      if (dialog.open) {
        if (typeof dialog.close === 'function') dialog.close()
        else dialog.removeAttribute('open')
      }
      if (before && before.isConnected) before.focus({ preventScroll: true })
    }
  }, [ref, focusRoot])
}

/** useKeyboardInset follows the on-screen keyboard on phones so a bottom sheet stays above it. */
function useKeyboardInset(): MotionValue<number> {
  const inset = useMotionValue(0)
  useEffect(() => {
    const vv = window.visualViewport
    if (!vv) return
    const update = () => inset.set(Math.max(0, window.innerHeight - vv.height - vv.offsetTop))
    vv.addEventListener('resize', update)
    vv.addEventListener('scroll', update)
    return () => {
      vv.removeEventListener('resize', update)
      vv.removeEventListener('scroll', update)
    }
  }, [inset])
  return inset
}

export interface SheetProps {
  open: boolean
  onClose: () => void
  title?: ReactNode
  /** "large": title-2 on the left (forms); "small": headline centred (small sheets) */
  titleVariant?: 'large' | 'small'
  /** a title for screen readers only, when the content brings its own heading */
  hiddenTitle?: boolean
  size?: 'form' | 'alert'
  footer?: ReactNode
  children?: ReactNode
  /** false while something must finish first: no drag, no scrim tap, no Escape */
  dismissible?: boolean
  className?: string
}

/** Sheet is a bottom drawer on phones and a centred dialog from 768 px. */
export function Sheet(props: SheetProps) {
  return <AnimatePresence>{props.open && <SheetDialog {...props} />}</AnimatePresence>
}

function SheetDialog({
  onClose,
  title,
  titleVariant = 'large',
  hiddenTitle,
  size = 'form',
  footer,
  children,
  dismissible = true,
  className,
}: SheetProps) {
  const { t } = useTranslation()
  const ref = useRef<HTMLDialogElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const phone = useIsPhone()
  const present = useIsPresent()
  const controls = useDragControls()
  const keyboard = useKeyboardInset()
  const titleId = useId()
  const [footerEl, setFooterEl] = useState<HTMLDivElement | null>(null)
  useModalDialog(ref, panelRef)

  const close = () => {
    if (dismissible && present) onClose()
  }

  const header = (
    <div
      className={cn('relative shrink-0 select-none', phone && dismissible && 'cursor-grab touch-none')}
      onPointerDown={phone && dismissible ? (e) => controls.start(e) : undefined}
    >
      {phone && <span aria-hidden className="mx-auto mt-1.5 block h-[5px] w-9 rounded-full bg-label-3" />}
      <div
        className={cn(
          'flex items-start gap-3 px-4',
          phone ? 'pt-2.5' : 'pt-4',
          hiddenTitle ? 'min-h-11 pb-0' : 'pb-3',
          titleVariant === 'small' && 'justify-center text-center',
        )}
      >
        <h2
          id={titleId}
          className={cn(
            hiddenTitle && 'sr-only',
            titleVariant === 'large' ? 'flex-1 pt-1 type-title-2' : 'px-10 pt-1.5 type-headline',
          )}
        >
          {title}
        </h2>
        <button
          type="button"
          onClick={close}
          disabled={!dismissible}
          aria-label={t('common.close')}
          className={cn(
            'inline-flex size-[30px] shrink-0 items-center justify-center rounded-full bg-fill text-label-2 transition-opacity hover:opacity-80 disabled:opacity-30',
            titleVariant === 'small' || hiddenTitle ? 'absolute top-auto right-4' : 'mt-0.5',
          )}
        >
          <X className="size-[18px]" strokeWidth={2.5} aria-hidden />
        </button>
      </div>
    </div>
  )

  const body = (
    <SurfaceContext.Provider value="sheet">
      <FooterContext.Provider value={footerEl}>
        {header}
        <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-4 pb-4 [&:has(+div:empty)]:pb-[max(16px,env(safe-area-inset-bottom))]">
          {children}
        </div>
        <div ref={setFooterEl} className="flex shrink-0 flex-col gap-2 px-4 pt-2 pb-[max(16px,env(safe-area-inset-bottom))] empty:hidden">
          {footer}
        </div>
      </FooterContext.Provider>
    </SurfaceContext.Provider>
  )

  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      onCancel={(e) => {
        e.preventDefault()
        close()
      }}
      className="fixed inset-0 z-50"
    >
      <motion.div
        aria-hidden
        className="fixed inset-0 bg-scrim"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={fade.fast}
        onClick={close}
      />
      {phone ? (
        <motion.div
          ref={panelRef}
          tabIndex={-1}
          className={cn(
            'fixed inset-x-0 flex max-h-[92dvh] flex-col rounded-t-xl bg-sheet shadow-[var(--shadow-sheet)] outline-none',
            className,
          )}
          style={{ bottom: keyboard }}
          initial={{ y: '100%' }}
          animate={{ y: 0 }}
          exit={{ y: '100%' }}
          transition={spring.sheet}
          drag={dismissible ? 'y' : false}
          dragListener={false}
          dragControls={controls}
          dragConstraints={{ top: 0, bottom: 0 }}
          dragElastic={{ top: 0, bottom: 0.9 }}
          onDragEnd={(_, info) => {
            const h = panelRef.current?.offsetHeight ?? 600
            if (info.offset.y > h * 0.3 || info.velocity.y > 500) close()
          }}
        >
          {body}
        </motion.div>
      ) : (
        <div className="pointer-events-none fixed inset-0 flex items-center justify-center p-6">
          <motion.div
            ref={panelRef}
            tabIndex={-1}
            className={cn(
              'pointer-events-auto flex max-h-[85dvh] w-full flex-col overflow-hidden rounded-xl bg-sheet shadow-[var(--shadow-sheet)] outline-none',
              size === 'alert' ? 'max-w-[360px]' : 'max-w-[480px]',
              className,
            )}
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.96 }}
            transition={spring.sheet}
          >
            {body}
          </motion.div>
        </div>
      )}
    </dialog>
  )
}

export interface ConfirmProps {
  open: boolean
  title: ReactNode
  text?: ReactNode
  action: ReactNode
  destructive?: boolean
  onConfirm: () => void
  onCancel: () => void
}

/** ActionSheet confirms a destructive action: a bottom action sheet on phones, a small alert on desktop. */
export function ActionSheet(props: ConfirmProps) {
  return <AnimatePresence>{props.open && <ActionSheetDialog {...props} />}</AnimatePresence>
}

function ActionSheetDialog({ title, text, action, destructive = true, onConfirm, onCancel }: ConfirmProps) {
  const { t } = useTranslation()
  const ref = useRef<HTMLDialogElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const phone = useIsPhone()
  const present = useIsPresent()
  const titleId = useId()
  const textId = useId()
  useModalDialog(ref, panelRef)
  const cancel = () => present && onCancel()
  const confirm = () => present && onConfirm()

  return (
    <dialog
      ref={ref}
      role="alertdialog"
      aria-labelledby={titleId}
      aria-describedby={text ? textId : undefined}
      onCancel={(e) => {
        e.preventDefault()
        cancel()
      }}
      className="fixed inset-0 z-50"
    >
      <motion.div
        aria-hidden
        className="fixed inset-0 bg-scrim"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={fade.fast}
        onClick={cancel}
      />
      {phone ? (
        <motion.div
          ref={panelRef}
          tabIndex={-1}
          className="fixed inset-x-0 bottom-0 px-2 pb-[max(8px,env(safe-area-inset-bottom))] outline-none"
          initial={{ y: '100%' }}
          animate={{ y: 0 }}
          exit={{ y: '100%' }}
          transition={spring.sheet}
        >
          <div className="overflow-hidden rounded-[14px] bg-dialog text-center">
            <div className="px-4 py-3.5">
              <h2 id={titleId} className="type-footnote font-semibold text-label-2">
                {title}
              </h2>
              {text && (
                <p id={textId} className="mt-1 type-footnote text-label-2">
                  {text}
                </p>
              )}
            </div>
            <button
              type="button"
              onClick={confirm}
              data-autofocus
              className={cn(
                'h-[57px] w-full hairline-t text-[20px] leading-6 active:bg-sheet-pressed',
                destructive ? 'text-danger-text' : 'text-accent-text',
              )}
            >
              {action}
            </button>
          </div>
          <button
            type="button"
            onClick={cancel}
            className="mt-2 h-[57px] w-full rounded-[14px] bg-dialog text-[20px] leading-6 font-semibold text-accent-text active:bg-sheet-pressed"
          >
            {t('common.cancel')}
          </button>
        </motion.div>
      ) : (
        <div className="pointer-events-none fixed inset-0 flex items-center justify-center p-6">
          <motion.div
            ref={panelRef}
            tabIndex={-1}
            className="pointer-events-auto w-full max-w-[360px] rounded-xl bg-dialog p-5 shadow-[var(--shadow-sheet)] outline-none"
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.96 }}
            transition={spring.sheet}
          >
            <h2 id={titleId} className="type-headline">
              {title}
            </h2>
            {text && (
              <p id={textId} className="mt-1.5 type-footnote text-label-2">
                {text}
              </p>
            )}
            <div className="mt-5 flex justify-end gap-2">
              <button
                type="button"
                onClick={cancel}
                data-autofocus
                className="h-9 rounded-full bg-fill px-4 text-[14px] font-semibold text-label hover:brightness-110"
              >
                {t('common.cancel')}
              </button>
              <button
                type="button"
                onClick={confirm}
                className={cn(
                  'h-9 rounded-full px-4 text-[14px] font-semibold text-white hover:brightness-110',
                  destructive ? 'bg-danger-fill' : 'bg-accent-fill',
                )}
              >
                {action}
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </dialog>
  )
}
