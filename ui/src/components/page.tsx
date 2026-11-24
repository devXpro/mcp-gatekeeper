import { ChevronLeft } from 'lucide-react'
import { motion, useMotionValue, useScroll, useTransform, type MotionValue } from 'motion/react'
import { createContext, useContext, useEffect, useRef, type ReactNode, type RefObject } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router'
import { DirectionContext } from '../features/shell/direction'
import { previousIs } from '../features/shell/navstack'
import { cn } from '../lib/cn'
import { pageVariants } from '../lib/motion'

// Page = the nav bar (back, inline title, one trailing button) + the large title + the content column
// (DESIGN.md §5.2, §5.3). The inline title fades in while the large title slides under the bar: driven by the
// scroll position, not by time.

const TitleRefContext = createContext<RefObject<HTMLElement | null> | null>(null)

/** usePageTitleRef lets a custom page header register its title, so the nav bar knows when it scrolled away. */
export function usePageTitleRef() {
  return useContext(TitleRefContext)
}

export interface BackTo {
  to: string
  label: string
}

export function BackButton({ back, labelOpacity }: { back: BackTo; labelOpacity?: MotionValue<number> }) {
  const navigate = useNavigate()
  const { t } = useTranslation()
  return (
    <button
      type="button"
      onClick={() => (previousIs(back.to) ? navigate(-1) : navigate(back.to))}
      className="-ml-2 inline-flex h-11 max-w-[42vw] min-w-11 items-center gap-0.5 rounded-md pr-2 text-accent-text hover:opacity-75 lg:max-w-[16rem]"
      aria-label={`${t('nav.back')}: ${back.label}`}
    >
      <ChevronLeft aria-hidden className="size-7 shrink-0" strokeWidth={2.2} />
      <motion.span style={{ opacity: labelOpacity }} className="truncate type-body">
        {back.label}
      </motion.span>
    </button>
  )
}

export function Page({
  title,
  back,
  trailing,
  children,
  largeTitle = true,
  className,
}: {
  title: string
  back?: BackTo
  trailing?: ReactNode
  children: ReactNode
  /** false when the page brings its own header and registers its title with usePageTitleRef */
  largeTitle?: boolean
  className?: string
}) {
  const dir = useContext(DirectionContext)
  const titleRef = useRef<HTMLElement>(null)
  const barRef = useRef<HTMLDivElement>(null)
  const { scrollY } = useScroll()
  const inline = useMotionValue(0)
  // On phones the back title gives way to the inline title (they would collide); wider bars keep both.
  const backLabel = useMotionValue(1)
  const hairline = useTransform(scrollY, [0, 8], [0, 1])

  useEffect(() => {
    const update = () => {
      const title = titleRef.current
      const bar = barRef.current
      if (!title || !bar) {
        inline.set(0)
        backLabel.set(1)
        return
      }
      const gap = bar.getBoundingClientRect().bottom - title.getBoundingClientRect().bottom
      const v = Math.min(1, Math.max(0, (gap + 8) / 14))
      inline.set(v)
      backLabel.set(window.innerWidth < 768 ? 1 - v : 1)
    }
    update()
    const off = scrollY.on('change', update)
    window.addEventListener('resize', update)
    return () => {
      off()
      window.removeEventListener('resize', update)
    }
  }, [scrollY, inline, backLabel])

  return (
    <TitleRefContext.Provider value={titleRef}>
      <header className="fixed inset-x-0 top-0 z-30 lg:left-[var(--sidebar-w)]">
        {/* Transparent at rest, material once content scrolls under it (iOS scroll-edge appearance). */}
        <motion.div aria-hidden style={{ opacity: hairline }} className="material absolute inset-0" />
        <div ref={barRef} className="relative pt-[env(safe-area-inset-top)]">
          <div className="relative mx-auto flex h-11 max-w-[calc(720px+2*var(--gutter))] items-center gap-2 gutter-x">
            <div className="flex min-w-0 flex-1 justify-start">{back && <BackButton back={back} labelOpacity={backLabel} />}</div>
            <motion.div
              aria-hidden
              style={{ opacity: inline }}
              className="pointer-events-none absolute inset-x-[28%] truncate text-center type-headline"
            >
              {title}
            </motion.div>
            <div className="flex min-w-0 flex-1 justify-end">{trailing}</div>
          </div>
        </div>
        <motion.div aria-hidden style={{ opacity: hairline }} className="relative hairline-b" />
      </header>
      <motion.main
        id="main"
        custom={dir}
        variants={pageVariants}
        className={cn(
          'gutter-x pt-[calc(44px+env(safe-area-inset-top))] pb-[calc(var(--tab-h)+env(safe-area-inset-bottom)+48px)] lg:pb-16',
          className,
        )}
      >
        <div className="mx-auto max-w-[720px]">
          {largeTitle && (
            <h1 ref={titleRef as RefObject<HTMLHeadingElement>} className="truncate pt-1 pb-5 type-large-title lg:pt-5">
              {title}
            </h1>
          )}
          {children}
        </div>
      </motion.main>
    </TitleRefContext.Provider>
  )
}
