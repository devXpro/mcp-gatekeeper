// Motion tokens (DESIGN.md §4). The app is wrapped in <MotionConfig reducedMotion="user">.

import type { Transition } from 'motion/react'

export const spring = {
  snappy: { type: 'spring', visualDuration: 0.22, bounce: 0.12 },
  smooth: { type: 'spring', visualDuration: 0.32, bounce: 0 },
  sheet: { type: 'spring', visualDuration: 0.38, bounce: 0.1 },
  success: { type: 'spring', visualDuration: 0.5, bounce: 0.35 },
} satisfies Record<string, Transition>

export const fade = {
  fast: { duration: 0.15, ease: 'easeOut' },
} satisfies Record<string, Transition>

/** How the page changed: deeper in a tab, back up, or another tab (DESIGN.md §4 Push / Tabs). */
export type Direction = 'push' | 'pop' | 'tab'

/** pageVariants slide a page's content 24 px on push and pop; the shell's wrapper does the fade. */
export const pageVariants = {
  enter: (dir: Direction) => ({ x: dir === 'push' ? 24 : dir === 'pop' ? -24 : 0 }),
  center: { x: 0, transition: spring.smooth },
  exit: { x: 0 },
}
