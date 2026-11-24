import { createContext } from 'react'
import type { Direction } from '../../lib/motion'

/** DirectionContext tells a page how it was reached, for its slide-in. */
export const DirectionContext = createContext<Direction>('tab')
