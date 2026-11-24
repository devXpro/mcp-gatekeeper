import { Bot, Globe, MessageSquare, Sparkles, type LucideIcon } from 'lucide-react'
import { cn } from '../lib/cn'

// An assistant's icon: a neutral glyph on a tile colour; no brand artwork is bundled. ChatGPT Sites with a legacy key
// get a globe.

const LOOK: Record<string, { icon: LucideIcon; bg: string }> = {
  chatgpt: { icon: Bot, bg: 'bg-tile-green' },
  claude: { icon: Sparkles, bg: 'bg-tile-orange' },
  // a ChatGPT Site that still calls the legacy REST door with its own key
  site: { icon: Globe, bg: 'bg-tile-teal' },
}

const SIZE = {
  sm: { box: 'size-[30px] rounded-sm', glyph: 'size-[18px]', stroke: 2 },
  md: { box: 'size-11 rounded-md', glyph: 'size-[26px]', stroke: 2 },
  lg: { box: 'size-16 rounded-lg', glyph: 'size-9', stroke: 1.75 },
} as const

/** AssistantTile is an assistant's icon on its tile colour (gray for anything unknown). */
export function AssistantTile({ assistant, size = 'md', className }: { assistant: string; size?: keyof typeof SIZE; className?: string }) {
  const look = LOOK[assistant] ?? { icon: MessageSquare, bg: 'bg-tile-gray' }
  const s = SIZE[size]
  const Icon = look.icon
  return (
    <span aria-hidden className={cn('inline-flex shrink-0 items-center justify-center text-white', s.box, look.bg, className)}>
      <Icon className={s.glyph} strokeWidth={s.stroke} />
    </span>
  )
}
