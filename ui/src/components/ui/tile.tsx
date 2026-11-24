import { Blocks, type LucideIcon } from 'lucide-react'
import { brand } from '../../config'
import { cn } from '../../lib/cn'
import { tileColor, type TileColor } from '../../lib/tiles'

export type { TileColor }

const TILE_BG: Record<TileColor, string> = {
  blue: 'bg-tile-blue',
  indigo: 'bg-tile-indigo',
  purple: 'bg-tile-purple',
  pink: 'bg-tile-pink',
  orange: 'bg-tile-orange',
  teal: 'bg-tile-teal',
  green: 'bg-tile-green',
  gray: 'bg-tile-gray',
  red: 'bg-danger',
}

/** IconTile is a white glyph on a coloured squircle, like iOS Settings (30 px, radius 8). */
export function IconTile({ icon: Icon, color, className }: { icon: LucideIcon; color: TileColor; className?: string }) {
  return (
    <span
      aria-hidden
      className={cn('inline-flex size-[30px] shrink-0 items-center justify-center rounded-sm text-white', TILE_BG[color], className)}
    >
      <Icon className="size-[18px]" strokeWidth={2} />
    </span>
  )
}

const RESOURCE_SIZE = {
  sm: { box: 'size-[30px] rounded-sm', glyph: 'size-[18px]', stroke: 2 },
  md: { box: 'size-11 rounded-md', glyph: 'size-[26px]', stroke: 2 },
  lg: { box: 'size-16 rounded-lg', glyph: 'size-9', stroke: 1.75 },
} as const

/**
 * ResourceTile is a resource's icon: 30 px in rows, 44 px in lists, 64 px in headers. Without a glyph and a colour it
 * is a block on a colour picked from the id; an application passes its own look (Family Hub: ModuleTile by module id).
 */
export function ResourceTile({
  id,
  size = 'md',
  className,
  icon: Icon = Blocks,
  color = tileColor(id),
}: {
  id: string
  size?: keyof typeof RESOURCE_SIZE
  className?: string
  icon?: LucideIcon
  color?: TileColor
}) {
  const s = RESOURCE_SIZE[size]
  return (
    <span aria-hidden className={cn('inline-flex shrink-0 items-center justify-center text-white', s.box, TILE_BG[color], className)}>
      <Icon className={s.glyph} strokeWidth={s.stroke} />
    </span>
  )
}

/** AppIcon is the application's icon: a blue-to-indigo squircle with the brand's white glyph (DESIGN.md §6). */
export function AppIcon({ size = 72, className }: { size?: number; className?: string }) {
  const Glyph = brand().icon
  return (
    <span
      aria-hidden
      className={cn(
        'inline-flex shrink-0 items-center justify-center bg-linear-135 from-tile-blue to-tile-indigo text-white',
        className,
      )}
      style={{ width: size, height: size, borderRadius: size * 0.22 }}
    >
      <Glyph style={{ width: size * 0.52, height: size * 0.52 }} strokeWidth={size >= 48 ? 1.9 : 2.2} />
    </span>
  )
}

/** Avatar is a person's initials on a tile colour picked from their id (DESIGN.md §6). */
export function Avatar({ id, name, size = 40, className }: { id: string; name: string; size?: number; className?: string }) {
  const letters = name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase())
    .join('')
  return (
    <span
      aria-hidden
      className={cn('inline-flex shrink-0 items-center justify-center rounded-full font-semibold text-white', TILE_BG[tileColor(id)], className)}
      style={{ width: size, height: size, fontSize: Math.round(size * 0.4) }}
    >
      {letters || '?'}
    </span>
  )
}
