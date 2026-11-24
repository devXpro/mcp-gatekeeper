// Tile colours (DESIGN.md §3.1): the iOS Settings palette, and a stable pick for any id.

export type TileColor = 'blue' | 'indigo' | 'purple' | 'pink' | 'orange' | 'teal' | 'green' | 'gray' | 'red'

const PALETTE: TileColor[] = ['blue', 'indigo', 'purple', 'pink', 'orange', 'teal', 'green', 'gray']

function fnv1a(s: string) {
  let h = 0x811c9dc5
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h >>> 0
}

/** tileColor picks a stable tile colour for any id (people, families, unknown modules). */
export function tileColor(id: string): TileColor {
  return PALETTE[fnv1a(id) % PALETTE.length]
}
