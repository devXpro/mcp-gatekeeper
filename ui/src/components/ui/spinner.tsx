import { cn } from '../../lib/cn'

/** Spinner is the iOS activity indicator: 8 spokes turning in steps (DESIGN.md §6). */
export function Spinner({ size = 'md', className, label }: { size?: 'sm' | 'md' | 'lg'; className?: string; label?: string }) {
  const px = size === 'lg' ? 28 : size === 'md' ? 20 : 16
  return (
    <svg
      width={px}
      height={px}
      viewBox="0 0 24 24"
      className={cn('fh-spinner shrink-0 text-label-2', className)}
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    >
      {Array.from({ length: 8 }, (_, i) => (
        <line
          key={i}
          x1="12"
          y1="2.5"
          x2="12"
          y2="7"
          stroke="currentColor"
          strokeWidth="2.4"
          strokeLinecap="round"
          opacity={0.25 + (i / 8) * 0.75}
          transform={`rotate(${i * 45} 12 12)`}
        />
      ))}
    </svg>
  )
}
