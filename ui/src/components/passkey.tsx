import { Fingerprint, KeyRound, ScanFace, type LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import { passkeyKind, type PasskeyKind } from '../lib/platform'
import { Button } from './ui/button'

const GLYPH: Record<PasskeyKind, LucideIcon> = { faceid: ScanFace, touchid: Fingerprint, passkey: KeyRound }

/** PasskeyGlyph is the platform's sign-in glyph (DESIGN.md §3.6). */
export function PasskeyGlyph({ className, kind = passkeyKind() }: { className?: string; kind?: PasskeyKind }) {
  const Icon = GLYPH[kind]
  return <Icon aria-hidden className={className} strokeWidth={1.75} />
}

/** PasskeyButton is the filled large button with the platform glyph (DESIGN.md §6). */
export function PasskeyButton({
  children,
  loading,
  disabled,
  onClick,
  autoFocus,
}: {
  children: ReactNode
  loading?: boolean
  disabled?: boolean
  onClick: () => void
  autoFocus?: boolean
}) {
  return (
    <Button
      variant="filled"
      size="lg"
      loading={loading}
      disabled={disabled}
      onClick={onClick}
      data-autofocus={autoFocus || undefined}
      icon={<PasskeyGlyph className="size-[22px]" />}
    >
      {children}
    </Button>
  )
}
