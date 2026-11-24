import { Check, Copy } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { copyText } from '../../lib/clipboard'
import { cn } from '../../lib/cn'

/** useCopy copies and flips its icon to a check for 1.5 s. */
function useCopy() {
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return
    const id = setTimeout(() => setCopied(false), 1500)
    return () => clearTimeout(id)
  }, [copied])
  const copy = async (text: string) => {
    const ok = await copyText(text)
    if (ok) setCopied(true)
    return ok
  }
  return { copied, copy }
}

/**
 * breakable offers a line break after every slash, so an address wraps between its parts, not inside them. (No
 * lookbehind regex: iOS before 16.4 cannot even parse one.)
 */
function breakable(value: string) {
  const parts: string[] = []
  let cur = ''
  for (const ch of value) {
    cur += ch
    if (ch === '/') {
      parts.push(cur)
      cur = ''
    }
  }
  if (cur) parts.push(cur)
  return parts.map((part, i) => (
    <span key={i}>
      {part}
      {i < parts.length - 1 && <wbr />}
    </span>
  ))
}

/** CopyField is a monospace value in a --fill box with "Скопировать" (DESIGN.md §6). */
export function CopyField({
  value,
  label,
  onCopied,
  className,
}: {
  value: string
  label?: string
  onCopied?: () => void
  className?: string
}) {
  const { t } = useTranslation()
  const { copied, copy } = useCopy()
  return (
    <div className={cn('flex items-center gap-2 rounded-md bg-fill py-1.5 pr-1.5 pl-3.5', className)}>
      <code aria-label={label} className="min-w-0 flex-1 font-mono text-[14px] leading-5 [overflow-wrap:anywhere] text-label select-all">
        {breakable(value)}
      </code>
      <button
        type="button"
        onClick={async () => {
          if (await copy(value)) onCopied?.()
        }}
        className="inline-flex h-9 shrink-0 items-center gap-1.5 rounded-full bg-accent-tint px-3 text-[14px] font-semibold text-accent-tinted"
      >
        {copied ? <Check aria-hidden className="size-4" strokeWidth={2.5} /> : <Copy aria-hidden className="size-4" />}
        <span aria-live="polite">{copied ? t('common.copied') : t('common.copy')}</span>
      </button>
    </div>
  )
}
