import { Share } from 'lucide-react'
import { lazy, Suspense } from 'react'
import { useTranslation } from 'react-i18next'
import { useLang } from '../i18n'
import { fmtDateTime } from '../lib/format'
import { Button } from './ui/button'
import { CopyField } from './ui/copy'
import { Skeleton } from './ui/feedback'

// An invite link, shown once after it is made (DESIGN.md §8.5.1): a QR code to scan with the other phone, the link
// to copy, and the system share sheet where there is one. The QR library loads only here.

const QRCodeView = lazy(() => import('./qrcode').then((m) => ({ default: m.QRCodeView })))

export function InviteLink({ url, expiresAt, shareText }: { url: string; expiresAt: string; shareText: string }) {
  const { t } = useTranslation()
  const lang = useLang()
  const canShare = typeof navigator !== 'undefined' && typeof navigator.share === 'function'
  return (
    <div className="flex flex-col items-center">
      <Suspense fallback={<Skeleton className="size-[216px] rounded-lg" />}>
        <QRCodeView value={url} size={200} label={t('invite.qr')} />
      </Suspense>
      <CopyField value={url} label={t('invite.link')} className="mt-5 w-full" />
      {canShare && (
        <Button
          className="mt-3 w-full"
          variant="tinted"
          size="md"
          icon={<Share aria-hidden className="size-5" />}
          onClick={() => void navigator.share({ title: t('app.name'), text: shareText, url }).catch(() => undefined)}
        >
          {t('invite.share')}
        </Button>
      )}
      <p className="mt-3 px-1 text-center type-footnote text-label-2">{t('invite.footnote', { time: fmtDateTime(expiresAt, lang) })}</p>
    </div>
  )
}
