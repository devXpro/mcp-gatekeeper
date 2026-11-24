import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Fingerprint, KeyRound, Plus, ScanFace } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Page } from '../../components/page'
import { Button } from '../../components/ui/button'
import { TextField } from '../../components/ui/controls'
import { ErrorState, SkeletonRows } from '../../components/ui/feedback'
import { Row, Section } from '../../components/ui/list'
import { ActionSheet, Sheet, SheetFooter } from '../../components/ui/sheet'
import { Spinner } from '../../components/ui/spinner'
import { IconTile } from '../../components/ui/tile'
import { useStepUp } from '../auth/stepup'
import { useLang } from '../../i18n'
import { api, isApiError, seg } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { fmtDate, fmtRelative } from '../../lib/format'
import { useDelayed, useNow, useSticky } from '../../lib/hooks'
import { ceremonyError, createCredential } from '../../lib/passkeys'
import { qk, usePasskeys } from '../../lib/queries'
import { toast } from '../../lib/toast'
import type { Begin, Passkey } from '../../lib/types'

// Ключи входа (docs/PLAN.md §5.9 "Passkeys", DESIGN.md §8.5.2): rename, remove (step-up, never the last one), add one
// more for another device, and sign out every other device (docs/reviews/T2.R.md M3: removing a passkey does that too).

function glyphFor(name: string) {
  if (/iphone|ipad/i.test(name)) return ScanFace
  if (/mac/i.test(name)) return Fingerprint
  return KeyRound
}

export function PasskeysPage() {
  const { t } = useTranslation()
  const lang = useLang()
  const qc = useQueryClient()
  const { withStepUp } = useStepUp()
  const passkeys = usePasskeys()
  const now = useNow()
  const showSkeleton = useDelayed(passkeys.isPending)
  const [open, setOpen] = useState<Passkey | null>(null)
  const [adding, setAdding] = useState(false)
  const [signingOut, setSigningOut] = useState(false)
  const [confirmSignOut, setConfirmSignOut] = useState(false)
  const items = passkeys.data ?? []

  // POST /api/me/sessions/revoke (T2.F2): every other session of the person ends; this browser gets a fresh cookie.
  const signOutOthers = async () => {
    setConfirmSignOut(false)
    setSigningOut(true)
    try {
      const done = await withStepUp(async () => {
        await api.post('/me/sessions/revoke', {})
        return true
      }, t('stepup.action.sessions_revoke'))
      if (done) toast(t('sessions.done'))
    } catch (err) {
      toast(errorText(err, t), 'warning')
    } finally {
      setSigningOut(false)
    }
  }

  const add = async () => {
    setAdding(true)
    try {
      const begin = await withStepUp(() => api.post<Begin>('/me/passkeys/begin', {}), t('stepup.action.passkey_add'))
      if (!begin) return
      const credential = await createCredential(begin.options)
      // A slow ceremony can outlive a step-up window: finish then asks again and is retried.
      const done = await withStepUp(() => api.post<unknown>('/me/passkeys/finish', { credential }).then(() => true), t('stepup.action.passkey_add'))
      if (!done) return
      await qc.invalidateQueries({ queryKey: qk.passkeys })
      toast(t('passkeys.added'))
    } catch (err) {
      if (isApiError(err) || ceremonyError(err) !== 'cancelled') {
        toast(isApiError(err) ? errorText(err, t) : ceremonyError(err) === 'exists' ? t('passkeys.exists') : t('stepup.failed'), 'warning')
      }
    } finally {
      setAdding(false)
    }
  }

  return (
    <Page title={t('passkeys.title')} back={{ to: '/account', label: t('tab.account') }}>
      {passkeys.error && !passkeys.data ? (
        <ErrorState text={errorText(passkeys.error, t)} onRetry={() => void passkeys.refetch()} />
      ) : !passkeys.data ? (
        showSkeleton && <SkeletonRows rows={2} />
      ) : (
        <>
          <Section footer={t('passkeys.footer')}>
            {items.map((pk) => (
              <Row
                key={pk.id}
                onClick={() => setOpen(pk)}
                iconInset
                leading={<IconTile icon={glyphFor(pk.name)} color="gray" />}
                title={pk.name}
                subtitle={
                  pk.last_used_at
                    ? t('passkeys.meta', { date: fmtDate(pk.created_at, lang), time: fmtRelative(pk.last_used_at, lang, now) })
                    : t('passkeys.meta_new', { date: fmtDate(pk.created_at, lang) })
                }
                chevron
              />
            ))}
          </Section>
          <Button className="mt-6 w-full" variant="tinted" size="md" loading={adding} onClick={() => void add()} icon={<Plus aria-hidden className="size-5" />}>
            {t('passkeys.add')}
          </Button>
          <Section footer={t('sessions.footer')}>
            <Row
              onClick={() => setConfirmSignOut(true)}
              disabled={signingOut}
              title={
                <span className="inline-flex items-center gap-2">
                  {signingOut && <Spinner size="sm" />}
                  {t('sessions.revoke')}
                </span>
              }
              destructive
              centered
            />
          </Section>
        </>
      )}
      <PasskeySheet passkey={open} only={items.length <= 1} onClose={() => setOpen(null)} />
      <ActionSheet
        open={confirmSignOut}
        title={t('sessions.confirm')}
        text={t('sessions.confirm.text')}
        action={t('sessions.confirm.action')}
        onConfirm={() => void signOutOthers()}
        onCancel={() => setConfirmSignOut(false)}
      />
    </Page>
  )
}

function PasskeySheet({ passkey, only, onClose }: { passkey: Passkey | null; only: boolean; onClose: () => void }) {
  const shown = useSticky(passkey)
  return (
    <Sheet open={!!passkey} onClose={onClose} title={shown?.name ?? ''}>
      {shown && <PasskeyForm key={shown.id} passkey={shown} only={only} onDone={onClose} />}
    </Sheet>
  )
}

function PasskeyForm({ passkey, only, onDone }: { passkey: Passkey; only: boolean; onDone: () => void }) {
  const { t } = useTranslation()
  const qc = useQueryClient()
  const { withStepUp } = useStepUp()
  const [name, setName] = useState(passkey.name)
  const [confirm, setConfirm] = useState(false)
  const rename = useMutation({
    mutationFn: () => api.patch<Passkey | undefined>(`/me/passkeys/${seg(passkey.id)}`, { name: name.trim() }),
    onSuccess: () => {
      qc.setQueryData<Passkey[]>(qk.passkeys, (l) => l?.map((x) => (x.id === passkey.id ? { ...x, name: name.trim() } : x)))
      toast(t('common.saved'))
      onDone()
    },
    onError: (err) => toast(errorText(err, t), 'warning'),
  })
  const remove = async () => {
    setConfirm(false)
    try {
      const done = await withStepUp(async () => {
        await api.del(`/me/passkeys/${seg(passkey.id)}`)
        return true
      }, t('stepup.action.passkey_remove'))
      if (!done) return
      qc.setQueryData<Passkey[]>(qk.passkeys, (l) => l?.filter((x) => x.id !== passkey.id))
      toast(t('passkeys.removed'))
      onDone()
    } catch (err) {
      toast(errorText(err, t), 'warning')
    }
  }
  return (
    <form
      id="passkey-form"
      onSubmit={(e) => {
        e.preventDefault()
        if (name.trim()) rename.mutate()
      }}
    >
      <TextField label={t('passkeys.name')} value={name} onChange={(e) => setName(e.target.value)} maxLength={40} autoComplete="off" />
      <div className="mt-6">
        <Button variant="destructive" size="md" className="w-full" disabled={only} onClick={() => setConfirm(true)}>
          {t('common.delete')}
        </Button>
        {only && <p className="mt-2 px-1 type-footnote text-label-2">{t('passkeys.last')}</p>}
      </div>
      <SheetFooter>
        <Button type="submit" form="passkey-form" variant="filled" size="lg" loading={rename.isPending} disabled={!name.trim() || name.trim() === passkey.name}>
          {t('common.save')}
        </Button>
      </SheetFooter>
      <ActionSheet
        open={confirm}
        title={t('passkeys.remove.confirm', { name: passkey.name })}
        text={t('passkeys.remove.text')}
        action={t('common.delete')}
        onConfirm={() => void remove()}
        onCancel={() => setConfirm(false)}
      />
    </form>
  )
}
