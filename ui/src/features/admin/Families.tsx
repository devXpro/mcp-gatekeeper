import { useQueryClient } from '@tanstack/react-query'
import { Plus, Users } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { InviteLink } from '../../components/invite'
import { Button } from '../../components/ui/button'
import { TextField } from '../../components/ui/controls'
import { ErrorState, SkeletonRows } from '../../components/ui/feedback'
import { Row, Section } from '../../components/ui/list'
import { Sheet, SheetFooter } from '../../components/ui/sheet'
import { IconTile } from '../../components/ui/tile'
import { useStepUp } from '../auth/stepup'
import { useLang } from '../../i18n'
import { api, seg } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { count, fmtDate, quote } from '../../lib/format'
import { useDelayed, useSticky } from '../../lib/hooks'
import { fade } from '../../lib/motion'
import { qk, useAdminAccounts, useMe } from '../../lib/queries'
import { tileColor } from '../../lib/tiles'
import { toast } from '../../lib/toast'
import type { AdminAccount, AdminAccountCreated } from '../../lib/types'

// The superadmin's families (Family Hub /admin, DESIGN.md §8.7): only names and counts, never their data; create one
// with its owner's invite link, or delete one by typing its name. The application puts this section on its own admin
// page (Family Hub: above the modules) and keeps that page behind AdminOnly.

export function FamiliesSection() {
  const { t } = useTranslation()
  const lang = useLang()
  const accounts = useAdminAccounts()
  const showAccounts = useDelayed(accounts.isPending)
  const [creating, setCreating] = useState(false)
  const [open, setOpen] = useState<AdminAccount | null>(null)

  return (
    <>
      <Section header={t('admin.families')} id="admin-families" footer={t('admin.families.footer')}>
        {accounts.error && !accounts.data ? (
          <ErrorState compact text={errorText(accounts.error, t)} onRetry={() => void accounts.refetch()} />
        ) : !accounts.data ? (
          showAccounts ? <SkeletonRows rows={2} bare /> : <div className="min-h-[60px]" />
        ) : (
          accounts.data.map((a) => (
            <Row
              key={a.id}
              onClick={() => setOpen(a)}
              iconInset
              leading={<IconTile icon={Users} color={tileColor(a.id)} />}
              title={a.name}
              subtitle={[
                t('admin.family.people', { count: count(a.members) }),
                t('admin.family.services', { count: count(a.modules) }),
                t('admin.family.since', { date: fmtDate(a.created_at, lang) }),
              ].join(' · ')}
              subtitleLines={1}
              chevron
            />
          ))
        )}
        <div className="fh-row [--row-inset:60px]">
          <Row iconInset leading={<IconTile icon={Plus} color="blue" />} title={t('admin.family.create')} accent onClick={() => setCreating(true)} />
        </div>
      </Section>
      <CreateFamilySheet open={creating} onClose={() => setCreating(false)} />
      <FamilySheet account={open} onClose={() => setOpen(null)} />
    </>
  )
}

function CreateFamilySheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  return (
    <Sheet open={open} onClose={onClose} title={t('admin.family.create')}>
      <CreateFamily onDone={onClose} />
    </Sheet>
  )
}

function CreateFamily({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation()
  const lang = useLang()
  const qc = useQueryClient()
  const { withStepUp } = useStepUp()
  const [name, setName] = useState('')
  const [owner, setOwner] = useState('')
  const [errors, setErrors] = useState<{ name?: string; owner?: string; form?: string }>({})
  const [busy, setBusy] = useState(false)
  const [created, setCreated] = useState<AdminAccountCreated>()

  const create = async () => {
    const n = name.trim()
    const o = owner.trim()
    const e = { name: n ? undefined : t('form.required'), owner: o ? undefined : t('form.required') }
    setErrors(e)
    if (e.name || e.owner) return
    setBusy(true)
    try {
      const res = await withStepUp(() => api.post<AdminAccountCreated>('/admin/accounts', { name: n, owner_name: o }), t('stepup.action.family_create'))
      if (res) {
        setCreated(res)
        void qc.invalidateQueries({ queryKey: qk.adminAccounts })
      }
    } catch (err) {
      setErrors({ form: errorText(err, t) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <AnimatePresence mode="wait" initial={false}>
      {created ? (
        <motion.div key="link" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={fade.fast}>
          <p className="mb-5 px-1 text-center type-subheadline text-label-2">
            {t('admin.family.created', { family: quote(created.account.name, lang), name: owner.trim() })}
          </p>
          <InviteLink
            url={created.invite.url}
            expiresAt={created.invite.expires_at}
            shareText={t('admin.family.share_text', { family: quote(created.account.name, lang) })}
          />
          <SheetFooter>
            <Button variant="filled" size="lg" onClick={onDone}>
              {t('common.done')}
            </Button>
          </SheetFooter>
        </motion.div>
      ) : (
        <motion.form
          key="form"
          id="family-form"
          noValidate
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={fade.fast}
          onSubmit={(e) => {
            e.preventDefault()
            void create()
          }}
        >
          <div className="flex flex-col gap-5">
            <TextField
              label={t('admin.family.name')}
              value={name}
              onChange={(e) => setName(e.target.value)}
              error={errors.name}
              placeholder={t('onboarding.family.placeholder')}
              maxLength={40}
              autoComplete="off"
              autoFocusOnOpen
            />
            <TextField
              label={t('admin.family.owner')}
              hint={t('admin.family.owner.hint')}
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              error={errors.owner}
              maxLength={40}
              autoComplete="off"
            />
          </div>
          {errors.form && (
            <p role="alert" className="mt-4 px-1 type-footnote text-danger-text">
              {errors.form}
            </p>
          )}
          <SheetFooter>
            <Button type="submit" form="family-form" variant="filled" size="lg" loading={busy}>
              {t('admin.family.create.button')}
            </Button>
          </SheetFooter>
        </motion.form>
      )}
    </AnimatePresence>
  )
}

function FamilySheet({ account, onClose }: { account: AdminAccount | null; onClose: () => void }) {
  const shown = useSticky(account)
  return (
    <Sheet open={!!account} onClose={onClose} title={shown?.name ?? ''}>
      {shown && <FamilyBody key={shown.id} account={shown} onDone={onClose} />}
    </Sheet>
  )
}

function FamilyBody({ account: a, onDone }: { account: AdminAccount; onDone: () => void }) {
  const { t } = useTranslation()
  const lang = useLang()
  const qc = useQueryClient()
  const { withStepUp } = useStepUp()
  const me = useMe().data
  const own = me?.account.id === a.id
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()

  const remove = async () => {
    setBusy(true)
    setError(undefined)
    try {
      const done = await withStepUp(async () => {
        await api.del(`/admin/accounts/${seg(a.id)}`, { confirm: typed.trim() })
        return true
      }, t('stepup.action.family_delete', { family: quote(a.name, lang) }))
      if (!done) return
      qc.setQueryData<AdminAccount[]>(qk.adminAccounts, (l) => l?.filter((x) => x.id !== a.id))
      toast(t('admin.family.deleted', { family: quote(a.name, lang) }))
      onDone()
    } catch (err) {
      setError(errorText(err, t))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <Section>
        <Row title={t('admin.family.people.title')} trailing={<span className="tabular-nums">{count(a.members)}</span>} />
        <Row title={t('admin.family.services.title')} trailing={<span className="tabular-nums">{count(a.modules)}</span>} />
        <Row title={t('admin.family.created_at')} trailing={fmtDate(a.created_at, lang)} />
      </Section>
      <p className="mt-3 px-4 type-footnote text-label-2">{t('admin.family.private')}</p>
      {own ? (
        <p className="mt-8 px-4 type-footnote text-label-2">{t('admin.family.own')}</p>
      ) : (
        <div className="mt-8">
          <TextField
            label={t('admin.family.delete.type', { family: a.name })}
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder={a.name}
            autoComplete="off"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
          />
          {error && (
            <p role="alert" className="mt-3 px-1 type-footnote text-danger-text">
              {error}
            </p>
          )}
          <Button className="mt-4 w-full" variant="destructive-filled" size="md" disabled={typed.trim() !== a.name} loading={busy} onClick={() => void remove()}>
            {t('admin.family.delete')}
          </Button>
        </div>
      )}
    </div>
  )
}
