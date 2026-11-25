import { useQueryClient } from '@tanstack/react-query'
import { AnimatePresence, motion } from 'motion/react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useApp } from '../../app/context'
import { InviteLink } from '../../components/invite'
import { Button } from '../../components/ui/button'
import { SegmentedControl, TextField } from '../../components/ui/controls'
import { Sheet, SheetFooter } from '../../components/ui/sheet'
import { features } from '../../config'
import { useStepUp } from '../auth/stepup'
import { useLang } from '../../i18n'
import { permissionIds, termEnd, type PermissionChoice, type TermChoice } from '../../lib/access'
import { api } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { quote } from '../../lib/format'
import { fade } from '../../lib/motion'
import { qk, useAccount, useMe } from '../../lib/queries'
import type { CreatedInvite, InviteBody, Role } from '../../lib/types'
import { PermissionPicker, TermPicker } from './AccessPickers'

// Invite someone into the family (docs/PLAN.md §5.9: owner, step-up): their name, then the one-time link. With the
// application's permission catalog the sheet also asks what they may use and for how long (ui/README.md, People's access); with
// co-owners the superadmin may invite a co-owner instead, who gets everything with no end.

export function InviteSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  return (
    <Sheet open={open} onClose={onClose} title={t('invite.title')}>
      <InviteFlow onDone={onClose} />
    </Sheet>
  )
}

interface Errors {
  name?: string
  permissions?: string
  term?: string
  form?: string
}

function InviteFlow({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation()
  const lang = useLang()
  const qc = useQueryClient()
  const { withStepUp } = useStepUp()
  const app = useApp()
  const catalog = app.usePermissions()
  const me = useMe().data
  const family = useAccount().data?.name ?? ''
  const [name, setName] = useState('')
  const [role, setRole] = useState<Role>('member')
  const [perms, setPerms] = useState<PermissionChoice>({ all: true, ids: [] })
  const [term, setTerm] = useState<TermChoice>({ preset: 'forever', date: '' })
  const [errors, setErrors] = useState<Errors>({})
  const [busy, setBusy] = useState(false)
  const [created, setCreated] = useState<CreatedInvite>()
  const canCoOwner = features().coOwners && !!me?.person.superadmin
  const owner = canCoOwner && role === 'owner'
  // The access pickers: an application with a catalog, for anyone but a co-owner (who has everything for good).
  const pickers = app.access && !owner

  const create = async () => {
    const n = name.trim()
    const body: InviteBody = { name: n }
    const e: Errors = { name: n ? undefined : t('form.required') }
    if (owner) body.role = 'owner'
    if (pickers) {
      const end = termEnd(term, new Date())
      if (end === undefined) e.term = t('access.term.date.invalid')
      else if (end) body.access_until = end.toISOString()
      if (!perms.all && perms.ids.length === 0) e.permissions = t('access.some.required')
      else body.permissions = permissionIds(perms)
    }
    if (e.name || e.permissions || e.term) return setErrors(e)
    setBusy(true)
    setErrors({})
    try {
      const inv = await withStepUp(() => api.post<CreatedInvite>('/account/invites', body), t('stepup.action.invite'))
      if (inv) {
        setCreated(inv)
        void qc.invalidateQueries({ queryKey: qk.account })
      }
    } catch (err) {
      // Without the pickers the name field carries every error, as it always did.
      setErrors(app.access ? { form: errorText(err, t) } : { name: errorText(err, t) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <AnimatePresence mode="wait" initial={false}>
      {created ? (
        <motion.div key="link" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={fade.fast}>
          <p className="mb-5 px-1 text-center type-subheadline text-label-2">{t('invite.ready', { name: name.trim() })}</p>
          <InviteLink url={created.url} expiresAt={created.expires_at} shareText={t('invite.share_text', { family: quote(family, lang) })} />
          <SheetFooter>
            <Button variant="filled" size="lg" onClick={onDone}>
              {t('common.done')}
            </Button>
          </SheetFooter>
        </motion.div>
      ) : (
        <motion.form
          key="name"
          id="invite-form"
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
          <TextField
            label={t('invite.name')}
            value={name}
            onChange={(e) => setName(e.target.value)}
            error={errors.name}
            hint={t('invite.name.hint')}
            maxLength={40}
            autoComplete="off"
            autoFocusOnOpen
          />
          {canCoOwner && (
            <div className="mt-6">
              <p className="px-1 pb-1.5 type-footnote text-label-2">{t('invite.role')}</p>
              <SegmentedControl<Role>
                label={t('invite.role')}
                value={role}
                onChange={setRole}
                options={[
                  { value: 'member', label: t('invite.role.member') },
                  { value: 'owner', label: t('invite.role.owner') },
                ]}
              />
              {owner && <p className="px-1 pt-1.5 type-footnote text-label-2">{t('invite.role.owner.hint')}</p>}
            </div>
          )}
          {pickers && (
            <div className="mt-8">
              <PermissionPicker catalog={catalog} value={perms} onChange={setPerms} error={errors.permissions} />
              <TermPicker value={term} onChange={setTerm} now={new Date()} error={errors.term} />
            </div>
          )}
          {errors.form && (
            <p role="alert" className="mt-4 px-1 type-footnote text-danger-text">
              {errors.form}
            </p>
          )}
          <SheetFooter>
            <Button type="submit" form="invite-form" variant="filled" size="lg" loading={busy}>
              {t('invite.create')}
            </Button>
          </SheetFooter>
        </motion.form>
      )}
    </AnimatePresence>
  )
}
