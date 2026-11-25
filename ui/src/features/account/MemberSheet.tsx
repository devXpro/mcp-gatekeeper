import { useQueryClient } from '@tanstack/react-query'
import { Unplug } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useApp } from '../../app/context'
import { AssistantTile } from '../../components/assistant'
import { Button } from '../../components/ui/button'
import { SkeletonRows } from '../../components/ui/feedback'
import { Row, Section } from '../../components/ui/list'
import { ActionSheet, Sheet, SheetFooter } from '../../components/ui/sheet'
import { Avatar } from '../../components/ui/tile'
import { useStepUp } from '../auth/stepup'
import { useLang } from '../../i18n'
import {
  hasEnded,
  isInactive,
  PERMISSION_ALL,
  permissionIds,
  permissionsOf,
  permissionTitles,
  termEnd,
  termOf,
  type PermissionChoice,
  type TermChoice,
} from '../../lib/access'
import { assistantName } from '../../lib/assistant'
import { api, seg } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { fmtDate, fmtRelative, quote } from '../../lib/format'
import { useNow, useSticky } from '../../lib/hooks'
import { fade } from '../../lib/motion'
import { qk, useAccount, useConnections, useMe } from '../../lib/queries'
import { toast } from '../../lib/toast'
import type { Account, Connection, Member, MemberPatch, PermissionInfo } from '../../lib/types'
import { PermissionPicker, TermPicker } from './AccessPickers'

// A person of the account, for an application with a permission catalog (ui/README.md, People's access): what they may use, the
// term, their assistant connections (each can be cut), and the owner's buttons — change the access (a widening change
// asks for Face ID and is then retried), end it now (the person stays listed, «Продлить» brings it back) and remove.
// Another owner is changed or removed by the superadmin only.

export interface MemberOpen {
  member: Member
  /** open straight in the editor with a term picked: «Продлить» of an expired person */
  extend?: boolean
}

export function MemberSheet({ open, onClose, onRemove }: { open: MemberOpen | undefined; onClose: () => void; onRemove: (m: Member) => void }) {
  const shown = useSticky(open)
  return (
    <Sheet open={!!open} onClose={onClose} title={shown?.member.name ?? ''}>
      {shown && <MemberBody key={`${shown.member.id}:${shown.extend ? 1 : 0}`} open={shown} onClose={onClose} onRemove={onRemove} />}
    </Sheet>
  )
}

/** capitalize starts a row's text with a capital: the term strings are made for the middle of a subtitle. */
const capitalize = (s: string) => s.charAt(0).toLocaleUpperCase() + s.slice(1)

/** connId is the id a connection is revoked by: a grant's id, or an application's own (e.g. a legacy key). */
const connId = (c: Connection) => c.grant_id || c.id || ''

function MemberBody({ open, onClose, onRemove }: { open: MemberOpen; onClose: () => void; onRemove: (m: Member) => void }) {
  const { t } = useTranslation()
  const lang = useLang()
  const now = useNow()
  const qc = useQueryClient()
  const { withStepUp } = useStepUp()
  const app = useApp()
  const catalog = app.usePermissions()
  const me = useMe().data
  const account = useAccount()
  // The freshest row of the person (the sheet stays open across refetches); the one it opened with otherwise.
  const m = account.data?.members?.find((x) => x.id === open.member.id) ?? open.member
  const [editing, setEditing] = useState(!!open.extend)
  const [ending, setEnding] = useState(false)

  const superadmin = !!me?.person.superadmin
  const isOwner = m.role === 'owner'
  const manage = me?.person.role === 'owner' && !m.you && (!isOwner || superadmin)
  const editable = manage && !isOwner
  const ended = hasEnded(m, now)
  const inactive = isInactive(m, now)

  const save = async (patch: MemberPatch, action: string) => {
    const done = await withStepUp(async () => {
      await api.patch(`/account/members/${seg(m.id)}`, patch)
      return true
    }, action)
    if (!done) return false
    qc.setQueryData<Account>(qk.account, (x) =>
      x && {
        ...x,
        members: (x.members ?? []).map((p) => {
          if (p.id !== m.id) return p
          const next = { ...p, ...patch }
          return { ...next, active: !hasEnded(next, Date.now()) }
        }),
      },
    )
    void qc.invalidateQueries({ queryKey: qk.account })
    return true
  }

  const endNow = async () => {
    try {
      if (await save({ access_until: new Date().toISOString() }, t('stepup.action.access_end', { name: m.name }))) toast(t('access.ended.toast', { name: m.name }))
    } catch (err) {
      toast(errorText(err, t), 'warning')
    }
  }

  const until = m.access_until ? fmtDate(m.access_until, lang, new Date(now)) : ''
  const termText = isOwner || !m.access_until ? t('access.forever') : ended ? t('access.ended', { date: until }) : t('access.until', { date: until })
  const statusText = !inactive ? undefined : ended ? t('access.ended', { date: until }) : t('access.closed')
  const ids = isOwner ? [PERMISSION_ALL] : (m.permissions ?? [])
  const what = ids.includes(PERMISSION_ALL) ? t('access.all') : ids.length === 0 ? t('access.none') : permissionTitles(ids, catalog, lang).join(', ')

  return (
    <AnimatePresence mode="wait" initial={false}>
      {editing ? (
        <motion.div key="edit" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={fade.fast}>
          <AccessEditor
            member={m}
            extend={!!open.extend}
            catalog={catalog}
            onSave={(patch) => save(patch, t('stepup.action.access_change', { name: m.name }))}
            onDone={() => (open.extend ? onClose() : setEditing(false))}
          />
        </motion.div>
      ) : (
        <motion.div key="view" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={fade.fast}>
          <Section>
            <Row
              className="min-h-[68px] [--row-inset:72px]"
              leading={<Avatar id={m.id} name={m.name} size={44} />}
              title={<span className="type-headline">{m.name}</span>}
              subtitle={[t(`role.${m.role}`), statusText].filter(Boolean).join(' · ')}
            />
          </Section>

          <Section header={t('access.what')} id="member-what" footer={isOwner ? t('access.owner') : undefined}>
            <Row title={what} wrap />
          </Section>
          {!isOwner && (
            <Section header={t('access.term')} id="member-term">
              <Row title={capitalize(termText)} titleClassName={inactive ? 'text-danger-text' : undefined} />
              {editable && inactive && <Row title={t('access.extend')} accent onClick={() => setEditing(true)} />}
            </Section>
          )}
          {editable && (
            <Section>
              <Row title={t('access.change')} accent onClick={() => setEditing(true)} chevron />
            </Section>
          )}

          <MemberConnections member={m} />

          {manage && (
            <Section>
              {editable && !inactive && <Row title={t('access.end')} destructive onClick={() => setEnding(true)} />}
              <Row title={t('account.member.remove')} destructive onClick={() => onRemove(m)} />
            </Section>
          )}

          <ActionSheet
            open={ending}
            title={t('access.end.confirm', { name: m.name })}
            text={t('access.end.text', { name: m.name })}
            action={t('access.end')}
            onConfirm={() => {
              setEnding(false)
              void endNow()
            }}
            onCancel={() => setEnding(false)}
          />
        </motion.div>
      )}
    </AnimatePresence>
  )
}

/** AccessEditor changes what the person may use and the term; only what was touched is sent. */
function AccessEditor({
  member: m,
  extend,
  catalog,
  onSave,
  onDone,
}: {
  member: Member
  extend: boolean
  catalog: PermissionInfo[] | undefined
  onSave: (patch: MemberPatch) => Promise<boolean>
  onDone: () => void
}) {
  const { t } = useTranslation()
  const [opened] = useState(() => new Date())
  const [perms, setPerms] = useState<PermissionChoice>(() => permissionsOf(m.permissions))
  const [term, setTerm] = useState<TermChoice>(() => (extend ? { preset: 'week', date: '' } : termOf(m.access_until, opened, 'week')))
  const [touched, setTouched] = useState({ perms: false, term: extend })
  const [errors, setErrors] = useState<{ permissions?: string; term?: string; form?: string }>({})
  const [busy, setBusy] = useState(false)

  const submit = async () => {
    const patch: MemberPatch = {}
    const e: typeof errors = {}
    if (touched.term) {
      const end = termEnd(term, new Date())
      if (end === undefined) e.term = t('access.term.date.invalid')
      else patch.access_until = end ? end.toISOString() : null
    }
    if (touched.perms) {
      if (!perms.all && perms.ids.length === 0) e.permissions = t('access.some.required')
      else patch.permissions = permissionIds(perms)
    }
    if (e.permissions || e.term) return setErrors(e)
    setErrors({})
    setBusy(true)
    try {
      if (await onSave(patch)) {
        toast(t('access.changed'))
        onDone()
      }
    } catch (err) {
      setErrors({ form: errorText(err, t) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <form
      id="access-form"
      noValidate
      onSubmit={(e) => {
        e.preventDefault()
        void submit()
      }}
    >
      <PermissionPicker
        catalog={catalog}
        value={perms}
        onChange={(v) => {
          setPerms(v)
          setTouched((x) => ({ ...x, perms: true }))
        }}
        error={errors.permissions}
      />
      <TermPicker
        value={term}
        onChange={(v) => {
          setTerm(v)
          setTouched((x) => ({ ...x, term: true }))
        }}
        now={opened}
        error={errors.term}
      />
      {errors.form && (
        <p role="alert" className="mt-4 px-1 type-footnote text-danger-text">
          {errors.form}
        </p>
      )}
      <SheetFooter>
        <div className="flex flex-col gap-2">
          <Button type="submit" form="access-form" variant="filled" size="lg" loading={busy} disabled={!touched.perms && !touched.term}>
            {extend ? t('access.extend') : t('common.save')}
          </Button>
          <Button variant="plain" size="lg" onClick={onDone} disabled={busy}>
            {t('common.cancel')}
          </Button>
        </div>
      </SheetFooter>
    </form>
  )
}

/** MemberConnections lists the person's assistant connections, each with a button that cuts it. */
function MemberConnections({ member: m }: { member: Member }) {
  const { t } = useTranslation()
  const lang = useLang()
  const now = useNow()
  const qc = useQueryClient()
  const app = useApp()
  const account = useAccount()
  const connections = useConnections()
  const [revoking, setRevoking] = useState<Connection>()
  const resources = account.data ? app.resources(account.data) : []
  const mine = (connections.data ?? []).filter((c) => c.person.id === m.id)
  const resourceName = (c: Connection) => {
    const id = typeof c.resource === 'string' ? c.resource : c.resource.id
    return resources.find((r) => r.id === id)?.name ?? (typeof c.resource === 'string' ? '' : (c.resource.name ?? ''))
  }

  const revoke = async (c: Connection) => {
    try {
      await api.del(`/account/connections/${seg(connId(c))}`)
      qc.setQueryData<Connection[]>(qk.connections, (l) => l?.filter((x) => connId(x) !== connId(c)))
      toast(t('connect.revoked', { assistant: assistantName(c.assistant, c.client_name) }))
    } catch (err) {
      toast(errorText(err, t), 'warning')
    }
  }

  return (
    <Section header={t('connect.connections')} id="member-connections">
      {connections.isPending ? (
        <SkeletonRows rows={1} bare />
      ) : mine.length === 0 ? (
        <p className="px-4 py-3 type-subheadline text-label-2">{t('access.connections.none')}</p>
      ) : (
        mine.map((c) => (
          <Row
            key={connId(c)}
            iconInset
            leading={<AssistantTile assistant={c.assistant} size="sm" />}
            title={assistantName(c.assistant, c.client_name)}
            subtitle={[
              resourceName(c) || undefined,
              c.last_used_at ? t('connect.used', { time: fmtRelative(c.last_used_at, lang, now) }) : c.created_at ? t('connect.connected_on', { date: fmtDate(c.created_at, lang) }) : undefined,
            ]
              .filter(Boolean)
              .join(' · ')}
            trailing={
              <button
                type="button"
                onClick={() => setRevoking(c)}
                aria-label={t('connect.revoke.label', { assistant: assistantName(c.assistant, c.client_name), name: m.name })}
                className="inline-flex h-8 items-center gap-1.5 rounded-full bg-fill px-3 text-[14px] font-semibold text-danger-text hover:brightness-110"
              >
                <Unplug aria-hidden className="size-4" />
                {t('connect.revoke')}
              </button>
            }
          />
        ))
      )}
      <ActionSheet
        open={!!revoking}
        title={t('connect.revoke.confirm', { assistant: revoking ? assistantName(revoking.assistant, revoking.client_name) : '', module: quote(revoking ? resourceName(revoking) : '', lang) })}
        text={t('connect.revoke.other', { name: m.name })}
        action={t('connect.revoke')}
        onConfirm={() => {
          const c = revoking
          setRevoking(undefined)
          if (c) void revoke(c)
        }}
        onCancel={() => setRevoking(undefined)}
      />
    </Section>
  )
}
