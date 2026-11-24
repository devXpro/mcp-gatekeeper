import { useQueryClient } from '@tanstack/react-query'
import { History, KeyRound, Languages, MailPlus, Palette, Trash2, UserPlus } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Page } from '../../components/page'
import { ErrorState, SkeletonRows } from '../../components/ui/feedback'
import { Row, RowValue, Section } from '../../components/ui/list'
import { ActionSheet } from '../../components/ui/sheet'
import { Avatar, IconTile } from '../../components/ui/tile'
import { useStepUp } from '../auth/stepup'
import { useLogout } from '../shell/AppShell'
import { useLang } from '../../i18n'
import { api, seg } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { fmtDate, fmtRelative, quote } from '../../lib/format'
import { useDelayed, useNow } from '../../lib/hooks'
import { spring } from '../../lib/motion'
import { qk, useAccount, useMe, usePasskeys } from '../../lib/queries'
import { useThemePref } from '../../lib/theme'
import { toast } from '../../lib/toast'
import type { Account, InviteRow, Member } from '../../lib/types'
import { InviteSheet } from './InviteSheet'

// Семья (/account, DESIGN.md §8.5): you, the family's people and open invites, then sign-in and appearance, the
// family's log, sign out and, for the owner, «Удалить всё».

export function AccountPage() {
  const { t } = useTranslation()
  const lang = useLang()
  const qc = useQueryClient()
  const me = useMe().data
  const account = useAccount()
  const passkeys = usePasskeys()
  const theme = useThemePref()
  const logout = useLogout()
  const { withStepUp } = useStepUp()
  const now = useNow()
  const showSkeleton = useDelayed(account.isPending)
  const [inviting, setInviting] = useState(false)
  const [removing, setRemoving] = useState<Member>()
  const [revoking, setRevoking] = useState<InviteRow>()
  const owner = me?.person.role === 'owner'
  const a = account.data

  const removeMember = async (m: Member) => {
    try {
      const done = await withStepUp(async () => {
        await api.del(`/account/members/${seg(m.id)}`)
        return true
      }, t('stepup.action.remove_member', { name: m.name }))
      if (!done) return
      qc.setQueryData<Account>(qk.account, (x) => x && { ...x, members: (x.members ?? []).filter((p) => p.id !== m.id) })
      void qc.invalidateQueries({ queryKey: qk.connections })
      toast(t('account.member.removed', { name: m.name }))
    } catch (err) {
      toast(errorText(err, t), 'warning')
    }
  }

  const revokeInvite = async (inv: InviteRow) => {
    try {
      const done = await withStepUp(async () => {
        await api.del(`/account/invites/${seg(inv.id)}`)
        return true
      }, t('stepup.action.invite_revoke'))
      if (!done) return
      qc.setQueryData<Account>(qk.account, (x) => x && { ...x, invites: (x.invites ?? []).filter((i) => i.id !== inv.id) })
      toast(t('account.invite.revoked'))
    } catch (err) {
      toast(errorText(err, t), 'warning')
    }
  }

  return (
    <Page title={a?.name ?? me?.account.name ?? t('account.title')}>
      {me && (
        <Section>
          <Row
            className="min-h-[68px] [--row-inset:72px]"
            leading={<Avatar id={me.person.id} name={me.person.name} size={44} />}
            title={<span className="type-headline">{me.person.name}</span>}
            subtitle={[t(`role.${me.person.role}`), me.person.superadmin ? t('role.superadmin') : undefined].filter(Boolean).join(' · ')}
          />
        </Section>
      )}

      {account.error && !a ? (
        <div className="mt-8">
          <ErrorState compact text={errorText(account.error, t)} onRetry={() => void account.refetch()} />
        </div>
      ) : !a ? (
        showSkeleton && (
          <div className="mt-8">
            <SkeletonRows rows={3} />
          </div>
        )
      ) : (
        <Section header={t('account.people')} id="account-people" footer={owner ? t('account.people.footer') : undefined}>
          <AnimatePresence initial={false}>
            {(a.members ?? []).map((m) => (
              <motion.div key={m.id} layout exit={{ opacity: 0, height: 0 }} transition={spring.smooth} className="fh-row overflow-hidden [--row-inset:60px]">
                <Row
                  iconInset
                  leading={<Avatar id={m.id} name={m.name} size={30} />}
                  title={m.you ? t('account.member.you', { name: m.name }) : m.name}
                  subtitle={`${t(`role.${m.role}`)} · ${t('account.member.since', { date: fmtDate(m.joined_at, lang) })}`}
                  onClick={owner && !m.you ? () => setRemoving(m) : undefined}
                  chevron={owner && !m.you}
                />
              </motion.div>
            ))}
            {(a.invites ?? []).map((inv) => (
              <motion.div key={inv.id} layout exit={{ opacity: 0, height: 0 }} transition={spring.smooth} className="fh-row overflow-hidden [--row-inset:60px]">
                <Row
                  iconInset
                  leading={<IconTile icon={MailPlus} color="gray" />}
                  title={inv.name}
                  subtitle={t('account.invite.until', { time: fmtRelative(inv.expires_at, lang, now) })}
                  onClick={owner ? () => setRevoking(inv) : undefined}
                  chevron={owner}
                />
              </motion.div>
            ))}
          </AnimatePresence>
          {owner && (
            <div className="fh-row [--row-inset:60px]">
              <Row iconInset leading={<IconTile icon={UserPlus} color="blue" />} title={t('account.invite')} accent onClick={() => setInviting(true)} />
            </div>
          )}
        </Section>
      )}

      <Section header={t('account.security')} id="account-security">
        <Row
          to="/account/passkeys"
          iconInset
          leading={<IconTile icon={KeyRound} color="gray" />}
          title={t('passkeys.title')}
          trailing={<RowValue className="tabular-nums">{passkeys.data?.length}</RowValue>}
          chevron
        />
      </Section>

      <Section header={t('account.appearance')} id="account-appearance">
        <Row
          to="/account/language"
          iconInset
          leading={<IconTile icon={Languages} color="indigo" />}
          title={t('language.title')}
          trailing={<RowValue>{lang === 'en' ? 'English' : 'Русский'}</RowValue>}
          chevron
        />
        <Row
          to="/account/appearance"
          iconInset
          leading={<IconTile icon={Palette} color="purple" />}
          title={t('appearance.title')}
          trailing={<RowValue>{t(`appearance.${theme}`)}</RowValue>}
          chevron
        />
      </Section>

      <Section id="account-log">
        <Row to="/account/audit" iconInset leading={<IconTile icon={History} color="teal" />} title={t(owner ? 'audit.account.title' : 'audit.mine.title')} chevron />
      </Section>

      <Section>
        <Row onClick={() => void logout()} title={t('account.logout')} destructive centered />
      </Section>

      {owner && a && (
        <Section footer={t('account.delete.footer', { family: quote(a.name, lang) })}>
          <Row to="/account/delete" iconInset leading={<IconTile icon={Trash2} color="red" />} title={t('account.delete')} destructive chevron />
        </Section>
      )}

      <InviteSheet open={inviting} onClose={() => setInviting(false)} />
      <ActionSheet
        open={!!removing}
        title={t('account.member.remove.confirm', { name: removing?.name ?? '' })}
        text={t('account.member.remove.text', { name: removing?.name ?? '' })}
        action={t('account.member.remove')}
        onConfirm={() => {
          const m = removing
          setRemoving(undefined)
          if (m) void removeMember(m)
        }}
        onCancel={() => setRemoving(undefined)}
      />
      <ActionSheet
        open={!!revoking}
        title={t('account.invite.revoke.confirm', { name: revoking?.name ?? '' })}
        text={t('account.invite.revoke.text')}
        action={t('account.invite.revoke')}
        onConfirm={() => {
          const inv = revoking
          setRevoking(undefined)
          if (inv) void revokeInvite(inv)
        }}
        onCancel={() => setRevoking(undefined)}
      />
    </Page>
  )
}
