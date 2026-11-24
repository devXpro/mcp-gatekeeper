import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Blocks, KeyRound, Unplug } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useApp, type Resource } from '../../app/context'
import { AssistantTile } from '../../components/assistant'
import { Page } from '../../components/page'
import { ButtonAnchor } from '../../components/ui/button'
import { CopyField } from '../../components/ui/copy'
import { EmptyState, ErrorState, SkeletonRows } from '../../components/ui/feedback'
import { Row, Section } from '../../components/ui/list'
import { ActionSheet } from '../../components/ui/sheet'
import { useStepUp } from '../auth/stepup'
import { useLang } from '../../i18n'
import { assistantName } from '../../lib/assistant'
import { api, seg } from '../../lib/api'
import { copyText } from '../../lib/clipboard'
import { errorText } from '../../lib/errors'
import { fmtDate, fmtRelative, quote } from '../../lib/format'
import { useDelayed, useNow } from '../../lib/hooks'
import { spring } from '../../lib/motion'
import { qk, useAccount, useConnections, useMe } from '../../lib/queries'
import { toast } from '../../lib/toast'
import type { Connection } from '../../lib/types'

// Сервисы (/connect, DESIGN.md §8.4): every resource of the account as a card: its connection address, one tap to add
// it to ChatGPT or Claude (the address is copied, the assistant's connector page opens) and the person's connections
// with a revoke button (standing keys among them, e.g. Family Hub's ChatGPT Sites, revoked by the owner). The
// application fills the rest through the connect slots (Family Hub: the status pill, the owner's setup form and the
// switch).

const CHATGPT_URL = 'https://chatgpt.com/plugins'
const CLAUDE_URL = 'https://claude.ai/customize/connectors'

/** resourceOf reads a connection's resource id (the API sends the id; an object with one is accepted too). */
function resourceOf(c: Connection) {
  return typeof c.resource === 'string' ? c.resource : c.resource.id
}

export function ConnectPage() {
  const { t } = useTranslation()
  const app = useApp()
  const me = useMe().data
  const account = useAccount()
  const connections = useConnections()
  const showSkeleton = useDelayed(account.isPending)
  const owner = me?.person.role === 'owner'
  const all = account.data ? app.resources(account.data) : []
  // A member sees only what the owner switched on; the owner sees everything the hub offers the family.
  const resources = [...all].filter((m) => owner || m.enabled).sort((a, b) => Number(b.enabled) - Number(a.enabled) || a.name.localeCompare(b.name))
  const empty = app.connect.empty?.(me)

  return (
    <Page title={t('connect.title')}>
      {account.error && !account.data ? (
        <ErrorState text={errorText(account.error, t)} onRetry={() => void account.refetch()} />
      ) : !account.data ? (
        showSkeleton && <SkeletonRows rows={3} />
      ) : resources.length === 0 ? (
        <EmptyState
          icon={Blocks}
          title={t('connect.empty.title')}
          text={t(empty?.textKey ?? (owner || all.length === 0 ? 'connect.empty.text' : 'connect.empty.member'))}
          action={empty?.action}
        />
      ) : (
        <>
          <p className="-mt-3 mb-6 px-1 type-subheadline text-label-2">{t('connect.intro')}</p>
          {resources.map((m, i) => (
            <motion.div
              key={m.id}
              className={i > 0 ? 'mt-6' : undefined}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ ...spring.smooth, delay: 0.04 * i }}
            >
              <ServiceCard
                resource={m}
                owner={owner}
                meId={me?.person.id ?? ''}
                connections={(connections.data ?? []).filter((c) => resourceOf(c) === m.id)}
                connectionsLoading={connections.isPending}
              />
            </motion.div>
          ))}
        </>
      )}
    </Page>
  )
}

function ServiceCard({
  resource: m,
  owner,
  meId,
  connections,
  connectionsLoading,
}: {
  resource: Resource
  owner: boolean
  meId: string
  connections: Connection[]
  connectionsLoading: boolean
}) {
  const { t } = useTranslation()
  const { ResourceTile, connect: slots } = useApp()
  const { Badge, Note, BodyEnd, End } = slots

  const copyAndOpen = (assistant: 'chatgpt' | 'claude') => {
    // The copy starts inside the click, before the new tab takes the focus; the link itself opens the tab.
    void copyText(m.mcp_url).then((ok) => {
      if (ok) toast(t('connect.copied', { assistant: assistantName(assistant) }))
    })
  }

  return (
    <Section className="mt-0" label={m.name}>
      <div className="flex items-start gap-3 px-4 pt-4 pb-3.5">
        <ResourceTile id={m.id} size="md" className={m.enabled ? undefined : 'opacity-50'} />
        <div className="flex min-w-0 flex-1 flex-col">
          <div className="flex items-start justify-between gap-2">
            <h2 className="pt-0.5 type-headline">{m.name}</h2>
            {Badge && <Badge resource={m} owner={owner} />}
          </div>
          {m.description && <p className="mt-0.5 type-subheadline text-label-2">{m.description}</p>}
          {Note && <Note resource={m} owner={owner} />}
        </div>
      </div>

      <AnimatePresence initial={false}>
        {m.enabled && (
          <motion.div
            key="body"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={spring.smooth}
            className="overflow-hidden"
          >
            <CardDivider />
            <div className="px-4 pt-3 pb-4">
              <p className="px-1 pb-1.5 type-footnote text-label-2">{t('connect.address')}</p>
              <CopyField value={m.mcp_url} label={t('connect.address')} onCopied={() => toast(t('common.copied'))} />
              <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
                <ButtonAnchor
                  href={CHATGPT_URL}
                  variant="tinted"
                  size="md"
                  onClick={() => copyAndOpen('chatgpt')}
                  icon={<AssistantTile assistant="chatgpt" size="sm" className="size-6 rounded-[7px] [&_svg]:size-4" />}
                >
                  {t('connect.chatgpt')}
                </ButtonAnchor>
                <ButtonAnchor
                  href={CLAUDE_URL}
                  variant="tinted"
                  size="md"
                  onClick={() => copyAndOpen('claude')}
                  icon={<AssistantTile assistant="claude" size="sm" className="size-6 rounded-[7px] [&_svg]:size-4" />}
                >
                  {t('connect.claude')}
                </ButtonAnchor>
              </div>
              <p className="mt-2.5 px-1 type-footnote text-label-2">{t(slots.hintKey?.(m, owner) ?? 'connect.hint')}</p>
            </div>
            <CardDivider />
            <Connections resource={m} connections={connections} loading={connectionsLoading} owner={owner} meId={meId} />
            {BodyEnd && <BodyEnd resource={m} owner={owner} />}
          </motion.div>
        )}
      </AnimatePresence>
      {End && <End resource={m} owner={owner} />}
    </Section>
  )
}

/** CardDivider is the hairline between the blocks of a card, inset like a row's. */
export function CardDivider() {
  return <div aria-hidden className="ml-4 hairline-t" />
}

/** connId is the id a connection is revoked by: a grant's id, or `lk_…` for a Site's legacy key. */
const connId = (c: Connection) => c.grant_id || c.id || ''

/** A legacy key of a ChatGPT Site (docs/reviews/T2.R.md L2): listed with the connections, revoked by the owner. */
const isSite = (c: Connection) => c.assistant === 'site'

function Connections({ resource: m, connections, loading, owner, meId }: { resource: Resource; connections: Connection[]; loading: boolean; owner: boolean; meId: string }) {
  const { t } = useTranslation()
  const lang = useLang()
  const now = useNow()
  const qc = useQueryClient()
  const { withStepUp } = useStepUp()
  const [revoking, setRevoking] = useState<Connection>()
  const nameOf = (c: Connection) => (isSite(c) ? c.label || c.client_name || t('connect.site.fallback') : assistantName(c.assistant, c.client_name))
  const revoke = useMutation({
    mutationFn: async (c: Connection) => {
      const del = async () => {
        await api.del(`/account/connections/${seg(connId(c))}`)
        return true
      }
      // A Site's key is a standing credential: if the hub asks for Face ID before it goes, the sheet asks.
      return isSite(c) ? withStepUp(del, t('stepup.action.site_revoke')) : del()
    },
    onSuccess: (done, c) => {
      if (!done) return
      qc.setQueryData<Connection[]>(qk.connections, (l) => l?.filter((x) => connId(x) !== connId(c)))
      toast(isSite(c) ? t('connect.site.revoked', { label: quote(nameOf(c), lang) }) : t('connect.revoked', { assistant: nameOf(c) }))
    },
    onError: (err) => toast(errorText(err, t), 'warning'),
  })
  if (loading) return <SkeletonRows rows={1} bare />
  const site = revoking && isSite(revoking)
  return (
    <>
      <div className="px-4 pt-3 pb-1 type-footnote text-label-2">{t('connect.connections')}</div>
      {connections.length === 0 ? (
        <p className="px-4 pb-3.5 type-subheadline text-label-2">{t('connect.connections.none')}</p>
      ) : (
        <AnimatePresence initial={false}>
          {connections.map((c) => {
            const mine = c.person.id === meId
            const key = isSite(c)
            // A grant: your own, or any as the owner. A Site's key: the owner only (T2.F5).
            const canRevoke = key ? owner : mine || owner
            return (
              <motion.div
                key={connId(c)}
                layout
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={spring.smooth}
                className="fh-row overflow-hidden [--row-inset:60px]"
              >
                <Row
                  leading={<AssistantTile assistant={c.assistant} size="sm" />}
                  iconInset
                  title={nameOf(c)}
                  subtitle={[
                    owner && !mine ? c.person.name : undefined,
                    key ? t('connect.site') : c.created_at ? t('connect.connected_on', { date: fmtDate(c.created_at, lang) }) : undefined,
                    c.last_used_at ? t('connect.used', { time: fmtRelative(c.last_used_at, lang, now) }) : undefined,
                  ]
                    .filter(Boolean)
                    .join(' · ')}
                  trailing={
                    canRevoke && (
                      <button
                        type="button"
                        onClick={() => setRevoking(c)}
                        aria-label={
                          key
                            ? t('connect.site.revoke.label', { label: nameOf(c), name: c.person.name })
                            : t('connect.revoke.label', { assistant: nameOf(c), name: c.person.name })
                        }
                        className="inline-flex h-8 items-center gap-1.5 rounded-full bg-fill px-3 text-[14px] font-semibold text-danger-text hover:brightness-110"
                      >
                        {key ? <KeyRound aria-hidden className="size-4" /> : <Unplug aria-hidden className="size-4" />}
                        {key ? t('connect.site.revoke') : t('connect.revoke')}
                      </button>
                    )
                  }
                />
              </motion.div>
            )
          })}
        </AnimatePresence>
      )}
      <ActionSheet
        open={!!revoking}
        title={
          site
            ? t('connect.site.revoke.confirm', { label: quote(nameOf(revoking), lang) })
            : t('connect.revoke.confirm', { assistant: revoking ? nameOf(revoking) : '', module: quote(m.name, lang) })
        }
        text={
          site
            ? t('connect.site.revoke.text')
            : revoking && revoking.person.id !== meId
              ? t('connect.revoke.other', { name: revoking.person.name })
              : t('connect.revoke.text')
        }
        action={site ? t('connect.site.revoke') : t('connect.revoke')}
        onConfirm={() => {
          if (revoking) revoke.mutate(revoking)
          setRevoking(undefined)
        }}
        onCancel={() => setRevoking(undefined)}
      />
    </>
  )
}
