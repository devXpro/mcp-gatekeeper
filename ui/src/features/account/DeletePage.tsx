import { TriangleAlert } from 'lucide-react'
import { AnimatePresence, motion } from 'motion/react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router'
import { useApp } from '../../app/context'
import { Page } from '../../components/page'
import { Rich } from '../../components/rich'
import { Button } from '../../components/ui/button'
import { TextField } from '../../components/ui/controls'
import { ErrorState, SkeletonRows } from '../../components/ui/feedback'
import { Row, Section } from '../../components/ui/list'
import { useStepUp } from '../auth/stepup'
import { useLang } from '../../i18n'
import { api, isApiError } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { quote } from '../../lib/format'
import { spring } from '../../lib/motion'
import { useAccount, useMe } from '../../lib/queries'

// «Удалить всё» (Family Hub docs/PLAN.md §3.2 flow 5, §5.9): the owner types the family's name and confirms with a
// passkey; the application erases its data (Family Hub: every module erases the family), then the gatekeeper does. A
// resource that fails (502 upstream naming it) keeps the family until a retry succeeds.

export function DeletePage() {
  const { t } = useTranslation()
  const lang = useLang()
  const navigate = useNavigate()
  const { resources, ResourceTile } = useApp()
  const { withStepUp } = useStepUp()
  const me = useMe().data
  const account = useAccount()
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [failed, setFailed] = useState<{ module?: string; text: string }>()
  const a = account.data

  const back = { to: '/account', label: t('tab.account') }
  if (me && me.person.role !== 'owner') {
    return (
      <Page title={t('account.delete')} back={back}>
        <ErrorState title={t('error.forbidden')} />
      </Page>
    )
  }
  if (account.error && !a) {
    return (
      <Page title={t('account.delete')} back={back}>
        <ErrorState text={errorText(account.error, t)} onRetry={() => void account.refetch()} />
      </Page>
    )
  }
  if (!a) {
    return (
      <Page title={t('account.delete')} back={back}>
        <SkeletonRows rows={3} />
      </Page>
    )
  }

  const matches = typed.trim() === a.name
  const all = resources(a)
  const modules = all.filter((m) => m.enabled)
  const remove = async () => {
    setBusy(true)
    setFailed(undefined)
    try {
      const done = await withStepUp(async () => {
        await api.del('/account', { confirm: typed.trim() })
        return true
      }, t('stepup.action.delete_all'))
      if (!done) return
      navigate('/account/deleted', { replace: true })
    } catch (err) {
      if (isApiError(err, 'upstream')) {
        const name = all.find((m) => m.id === err.module)?.name ?? err.module ?? ''
        setFailed({ module: name, text: t(err.reason === 'not_deployed' ? 'delete.not_deployed' : 'delete.upstream', { module: quote(name, lang) }) })
      } else setFailed({ text: errorText(err, t) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Page title={t('account.delete')} back={back}>
      <div className="flex gap-3 rounded-lg bg-surface-1 p-4">
        <TriangleAlert aria-hidden className="mt-0.5 size-6 shrink-0 text-danger" />
        <div>
          <p className="type-headline">{t('delete.title', { family: quote(a.name, lang) })}</p>
          <p className="prose-ru mt-1 type-subheadline text-label-2">{t('delete.text')}</p>
          {me?.person.superadmin && (
            <p className="prose-ru mt-2 type-subheadline text-warning-text">
              <Rich text={t('delete.superadmin')} />
            </p>
          )}
        </div>
      </div>
      {modules.length > 0 && (
        <Section header={t('delete.modules')} className="mt-6">
          {modules.map((m) => (
            <Row key={m.id} iconInset leading={<ResourceTile id={m.id} size="sm" />} title={m.name} subtitle={t('delete.module_data')} />
          ))}
        </Section>
      )}
      <div className="mt-8">
        <TextField
          label={t('delete.type', { family: a.name })}
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          placeholder={a.name}
          autoComplete="off"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
        />
      </div>
      <AnimatePresence>
        {failed && (
          <motion.p
            role="alert"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={spring.smooth}
            className="mt-4 overflow-hidden rounded-lg bg-fill p-4 type-subheadline"
          >
            {failed.text}
          </motion.p>
        )}
      </AnimatePresence>
      <Button className="mt-6" variant="destructive-filled" size="lg" disabled={!matches} loading={busy} onClick={() => void remove()}>
        {failed ? t('common.retry') : t('delete.button')}
      </Button>
      <p className="mt-3 px-1 text-center type-footnote text-label-2">{t('delete.footnote')}</p>
    </Page>
  )
}
