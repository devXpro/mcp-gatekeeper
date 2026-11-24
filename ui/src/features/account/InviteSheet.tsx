import { useQueryClient } from '@tanstack/react-query'
import { AnimatePresence, motion } from 'motion/react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { InviteLink } from '../../components/invite'
import { Button } from '../../components/ui/button'
import { TextField } from '../../components/ui/controls'
import { Sheet, SheetFooter } from '../../components/ui/sheet'
import { useStepUp } from '../auth/stepup'
import { useLang } from '../../i18n'
import { api } from '../../lib/api'
import { errorText } from '../../lib/errors'
import { quote } from '../../lib/format'
import { fade } from '../../lib/motion'
import { qk, useAccount } from '../../lib/queries'
import type { CreatedInvite } from '../../lib/types'

// Invite someone into the family (docs/PLAN.md §5.9: owner, step-up): their name, then the one-time link.

export function InviteSheet({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation()
  return (
    <Sheet open={open} onClose={onClose} title={t('invite.title')}>
      <InviteFlow onDone={onClose} />
    </Sheet>
  )
}

function InviteFlow({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation()
  const lang = useLang()
  const qc = useQueryClient()
  const { withStepUp } = useStepUp()
  const family = useAccount().data?.name ?? ''
  const [name, setName] = useState('')
  const [error, setError] = useState<string>()
  const [busy, setBusy] = useState(false)
  const [created, setCreated] = useState<CreatedInvite>()

  const create = async () => {
    const n = name.trim()
    if (!n) return setError(t('form.required'))
    setBusy(true)
    setError(undefined)
    try {
      const inv = await withStepUp(() => api.post<CreatedInvite>('/account/invites', { name: n }), t('stepup.action.invite'))
      if (inv) {
        setCreated(inv)
        void qc.invalidateQueries({ queryKey: qk.account })
      }
    } catch (err) {
      setError(errorText(err, t))
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
            error={error}
            hint={t('invite.name.hint')}
            maxLength={40}
            autoComplete="off"
            autoFocusOnOpen
          />
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
