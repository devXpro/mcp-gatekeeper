import { useQueryClient } from '@tanstack/react-query'
import { HeartCrack } from 'lucide-react'
import { motion } from 'motion/react'
import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { ButtonLink } from '../../components/ui/button'
import { EmptyState } from '../../components/ui/feedback'
import { spring } from '../../lib/motion'

// After «Удалить всё» (/account/deleted): the family is gone and so is the session, so this page lives outside the
// signed-in shell and forgets every cached answer.

export function Farewell() {
  const { t } = useTranslation()
  const qc = useQueryClient()
  useEffect(() => qc.clear(), [qc])
  return (
    <main className="flex min-h-dvh items-center justify-center px-6">
      <motion.div initial={{ opacity: 0, scale: 0.96 }} animate={{ opacity: 1, scale: 1 }} transition={spring.sheet}>
        <EmptyState
          icon={HeartCrack}
          title={t('delete.done.title')}
          text={t('delete.done.text')}
          action={
            <ButtonLink to="/login" replace variant="tinted" size="lg">
              {t('common.close')}
            </ButtonLink>
          }
        />
      </motion.div>
    </main>
  )
}
