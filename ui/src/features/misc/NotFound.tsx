import { useTranslation } from 'react-i18next'
import { Page } from '../../components/page'
import { ButtonLink } from '../../components/ui/button'
import { ErrorState } from '../../components/ui/feedback'

// Unknown routes (DESIGN.md §8.10.4).

export function NotFoundPage() {
  const { t } = useTranslation()
  return (
    <Page title={t('notfound.title')} largeTitle={false}>
      <ErrorState
        title={t('notfound.title')}
        action={
          <ButtonLink to="/connect" variant="tinted" size="lg">
            {t('common.home')}
          </ButtonLink>
        }
      />
    </Page>
  )
}
