import { useTranslation } from 'react-i18next'
import { Page } from '../../components/page'
import { CheckList } from '../../components/ui/controls'
import { Section } from '../../components/ui/list'
import { setLanguage, useLang } from '../../i18n'
import { setThemePref, useThemePref, type ThemePref } from '../../lib/theme'
import type { Lang } from '../../lib/types'

// Язык and Оформление (DESIGN.md §8.5.3): checkmarked lists that apply at once and stay in this browser.

export function LanguagePage() {
  const { t } = useTranslation()
  const lang = useLang()
  return (
    <Page title={t('language.title')} back={{ to: '/account', label: t('tab.account') }}>
      <Section footer={t('language.footer')}>
        <CheckList<Lang>
          label={t('language.title')}
          options={[
            { value: 'ru', label: 'Русский' },
            { value: 'en', label: 'English' },
          ]}
          selected={[lang]}
          onToggle={setLanguage}
        />
      </Section>
    </Page>
  )
}

export function AppearancePage() {
  const { t } = useTranslation()
  const pref = useThemePref()
  return (
    <Page title={t('appearance.title')} back={{ to: '/account', label: t('tab.account') }}>
      <Section>
        <CheckList<ThemePref>
          label={t('appearance.title')}
          options={[
            { value: 'dark', label: t('appearance.dark') },
            { value: 'light', label: t('appearance.light') },
            { value: 'system', label: t('appearance.system') },
          ]}
          selected={[pref]}
          onToggle={setThemePref}
        />
      </Section>
    </Page>
  )
}
