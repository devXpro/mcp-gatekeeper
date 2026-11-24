// Error codes → words (DESIGN.md §10.6); unknown codes use error.generic.

import type { TFunction } from 'i18next'
import { isApiError, isOffline } from './api'

export function errorText(err: unknown, t: TFunction): string {
  if (isOffline(err)) return t('error.offline')
  if (isApiError(err)) return t(`error.${err.code}`, { defaultValue: t('error.generic') })
  return t('error.generic')
}
