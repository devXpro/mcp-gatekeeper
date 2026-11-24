import { setBrand, type Brand } from './config'
import { initI18n, type Strings } from './i18n'
import { applyTheme } from './lib/theme'

export interface GatekeeperConfig {
  brand: Brand
  /** the application's strings: new keys and overrides of the package's, per language */
  strings?: Strings
}

/**
 * configure sets the brand, starts i18next with the package's strings plus the application's and applies the saved
 * appearance. Call it once in the application's entry module, before the first render.
 */
export function configure(config: GatekeeperConfig) {
  setBrand(config.brand)
  initI18n(config.strings)
  applyTheme()
}
