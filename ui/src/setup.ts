import { setBrand, setFeatures, type Brand } from './config'
import { initI18n, type Strings } from './i18n'
import { applyTheme } from './lib/theme'

export interface GatekeeperConfig {
  brand: Brand
  /** the application's strings: new keys and overrides of the package's, per language */
  strings?: Strings
  /** people.Options.SingleAccount of the Go side: hides the superadmin's families section */
  singleAccount?: boolean
  /** people.Options.CoOwners of the Go side: the superadmin's invite sheet offers a co-owner */
  coOwners?: boolean
  /** false hides the owner's «Удалить всё»: its section on /account, and /account/delete answers "not found" */
  accountDelete?: boolean
}

/**
 * configure sets the brand and the people options, starts i18next with the package's strings plus the application's
 * and applies the saved appearance. Call it once in the application's entry module, before the first render.
 */
export function configure(config: GatekeeperConfig) {
  setBrand(config.brand)
  setFeatures({ singleAccount: config.singleAccount, coOwners: config.coOwners, accountDelete: config.accountDelete })
  initI18n(config.strings)
  applyTheme()
}
