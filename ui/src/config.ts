// The application's brand, set once by configure() (setup.ts) before anything renders. The API client, the theme
// and the language read it outside React, so it is module state rather than context.

import type { LucideIcon } from 'lucide-react'

export interface Brand {
  /** core.Brand.CSRFHeader of the Go side, e.g. "X-Family-Hub": sent with the value 1 on every write */
  csrfHeader: string
  /** the localStorage prefix: "<prefix>.theme", "<prefix>.lang", "<prefix>.mock.webauthn" (Family Hub: "fh") */
  storagePrefix: string
  /** the glyph of the app icon (sign-in, setup, the sidebar) */
  icon: LucideIcon
}

/** The people options of the Go side the screens must follow (people.Options); Family Hub's behaviour by default. */
export interface Features {
  /** people.Options.SingleAccount: one account only, so the superadmin's families section is hidden */
  singleAccount: boolean
  /** people.Options.CoOwners: the superadmin may invite a co-owner into the account */
  coOwners: boolean
  /** the owner's «Удалить всё» (the section on /account and the page /account/delete); on by default */
  accountDelete: boolean
}

let current: Brand | undefined
let currentFeatures: Features = { singleAccount: false, coOwners: false, accountDelete: true }

export function setBrand(b: Brand) {
  current = b
}

export function setFeatures(f: Partial<Features>) {
  currentFeatures = { singleAccount: !!f.singleAccount, coOwners: !!f.coOwners, accountDelete: f.accountDelete !== false }
}

/** features returns the people options configure() was given. */
export function features(): Features {
  return currentFeatures
}

/** brand returns the configured brand; configure() must have run. */
export function brand(): Brand {
  if (!current) throw new Error('@devxpro/mcp-gatekeeper-ui: call configure() before rendering')
  return current
}

/** storageKey is the localStorage key of a setting, under the brand's prefix. */
export function storageKey(name: string) {
  return `${brand().storagePrefix}.${name}`
}
