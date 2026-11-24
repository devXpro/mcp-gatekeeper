// What an application plugs into the shared screens: its tabs, its resources (Family Hub: modules) with their tile,
// and the slots of the connect page and the shell. GatekeeperApp provides it; screens read it with useApp().

import type { LucideIcon } from 'lucide-react'
import { createContext, useContext, type ComponentType, type ReactNode } from 'react'
import type { Account, Me } from '../lib/types'

/** A tab of the shell (DESIGN.md §2.1): the tab bar on phones, the sidebar on desktop. */
export interface TabDef {
  id: string
  root: string
  icon: LucideIcon
  /** an i18n key */
  label: string
  /** shown to the superadmin only */
  superadmin?: boolean
}

/** A resource behind an MCP endpoint, as the connect page shows it (Family Hub: an AccountModule). */
export interface Resource {
  id: string
  name: string
  description?: string
  mcp_url: string
  /** on for the account: a member sees only these; the card's body shows only for these */
  enabled: boolean
}

export interface ResourceTileProps {
  id: string
  size?: 'sm' | 'md' | 'lg'
  className?: string
}

/** The props of every connect-card slot. `resource` is the object `resources` returned (cast it to the app's type). */
export interface CardSlotProps {
  resource: Resource
  owner: boolean
}

export interface ConnectSlots {
  /** the right of a card's title row (Family Hub: the status pill) */
  Badge?: ComponentType<CardSlotProps>
  /** under the description (Family Hub: why a service is unwell) */
  Note?: ComponentType<CardSlotProps>
  /** the i18n key of the footnote under the assistant buttons; undefined keeps "connect.hint" */
  hintKey?: (resource: Resource, owner: boolean) => string | undefined
  /** inside the card's body, after the connections (Family Hub: the owner's Setup row and its sheet) */
  BodyEnd?: ComponentType<CardSlotProps>
  /** at the card's end, shown also when the resource is off (Family Hub: the owner's on/off switch) */
  End?: ComponentType<CardSlotProps>
  /** the empty page: another text key and an action (Family Hub: the superadmin's "Install a module") */
  empty?: (me: Me | undefined) => { textKey?: string; action?: ReactNode } | undefined
}

export interface AppSlots {
  tabs: TabDef[]
  /** the resources of the account, from GET /api/account (Family Hub: `account.modules`) */
  resources: (account: Account) => Resource[]
  /** a resource's icon tile: 30 px in rows, 44 px in lists, 64 px in headers */
  ResourceTile: ComponentType<ResourceTileProps>
  /** red dots on tabs, by tab id; called as a hook inside the signed-in shell */
  useBadges: (me: Me) => Partial<Record<string, boolean>>
  connect: ConnectSlots
  /** where "Get started" leads after the first-run setup link (Family Hub: "/admin") */
  setupDoneTo: string
}

export const AppContext = createContext<AppSlots | null>(null)

export function useApp(): AppSlots {
  const ctx = useContext(AppContext)
  if (!ctx) throw new Error('@devxpro/mcp-gatekeeper-ui: render the screens inside <GatekeeperApp> or <AppProvider>')
  return ctx
}
