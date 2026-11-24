import { Blocks, Users } from 'lucide-react'
import type { TabDef } from '../../app/context'

export type { TabDef }

/** The gatekeeper's two tabs (DESIGN.md §2.1); an application adds its own after them (Family Hub: Admin). */
export const CONNECT_TAB: TabDef = { id: 'connect', root: '/connect', icon: Blocks, label: 'tab.connect' }
export const ACCOUNT_TAB: TabDef = { id: 'account', root: '/account', icon: Users, label: 'tab.account' }

export const DEFAULT_TABS: TabDef[] = [CONNECT_TAB, ACCOUNT_TAB]
