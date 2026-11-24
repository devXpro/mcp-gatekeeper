import { QueryClientProvider } from '@tanstack/react-query'
import { MotionConfig } from 'motion/react'
import { useState, type ComponentType, type ReactNode } from 'react'
import { createBrowserRouter } from 'react-router'
import { RouterProvider } from 'react-router/dom'
import { ResourceTile } from '../components/ui/tile'
import { Toaster } from '../components/ui/toaster'
import { DEFAULT_TABS } from '../features/shell/tabdefs'
import { makeQueryClient } from '../lib/queries'
import { gatekeeperRoutes, type RouteOptions } from './routes'
import { AppContext, type AppSlots, type ConnectSlots, type Resource, type ResourceTileProps, type TabDef } from './context'
import type { Account, Me } from '../lib/types'

const noResources = (): Resource[] => []
const noBadges = (): Partial<Record<string, boolean>> => ({})

export interface AppOptions {
  /** the shell's tabs; default the gatekeeper's two (DEFAULT_TABS), Family Hub adds Admin */
  tabs?: TabDef[]
  /** the resources of the account (Family Hub: `(a) => a.modules ?? []`); default none */
  resources?: (account: Account) => Resource[]
  /** a resource's tile; default ResourceTile (a block on a colour picked from the id) */
  ResourceTile?: ComponentType<ResourceTileProps>
  /** red dots on tabs, called as a hook inside the signed-in shell */
  useBadges?: (me: Me) => Partial<Record<string, boolean>>
  connect?: ConnectSlots
  /** where the first-run setup lands; default "/connect" (Family Hub: "/admin") */
  setupDoneTo?: string
}

function slotsOf(o: AppOptions): AppSlots {
  return {
    tabs: o.tabs ?? DEFAULT_TABS,
    resources: o.resources ?? noResources,
    ResourceTile: o.ResourceTile ?? ResourceTile,
    useBadges: o.useBadges ?? noBadges,
    connect: o.connect ?? {},
    setupDoneTo: o.setupDoneTo ?? '/connect',
  }
}

/** AppProvider gives the shared screens the application's slots without the router (tests, custom setups). */
export function AppProvider({ children, ...options }: AppOptions & { children: ReactNode }) {
  // The options are the application's static wiring: read once, like the routes.
  const [slots] = useState(() => slotsOf(options))
  return <AppContext.Provider value={slots}>{children}</AppContext.Provider>
}

export type GatekeeperAppProps = AppOptions & RouteOptions

/**
 * GatekeeperApp is the whole admin SPA: TanStack Query, reduced motion as the system says, the router with the
 * gatekeeper's pages and the application's, and the toasts. Call configure() before rendering it.
 */
export function GatekeeperApp({ routes, publicRoutes, ...options }: GatekeeperAppProps) {
  const [qc] = useState(makeQueryClient)
  const [router] = useState(() => createBrowserRouter(gatekeeperRoutes({ routes, publicRoutes })))
  const [slots] = useState(() => slotsOf(options))
  return (
    <AppContext.Provider value={slots}>
      <QueryClientProvider client={qc}>
        <MotionConfig reducedMotion="user">
          <RouterProvider router={router} />
          <Toaster />
        </MotionConfig>
      </QueryClientProvider>
    </AppContext.Provider>
  )
}
