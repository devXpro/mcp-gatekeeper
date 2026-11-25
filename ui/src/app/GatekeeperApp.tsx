import { QueryClientProvider } from '@tanstack/react-query'
import { MotionConfig } from 'motion/react'
import { useMemo, useState, type ComponentType, type ReactNode } from 'react'
import { createBrowserRouter } from 'react-router'
import { RouterProvider } from 'react-router/dom'
import { ResourceTile } from '../components/ui/tile'
import { Toaster } from '../components/ui/toaster'
import { DEFAULT_TABS } from '../features/shell/tabdefs'
import { makeQueryClient } from '../lib/queries'
import { gatekeeperRoutes, type RouteOptions } from './routes'
import { AppContext, type AppSlots, type ConnectSlots, type LiveMode, type Resource, type ResourceTileProps, type TabDef } from './context'
import type { Account, Me, PermissionInfo } from '../lib/types'

const noResources = (): Resource[] => []
const noBadges = (): Partial<Record<string, boolean>> => ({})
const noPermissions = (): PermissionInfo[] | undefined => undefined
const invitesOn = (): string | null | undefined => undefined

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
  /**
   * The application's permission catalog (people.Options.Permissions), called as a hook wherever the screens need
   * it; return undefined while it loads. With it, invites and the member detail offer "what they may use" and a
   * term. Without it (the default) neither appears, and the server refuses both.
   */
  usePermissions?: () => PermissionInfo[] | undefined
  /** how the application's own data hooks follow changes (useLiveMode); default 'sse'. It may change at runtime. */
  live?: LiveMode
  /**
   * A layer of the application over every signed-in page (Homie: the running-call strip, the job drawer). The shell
   * mounts it once, after the tab bar, so it survives page changes; it positions itself (see ui/README.md).
   */
  Overlay?: ComponentType<{ me: Me }>
  /**
   * Called as a hook on the people list. Return a text to turn invites off: it stands in place of the invite button
   * (Homie: "invites are off in quick mode"). Return undefined (the default) to keep them on.
   */
  useInvitesDisabled?: () => string | null | undefined
}

type StaticSlots = Omit<AppSlots, 'live'>

function slotsOf(o: AppOptions): StaticSlots {
  return {
    tabs: o.tabs ?? DEFAULT_TABS,
    resources: o.resources ?? noResources,
    ResourceTile: o.ResourceTile ?? ResourceTile,
    useBadges: o.useBadges ?? noBadges,
    connect: o.connect ?? {},
    setupDoneTo: o.setupDoneTo ?? '/connect',
    access: !!o.usePermissions,
    usePermissions: o.usePermissions ?? noPermissions,
    Overlay: o.Overlay ?? null,
    useInvitesDisabled: o.useInvitesDisabled ?? invitesOn,
  }
}

/** useSlots reads the static wiring once, like the routes; only `live` follows the prop. */
function useSlots({ live = 'sse', ...options }: AppOptions): AppSlots {
  const [slots] = useState(() => slotsOf(options))
  return useMemo(() => ({ ...slots, live }), [slots, live])
}

/** AppProvider gives the shared screens the application's slots without the router (tests, custom setups). */
export function AppProvider({ children, ...options }: AppOptions & { children: ReactNode }) {
  const slots = useSlots(options)
  return <AppContext.Provider value={slots}>{children}</AppContext.Provider>
}

export type GatekeeperAppProps = AppOptions & RouteOptions

/**
 * GatekeeperApp is the whole admin SPA: TanStack Query, reduced motion as the system says, the router with the
 * gatekeeper's pages and the application's, and the toasts. Call configure() before rendering it.
 */
export function GatekeeperApp({ routes, publicRoutes, indexRoute, ...options }: GatekeeperAppProps) {
  const [qc] = useState(makeQueryClient)
  const [router] = useState(() => createBrowserRouter(gatekeeperRoutes({ routes, publicRoutes, indexRoute })))
  const slots = useSlots(options)
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
