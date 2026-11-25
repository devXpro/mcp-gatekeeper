import type { ComponentType } from 'react'
import { Navigate, type IndexRouteObject, type RouteObject } from 'react-router'
import { features } from '../config'
import { AccountPage } from '../features/account/AccountPage'
import { AppearancePage, LanguagePage } from '../features/account/ChoicePages'
import { DeletePage } from '../features/account/DeletePage'
import { Farewell } from '../features/account/Farewell'
import { PasskeysPage } from '../features/account/PasskeysPage'
import { AccountAuditPage } from '../features/audit/AuditPage'
import { LoginPage } from '../features/auth/LoginPage'
import { ConnectPage } from '../features/connect/ConnectPage'
import { ConsentPage } from '../features/consent/ConsentPage'
import { NotFoundPage } from '../features/misc/NotFound'
import { Onboarding } from '../features/onboarding/Onboarding'
import { AppShell, type PageHandle } from '../features/shell/AppShell'

const page = (path: string, Component: ComponentType, handle: PageHandle): RouteObject => ({ path, Component, handle })

export interface RouteOptions {
  /** the application's pages inside the signed-in shell (Family Hub: /admin/*); give them a PageHandle */
  routes?: RouteObject[]
  /** the application's pages outside the shell, without a session */
  publicRoutes?: RouteObject[]
  /**
   * the page at "/" inside the shell (signed in), in place of the redirect to /connect; give it a PageHandle. It is
   * the shell's index route, so it does not depend on the order of the other routes.
   */
  indexRoute?: Omit<IndexRouteObject, 'index'>
}

/**
 * The routes of Family Hub docs/PLAN.md §5.2 (DESIGN.md §2.2): the pages outside the shell work without a session;
 * the application's routes join them.
 */
export function gatekeeperRoutes({ routes = [], publicRoutes = [], indexRoute }: RouteOptions = {}): RouteObject[] {
  return [
    { path: '/login', Component: LoginPage },
    { path: '/setup', element: <Onboarding key="setup" route="setup" /> },
    { path: '/join', element: <Onboarding key="join" route="join" /> },
    { path: '/consent', Component: ConsentPage },
    { path: '/account/deleted', Component: Farewell },
    ...publicRoutes,
    {
      path: '/',
      Component: AppShell,
      children: [
        indexRoute ? { ...indexRoute, index: true } : { index: true, element: <Navigate to="/connect" replace /> },
        page('connect', ConnectPage, { page: 'connect', tab: 'connect', depth: 0 }),
        page('account', AccountPage, { page: 'account', tab: 'account', depth: 0 }),
        page('account/passkeys', PasskeysPage, { page: 'account/passkeys', tab: 'account', depth: 1 }),
        page('account/language', LanguagePage, { page: 'account/language', tab: 'account', depth: 1 }),
        page('account/appearance', AppearancePage, { page: 'account/appearance', tab: 'account', depth: 1 }),
        page('account/audit', AccountAuditPage, { page: 'account/audit', tab: 'account', depth: 1 }),
        // configure({ accountDelete: false }) takes «Удалить всё» away: the page is not there.
        page('account/delete', features().accountDelete ? DeletePage : NotFoundPage, { page: 'account/delete', tab: 'account', depth: 1 }),
        ...routes,
        page('*', NotFoundPage, { page: 'notfound', depth: 0 }),
      ],
    },
  ]
}

